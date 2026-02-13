package main

import (
	"anytls/proxy/padding"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var passwordSha256 []byte

func main() {
	if len(os.Args) == 2 && isVersionArg(os.Args[1]) {
		fmt.Println(util.BuildInfo())
		return
	}
	if len(os.Args) == 1 {
		if err := runServerMenu(); err != nil {
			logrus.Fatalln(err)
		}
		return
	}
	if os.Args[1] == "config" {
		if err := runServerConfigCLI(os.Args[2:]); err != nil {
			logrus.Fatalln(err)
		}
		return
	}
	runServer(os.Args[1:])
}

func isVersionArg(arg string) bool {
	switch strings.TrimSpace(strings.ToLower(arg)) {
	case "version", "-v", "--version", "-version":
		return true
	default:
		return false
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("anytls-server", flag.ExitOnError)
	listen := fs.String("l", "0.0.0.0:8443", "server listen port")
	password := fs.String("p", "", "password")
	certDir := fs.String("cert-dir", "", "TLS cert directory (expects server.crt and server.key)")
	paddingScheme := fs.String("padding-scheme", "", "padding-scheme")
	_ = fs.Parse(args)

	if *password == "" {
		logrus.Fatalln("please set password")
	}
	if *paddingScheme != "" {
		if f, err := os.Open(*paddingScheme); err == nil {
			b, err := io.ReadAll(f)
			if err != nil {
				logrus.Fatalln(err)
			}
			if padding.UpdatePaddingScheme(b) {
				logrus.Infoln("loaded padding scheme file:", *paddingScheme)
			} else {
				logrus.Errorln("wrong format padding scheme file:", *paddingScheme)
			}
			f.Close()
		} else {
			logrus.Fatalln(err)
		}
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	var sum = sha256.Sum256([]byte(*password))
	passwordSha256 = sum[:]

	logrus.Infoln("[Server]", util.BuildInfo())
	logrus.Infoln("[Server] Listening TCP", *listen)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logrus.Fatalln("listen server tcp:", err)
	}

	var tlsConfig *tls.Config
	if *certDir != "" {
		certFile := filepath.Join(*certDir, "server.crt")
		keyFile := filepath.Join(*certDir, "server.key")
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logrus.Fatalln("load cert failed (cert-dir should contain server.crt and server.key):", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}
		logrus.Infoln("[Server] TLS cert from", *certDir)
	} else {
		tlsCert, _ := util.GenerateKeyPair(time.Now, "")
		tlsConfig = &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return tlsCert, nil
			},
		}
		logrus.Infoln("[Server] TLS cert mode: auto-generated")
	}

	ctx := context.Background()
	server := NewMyServer(tlsConfig)

	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Fatalln("accept:", err)
		}
		go handleTcpConnection(ctx, c, server)
	}
}
