package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/tlsopts"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
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
	certFile := fs.String("cert-file", "", "TLS cert file path")
	keyFile := fs.String("key-file", "", "TLS key file path")
	caCert := fs.String("ca-cert", "", "CA cert file path (used to issue server certs)")
	caKey := fs.String("ca-key", "", "CA key file path (used to issue server certs)")
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
	raiseServerNoFileLimit()

	if err := validateServerTLSConfig(serverEnvConfig{
		CertDir:    strings.TrimSpace(*certDir),
		CertFile:   strings.TrimSpace(*certFile),
		KeyFile:    strings.TrimSpace(*keyFile),
		CACertFile: strings.TrimSpace(*caCert),
		CAKeyFile:  strings.TrimSpace(*caKey),
	}); err != nil {
		logrus.Fatalln("invalid tls config:", err)
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logrus.Fatalln("listen server tcp:", err)
	}

	tlsConfig, tlsMode, err := buildServerTLSConfig(*listen, *certDir, *certFile, *keyFile, *caCert, *caKey)
	if err != nil {
		logrus.Fatalln("build tls config failed:", err)
	}
	logrus.Infoln("[Server] TLS cert mode:", tlsMode)

	ctx := context.Background()
	server := NewMyServer(tlsConfig)

	connLimit := serverInboundConnLimit()
	slotWait := serverInboundSlotWaitTimeout()
	connSlots := make(chan struct{}, connLimit)
	pressureCtl := newServerPressureController()
	var emfileCooldownMS int64
	acceptErrStreak := 0
	acceptEMFILECooldownUntil := time.Time{}
	var dropWarnLogger serverWarnLogger

	logrus.Infof("[Server] inbound connection cap: %d wait=%s (%s)", connLimit, slotWait, serverFDUsageSummary())

	for {
		if d := time.Until(acceptEMFILECooldownUntil); d > 0 {
			atomic.StoreInt64(&emfileCooldownMS, d.Milliseconds())
			time.Sleep(d)
		} else {
			atomic.StoreInt64(&emfileCooldownMS, 0)
		}

		c, err := listener.Accept()
		if err != nil {
			acceptErrStreak++
			backoff := time.Duration(acceptErrStreak) * 200 * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			logrus.Warnf("[Server] accept failed (streak=%d), retrying in %s: %v", acceptErrStreak, backoff, err)
			if serverIsTooManyOpenFilesErr(err) {
				emfileCooldown := time.Duration(acceptErrStreak) * 300 * time.Millisecond
				if emfileCooldown < 800*time.Millisecond {
					emfileCooldown = 800 * time.Millisecond
				}
				if emfileCooldown > 5*time.Second {
					emfileCooldown = 5 * time.Second
				}
				until := time.Now().Add(emfileCooldown)
				if until.After(acceptEMFILECooldownUntil) {
					acceptEMFILECooldownUntil = until
				}
				atomic.StoreInt64(&emfileCooldownMS, emfileCooldown.Milliseconds())
				dropWarnLogger.log("[Server] fd pressure detected", fmt.Errorf("%s cooldown=%s", serverFDUsageSummary(), emfileCooldown))
			}
			pressureCtl.onAcceptError(err)
			time.Sleep(backoff)
			continue
		}
		acceptErrStreak = 0
		acceptEMFILECooldownUntil = time.Time{}
		atomic.StoreInt64(&emfileCooldownMS, 0)

		activeNow := len(connSlots)
		softLimit, pressureWaitCap, pressureReason := pressureCtl.compute(connLimit, atomic.LoadInt64(&emfileCooldownMS))
		if activeNow >= softLimit {
			pressureDrop := softLimit < connLimit
			if pressureDrop {
				pressureCtl.onPressureDrop()
				dropWarnLogger.log(
					"[Server] inbound connection dropped (pressure)",
					fmt.Errorf("active=%d soft_limit=%d hard_limit=%d %s", activeNow, softLimit, connLimit, pressureReason),
				)
				_ = c.Close()
				continue
			}
		}

		waitForSlot := slotWait
		if pressureWaitCap > 0 && waitForSlot > pressureWaitCap {
			waitForSlot = pressureWaitCap
		}
		acquired := false
		select {
		case connSlots <- struct{}{}:
			acquired = true
		default:
			timer := time.NewTimer(waitForSlot)
			select {
			case connSlots <- struct{}{}:
				acquired = true
			case <-timer.C:
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if !acquired {
			pressureCtl.onPressureDrop()
			dropWarnLogger.log("[Server] inbound connection dropped", fmt.Errorf("active=%d limit=%d %s", len(connSlots), connLimit, serverFDUsageSummary()))
			_ = c.Close()
			continue
		}
		go func(conn net.Conn) {
			defer func() {
				<-connSlots
			}()
			handleTcpConnection(ctx, conn, server)
		}(c)
	}
}

func buildServerTLSConfig(listen, certDir, certFile, keyFile, caCertFile, caKeyFile string) (*tls.Config, string, error) {
	return tlsopts.BuildServerConfig(tlsopts.ServerOptions{
		Listen:     strings.TrimSpace(listen),
		CertDir:    strings.TrimSpace(certDir),
		CertFile:   strings.TrimSpace(certFile),
		KeyFile:    strings.TrimSpace(keyFile),
		CACertFile: strings.TrimSpace(caCertFile),
		CAKeyFile:  strings.TrimSpace(caKeyFile),
	})
}
