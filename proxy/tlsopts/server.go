package tlsopts

import (
	"anytls/util"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ServerOptions struct {
	Listen     string
	CertDir    string
	CertFile   string
	KeyFile    string
	CACertFile string
	CAKeyFile  string
}

type serverCAIssuer struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
}

func BuildServerConfig(opts ServerOptions) (*tls.Config, string, error) {
	opts = normalizeServerOptions(opts)

	if opts.CertFile != "" || opts.KeyFile != "" {
		if opts.CertFile == "" || opts.KeyFile == "" {
			return nil, "", fmt.Errorf("cert-file and key-file must be set together")
		}
		tlsCert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("load cert-file/key-file failed: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{tlsCert}}, "cert-file", nil
	}

	if opts.CertDir != "" {
		certPath := filepath.Join(opts.CertDir, "server.crt")
		keyPath := filepath.Join(opts.CertDir, "server.key")
		tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, "", fmt.Errorf("load cert failed (cert-dir should contain server.crt and server.key): %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{tlsCert}}, "cert-dir", nil
	}

	if opts.CACertFile != "" || opts.CAKeyFile != "" {
		if opts.CACertFile == "" || opts.CAKeyFile == "" {
			return nil, "", fmt.Errorf("ca-cert and ca-key must be set together")
		}
		issuer, err := loadServerCAIssuer(opts.CACertFile, opts.CAKeyFile)
		if err != nil {
			return nil, "", err
		}
		defaultName := defaultServerCertNameFromListen(opts.Listen)
		cache := make(map[string]*tls.Certificate)
		var cacheMu sync.Mutex

		cfg := &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := ""
				if chi != nil {
					name = strings.TrimSpace(chi.ServerName)
				}
				if name == "" {
					name = defaultName
				}
				if name == "" {
					name = "localhost"
				}
				key := strings.ToLower(name)

				cacheMu.Lock()
				cached := cache[key]
				cacheMu.Unlock()
				if cached != nil {
					return cached, nil
				}

				issued, issueErr := issueServerCertFromCA(issuer, name, time.Now())
				if issueErr != nil {
					return nil, issueErr
				}
				cacheMu.Lock()
				cache[key] = issued
				cacheMu.Unlock()
				return issued, nil
			},
		}
		return cfg, "ca-cert+ca-key", nil
	}

	defaultName := defaultServerCertNameFromListen(opts.Listen)
	tlsCert, err := util.GenerateKeyPair(time.Now, defaultName)
	if err != nil {
		return nil, "", err
	}
	cfg := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return tlsCert, nil
		},
	}
	return cfg, "auto-generated", nil
}

func ValidateServerOptions(opts ServerOptions) error {
	opts = normalizeServerOptions(opts)
	modeCount := 0
	if opts.CertDir != "" {
		modeCount++
		if err := validateCertDir(opts.CertDir); err != nil {
			return err
		}
	}
	if opts.CertFile != "" || opts.KeyFile != "" {
		modeCount++
		if opts.CertFile == "" || opts.KeyFile == "" {
			return fmt.Errorf("cert-file and key-file must be set together")
		}
		if err := validateFileExists(opts.CertFile, "cert-file"); err != nil {
			return err
		}
		if err := validateFileExists(opts.KeyFile, "key-file"); err != nil {
			return err
		}
	}
	if opts.CACertFile != "" || opts.CAKeyFile != "" {
		modeCount++
		if opts.CACertFile == "" || opts.CAKeyFile == "" {
			return fmt.Errorf("ca-cert and ca-key must be set together")
		}
		if err := validateFileExists(opts.CACertFile, "ca-cert"); err != nil {
			return err
		}
		if err := validateFileExists(opts.CAKeyFile, "ca-key"); err != nil {
			return err
		}
	}
	if modeCount > 1 {
		return fmt.Errorf("tls config conflict: choose one of cert-dir / cert-file+key-file / ca-cert+ca-key")
	}
	return nil
}

func normalizeServerOptions(opts ServerOptions) ServerOptions {
	opts.Listen = strings.TrimSpace(opts.Listen)
	opts.CertDir = strings.TrimSpace(opts.CertDir)
	opts.CertFile = strings.TrimSpace(opts.CertFile)
	opts.KeyFile = strings.TrimSpace(opts.KeyFile)
	opts.CACertFile = strings.TrimSpace(opts.CACertFile)
	opts.CAKeyFile = strings.TrimSpace(opts.CAKeyFile)
	return opts
}

func validateCertDir(certDir string) error {
	certDir = strings.TrimSpace(certDir)
	if certDir == "" {
		return nil
	}
	info, err := os.Stat(certDir)
	if err != nil {
		return fmt.Errorf("invalid cert-dir %q: %w", certDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cert-dir must be a directory: %s", certDir)
	}
	if _, err := os.Stat(filepath.Join(certDir, "server.crt")); err != nil {
		return fmt.Errorf("missing cert file: %s", filepath.Join(certDir, "server.crt"))
	}
	if _, err := os.Stat(filepath.Join(certDir, "server.key")); err != nil {
		return fmt.Errorf("missing cert file: %s", filepath.Join(certDir, "server.key"))
	}
	return nil
}

func validateFileExists(path string, label string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", label, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must be a file: %s", label, path)
	}
	return nil
}

func defaultServerCertNameFromListen(listen string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return ""
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	switch host {
	case "", "0.0.0.0", "::":
		return "localhost"
	default:
		return host
	}
}

func loadServerCAIssuer(certFile, keyFile string) (*serverCAIssuer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read ca-cert failed: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read ca-key failed: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid ca-cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca-cert failed: %w", err)
	}
	signer, err := parseSignerPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca-key failed: %w", err)
	}
	return &serverCAIssuer{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		key:     signer,
	}, nil
}

func parseSignerPEM(keyPEM []byte) (crypto.Signer, error) {
	for {
		block, rest := pem.Decode(keyPEM)
		if block == nil {
			break
		}
		keyPEM = rest
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				continue
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				continue
			}
			return signer, nil
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				continue
			}
			return key, nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				continue
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func issueServerCertFromCA(issuer *serverCAIssuer, serverName string, now time.Time) (*tls.Certificate, error) {
	if issuer == nil || issuer.cert == nil || issuer.key == nil {
		return nil, fmt.Errorf("invalid ca issuer")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	leafKey, err := util.GenerateKeyPair(func() time.Time { return now }, serverName)
	if err != nil || leafKey == nil || len(leafKey.Certificate) == 0 {
		if err == nil {
			err = fmt.Errorf("failed to generate leaf keypair")
		}
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(leafKey.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse generated leaf cert failed: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		Subject:               pkix.Name{CommonName: serverName},
	}
	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if strings.TrimSpace(serverName) != "" {
		tmpl.DNSNames = []string{serverName}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, leafCert.PublicKey, issuer.key)
	if err != nil {
		return nil, fmt.Errorf("issue server cert from ca failed: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPEM = append(certPEM, issuer.certPEM...)

	leafKeyPEM, err := encodeTLSPrivateKey(leafKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("encode leaf private key failed: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, leafKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("build tls keypair failed: %w", err)
	}
	return &tlsCert, nil
}

func encodeTLSPrivateKey(priv any) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), nil
}
