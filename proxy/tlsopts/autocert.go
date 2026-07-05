package tlsopts

import (
	"anytls/util"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	AutoCertFileName = "server.crt"
	AutoKeyFileName  = "server.key"
)

func EnsureServerCertDir(dir, listen string) (certPath, keyPath, certSHA256 string, err error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", "", "", fmt.Errorf("auto cert dir is empty")
	}
	certPath = filepath.Join(dir, AutoCertFileName)
	keyPath = filepath.Join(dir, AutoKeyFileName)

	if fileExists(certPath) && fileExists(keyPath) {
		tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return "", "", "", fmt.Errorf("load auto cert failed: %w", err)
		}
		if len(tlsCert.Certificate) == 0 {
			return "", "", "", fmt.Errorf("load auto cert failed: certificate chain is empty")
		}
		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return "", "", "", fmt.Errorf("parse auto cert failed: %w", err)
		}
		if time.Now().Before(leaf.NotAfter) {
			fp, err := CertificateSHA256FromPEMFile(certPath)
			if err != nil {
				return "", "", "", err
			}
			return certPath, keyPath, fp, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", err
	}
	name := defaultServerCertNameFromListen(listen)
	cert, err := util.GenerateKeyPair(time.Now, name)
	if err != nil {
		return "", "", "", err
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return "", "", "", fmt.Errorf("generated auto cert is empty")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return "", "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", "", err
	}
	return certPath, keyPath, CertificateSHA256FromDER(cert.Certificate[0]), nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
