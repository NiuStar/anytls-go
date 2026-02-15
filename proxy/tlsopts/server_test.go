package tlsopts

import (
	"anytls/util"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateServerOptionsConflict(t *testing.T) {
	dir := t.TempDir()
	opts := ServerOptions{
		CertDir:  dir,
		CertFile: filepath.Join(dir, "server.crt"),
		KeyFile:  filepath.Join(dir, "server.key"),
	}
	err := ValidateServerOptions(opts)
	if err == nil {
		t.Fatalf("expect tls config conflict error")
	}
}

func TestBuildServerConfigCertDir(t *testing.T) {
	dir := t.TempDir()
	if err := writeLeafPair(t, filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), "localhost"); err != nil {
		t.Fatalf("write leaf pair failed: %v", err)
	}

	cfg, mode, err := BuildServerConfig(ServerOptions{CertDir: dir})
	if err != nil {
		t.Fatalf("build server config failed: %v", err)
	}
	if mode != "cert-dir" {
		t.Fatalf("unexpected mode: %s", mode)
	}
	if cfg == nil || len(cfg.Certificates) == 0 {
		t.Fatalf("certificates should not be empty")
	}
}

func TestBuildServerConfigCAMode(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := writeSelfSignedCA(t, caCert, caKey); err != nil {
		t.Fatalf("write ca failed: %v", err)
	}
	cfg, mode, err := BuildServerConfig(ServerOptions{
		Listen:     "0.0.0.0:8443",
		CACertFile: caCert,
		CAKeyFile:  caKey,
	})
	if err != nil {
		t.Fatalf("build server config failed: %v", err)
	}
	if mode != "ca-cert+ca-key" {
		t.Fatalf("unexpected mode: %s", mode)
	}
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatalf("GetCertificate should not be nil")
	}
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatalf("issued certificate should not be empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf failed: %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("unexpected CN: %s", leaf.Subject.CommonName)
	}
}

func TestBuildServerConfigAuto(t *testing.T) {
	cfg, mode, err := BuildServerConfig(ServerOptions{Listen: "0.0.0.0:8443"})
	if err != nil {
		t.Fatalf("build server config failed: %v", err)
	}
	if mode != "auto-generated" {
		t.Fatalf("unexpected mode: %s", mode)
	}
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatalf("GetCertificate should not be nil")
	}
	cert, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatalf("certificate should not be nil")
	}
}

func writeLeafPair(t *testing.T, certPath, keyPath, serverName string) error {
	t.Helper()
	keypair, err := util.GenerateKeyPair(time.Now, serverName)
	if err != nil {
		return err
	}
	if keypair == nil || len(keypair.Certificate) == 0 {
		return os.ErrInvalid
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keypair.Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(keypair.PrivateKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(keyPath, keyPEM, 0600)
}

func writeSelfSignedCA(t *testing.T, certPath, keyPath string) error {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "AnyTLS Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(keyPath, keyPEM, 0600)
}
