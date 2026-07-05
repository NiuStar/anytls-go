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
	assertHardenedServerTLSConfig(t, cfg)
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
	assertHardenedServerTLSConfig(t, cfg)
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
	assertHardenedServerTLSConfig(t, cfg)
	cert, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatalf("certificate should not be nil")
	}
}

func TestBuildServerConfigAutoCertDirPersists(t *testing.T) {
	dir := t.TempDir()
	cfg, mode, err := BuildServerConfig(ServerOptions{Listen: "127.0.0.1:8443", AutoCertDir: dir})
	if err != nil {
		t.Fatalf("build auto cert dir config failed: %v", err)
	}
	if mode != "auto-cert-dir" {
		t.Fatalf("unexpected mode: %s", mode)
	}
	if cfg == nil || len(cfg.Certificates) == 0 {
		t.Fatalf("expected loaded auto certificate")
	}
	assertHardenedServerTLSConfig(t, cfg)
	firstFP, err := CertificateSHA256FromPEMFile(filepath.Join(dir, AutoCertFileName))
	if err != nil {
		t.Fatalf("read auto cert fingerprint failed: %v", err)
	}

	cfg2, mode, err := BuildServerConfig(ServerOptions{Listen: "127.0.0.1:8443", AutoCertDir: dir})
	if err != nil {
		t.Fatalf("rebuild auto cert dir config failed: %v", err)
	}
	if mode != "auto-cert-dir" || cfg2 == nil || len(cfg2.Certificates) == 0 {
		t.Fatalf("unexpected second build: mode=%s cfg=%#v", mode, cfg2)
	}
	secondFP, err := CertificateSHA256FromPEMFile(filepath.Join(dir, AutoCertFileName))
	if err != nil {
		t.Fatalf("read second auto cert fingerprint failed: %v", err)
	}
	if firstFP == "" || firstFP != secondFP {
		t.Fatalf("auto cert fingerprint should persist across builds: %q vs %q", firstFP, secondFP)
	}
}

func TestBuildServerConfigAutoCertDirRegeneratesExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, AutoCertFileName)
	keyPath := filepath.Join(dir, AutoKeyFileName)
	expiredAt := time.Now().Add(-1 * time.Hour)
	if err := writeLeafPairAt(t, certPath, keyPath, "127.0.0.1", expiredAt.Add(-2*time.Hour), expiredAt); err != nil {
		t.Fatalf("write expired leaf pair failed: %v", err)
	}
	expiredFP, err := CertificateSHA256FromPEMFile(certPath)
	if err != nil {
		t.Fatalf("read expired cert fingerprint failed: %v", err)
	}

	cfg, mode, err := BuildServerConfig(ServerOptions{Listen: "127.0.0.1:8443", AutoCertDir: dir})
	if err != nil {
		t.Fatalf("build auto cert dir config failed: %v", err)
	}
	if mode != "auto-cert-dir" || cfg == nil || len(cfg.Certificates) == 0 {
		t.Fatalf("unexpected build result: mode=%s cfg=%#v", mode, cfg)
	}
	newFP, err := CertificateSHA256FromPEMFile(certPath)
	if err != nil {
		t.Fatalf("read regenerated cert fingerprint failed: %v", err)
	}
	if newFP == "" || newFP == expiredFP {
		t.Fatalf("expired auto cert should be regenerated: expired=%q new=%q", expiredFP, newFP)
	}
	leaf := readLeafCertFromPEMFile(t, certPath)
	if time.Until(leaf.NotAfter) < 9*365*24*time.Hour {
		t.Fatalf("regenerated auto cert should be long lived, NotAfter=%s", leaf.NotAfter)
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

func writeLeafPairAt(t *testing.T, certPath, keyPath, serverName string, notBefore, notAfter time.Time) error {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

func readLeafCertFromPEMFile(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certificate failed: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("invalid certificate PEM in %s", certPath)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate failed: %v", err)
	}
	return leaf
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

func assertHardenedServerTLSConfig(t *testing.T, cfg *tls.Config) {
	t.Helper()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected MinVersion: got %#x want TLS1.2", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatalf("expected explicit hardened TLS 1.2 cipher suite allowlist")
	}
	if len(cfg.CurvePreferences) == 0 || cfg.CurvePreferences[0] != tls.X25519 {
		t.Fatalf("expected X25519-first curve preferences, got %#v", cfg.CurvePreferences)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatalf("server should disable TLS session tickets by default")
	}
}
