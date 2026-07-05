package tlsopts

import (
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

func genTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
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
		t.Fatalf("create cert failed: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestBuildClientConfigStrictWithCACert(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, genTestCAPEM(t), 0644); err != nil {
		t.Fatalf("write ca cert failed: %v", err)
	}
	cfg, err := BuildClientConfig(ClientOptions{
		Server:        "example.com:443",
		SNI:           "example.com",
		AllowInsecure: false,
		CACertPath:    caPath,
	})
	if err != nil {
		t.Fatalf("build client config failed: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatalf("expect strict verify")
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("unexpected server name: %q", cfg.ServerName)
	}
	if cfg.RootCAs == nil {
		t.Fatalf("expected custom root CAs")
	}
	assertHardenedClientTLSConfig(t, cfg)
}

func TestBuildClientConfigStrictDefaultsAreHardened(t *testing.T) {
	cfg, err := BuildClientConfig(ClientOptions{
		Server: "example.com:443",
	})
	if err != nil {
		t.Fatalf("build client config failed: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatalf("strict default should not skip certificate verification")
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("expected server name derived from server address, got %q", cfg.ServerName)
	}
	assertHardenedClientTLSConfig(t, cfg)
}

func TestBuildClientConfigInsecureDefaultServerName(t *testing.T) {
	cfg, err := BuildClientConfig(ClientOptions{
		Server:        "example.com:443",
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("build client config failed: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatalf("expect insecure skip verify")
	}
	if cfg.ServerName != "127.0.0.1" {
		t.Fatalf("unexpected server name: %q", cfg.ServerName)
	}
	assertHardenedClientTLSConfig(t, cfg)
}

func TestLoadRootCAsFromFileInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.crt")
	block := &pem.Block{Type: "NOTCERT", Bytes: []byte("x")}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0644); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	pool, err := LoadRootCAsFromFile(path)
	if err == nil {
		t.Fatalf("expect error, got pool=%v", pool)
	}
}

func TestLoadRootCAsFromFileValidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, genTestCAPEM(t), 0644); err != nil {
		t.Fatalf("write ca cert failed: %v", err)
	}
	pool, err := LoadRootCAsFromFile(path)
	if err != nil {
		t.Fatalf("load root ca failed: %v", err)
	}
	if pool == nil {
		t.Fatalf("pool is nil")
	}
	// Just ensure it's a usable cert pool value.
	_ = x509.VerifyOptions{Roots: pool}
}

func TestBuildClientConfigWithCertSHA256Pin(t *testing.T) {
	cert := genTestCAPEM(t)
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatalf("generated cert pem missing block")
	}
	pin := CertificateSHA256FromDER(block.Bytes)

	cfg, err := BuildClientConfig(ClientOptions{
		Server:     "example.com:443",
		CertSHA256: pin,
	})
	if err != nil {
		t.Fatalf("build client config with pin failed: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatalf("certificate pin mode should use custom verification")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatalf("certificate pin mode must install VerifyPeerCertificate")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{block.Bytes}, nil); err != nil {
		t.Fatalf("expected pinned certificate to verify: %v", err)
	}
	wrong := make([]byte, len(block.Bytes))
	copy(wrong, block.Bytes)
	wrong[len(wrong)-1] ^= 0xff
	if err := cfg.VerifyPeerCertificate([][]byte{wrong}, nil); err == nil {
		t.Fatalf("expected mismatched certificate pin to fail")
	}
	assertHardenedClientTLSConfig(t, cfg)
}

func TestBuildClientConfigRejectsInvalidCertSHA256Pin(t *testing.T) {
	if _, err := BuildClientConfig(ClientOptions{Server: "example.com:443", CertSHA256: "bad"}); err == nil {
		t.Fatalf("expected invalid cert_sha256 error")
	}
}

func assertHardenedClientTLSConfig(t *testing.T, cfg *tls.Config) {
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
}
