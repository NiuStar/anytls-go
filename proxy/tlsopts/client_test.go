package tlsopts

import (
	"crypto/rand"
	"crypto/rsa"
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
