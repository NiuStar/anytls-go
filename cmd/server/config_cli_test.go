package main

import (
	"anytls/proxy/tlsopts"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveServerPasswordFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("secret-value\n"), 0600); err != nil {
		t.Fatalf("write password file failed: %v", err)
	}
	got, err := resolveServerPassword("", path)
	if err != nil {
		t.Fatalf("resolve password failed: %v", err)
	}
	if got != "secret-value" {
		t.Fatalf("password=%q want secret-value", got)
	}
}

func TestResolveServerPasswordRejectsAmbiguousOrMultilineInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("line-one\nline-two\n"), 0600); err != nil {
		t.Fatalf("write password file failed: %v", err)
	}
	if _, err := resolveServerPassword("direct", path); err == nil {
		t.Fatalf("expected direct password plus password file to fail")
	}
	if _, err := resolveServerPassword("", path); err == nil {
		t.Fatalf("expected multiline password file to fail")
	}
}

func TestParseOptionalBool(t *testing.T) {
	v, err := parseOptionalBool("")
	if err != nil {
		t.Fatalf("parseOptionalBool empty error: %v", err)
	}
	if v != nil {
		t.Fatalf("parseOptionalBool empty = %v, want nil", *v)
	}

	v, err = parseOptionalBool("true")
	if err != nil {
		t.Fatalf("parseOptionalBool true error: %v", err)
	}
	if v == nil || !*v {
		t.Fatalf("parseOptionalBool true = %v, want true", v)
	}

	v, err = parseOptionalBool("false")
	if err != nil {
		t.Fatalf("parseOptionalBool false error: %v", err)
	}
	if v == nil || *v {
		t.Fatalf("parseOptionalBool false = %v, want false", v)
	}

	if _, err := parseOptionalBool("maybe"); err == nil {
		t.Fatalf("parseOptionalBool should fail on invalid input")
	}
}

func TestBuildNodeURI_WithTLSFields(t *testing.T) {
	insecure := false
	uri, err := buildNodeURI(
		"pass",
		"example.com:443",
		"example.com",
		"",
		"",
		&insecure,
		"/etc/anytls/ca.crt",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("buildNodeURI error: %v", err)
	}
	if !strings.HasPrefix(uri, "anytls://pass@example.com:443/?") {
		t.Fatalf("unexpected uri prefix: %s", uri)
	}
	if !strings.Contains(uri, "insecure=0") {
		t.Fatalf("uri missing insecure=0: %s", uri)
	}
	if !strings.Contains(uri, "ca-cert-path=%2Fetc%2Fanytls%2Fca.crt") {
		t.Fatalf("uri missing encoded ca-cert-path: %s", uri)
	}
	if !strings.Contains(uri, "cert-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Fatalf("uri missing cert-sha256: %s", uri)
	}
}

func TestServerConfigEditReadsPasswordFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.env")
	passwordPath := filepath.Join(dir, "server.password")
	if err := os.WriteFile(passwordPath, []byte("secret-from-file\n"), 0600); err != nil {
		t.Fatalf("write password file failed: %v", err)
	}
	if err := runServerConfigEdit([]string{
		"--config", configPath,
		"--listen", "127.0.0.1:18443",
		"--password-file", passwordPath,
		"--auto-cert",
		"--yes",
	}); err != nil {
		t.Fatalf("config edit with password file failed: %v", err)
	}
	cfg, err := loadServerEnvConfig(configPath)
	if err != nil {
		t.Fatalf("load generated config failed: %v", err)
	}
	if cfg.Password != "secret-from-file" {
		t.Fatalf("generated password=%q", cfg.Password)
	}
}

func TestServerConfigAutoCertExportIncludesPinnedURI(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.env")
	if err := runServerConfigEdit([]string{
		"--config", configPath,
		"--listen", "127.0.0.1:18443",
		"--password", "secret",
		"--auto-cert",
		"--yes",
	}); err != nil {
		t.Fatalf("config edit failed: %v", err)
	}

	autoDir := defaultServerAutoCertDirForConfig(configPath)
	fp, err := tlsopts.CertificateSHA256FromPEMFile(filepath.Join(autoDir, tlsopts.AutoCertFileName))
	if err != nil {
		t.Fatalf("auto cert fingerprint missing: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runServerConfigExport([]string{
			"--config", configPath,
			"--addr", "127.0.0.1:18443",
			"--node-prefix", "oneclick",
			"--yes",
		}); err != nil {
			t.Fatalf("config export failed: %v", err)
		}
	})
	if !strings.Contains(out, "cert-sha256="+fp) {
		t.Fatalf("export output missing cert-sha256 pin %s:\n%s", fp, out)
	}
	if strings.Contains(out, "insecure=1") || strings.Contains(out, "allow_insecure=true") {
		t.Fatalf("export should not downgrade to insecure mode:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout failed: %v", err)
	}
	return string(b)
}
