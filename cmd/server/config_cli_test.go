package main

import (
	"anytls/proxy/tlsopts"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
