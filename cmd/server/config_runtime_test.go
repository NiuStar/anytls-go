package main

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestConfigRunStartsRealTLS(t *testing.T) {
	d := t.TempDir()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.Addr().String()
	reserve.Close()
	path := filepath.Join(d, "server.env")
	if err := saveServerEnvConfig(path, serverEnvConfig{Listen: addr, Password: `$NAME$(printf EXECUTED)\literal`}); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run", "^TestReviewConfigCLIHelper$", "--", "config", "run", "--config", path)
	cmd.Env = append(os.Environ(), "REVIEW_CONFIG_HELPER=1", "ANYTLS_AUTO_CERT_DIR="+filepath.Join(d, "certs"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	for ctx.Err() == nil {
		dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("config run did not start actual TLS listener")
}

func TestRuntimeConfigLiteralTLSAndPasswordPriority(t *testing.T) {
	for _, password := range []string{`$NAME`, `$(printf EXECUTED >&2)secret`, "`printf EXECUTED >&2`secret", `back\slash'"quote`} {
		d := t.TempDir()
		path := filepath.Join(d, "server.env")
		cfg := serverEnvConfig{Listen: "127.0.0.1:9555", Password: password, CertDir: `/literal/$NAME/$(no)/certs`, CertFile: `/literal/"cert`, KeyFile: `/literal/\key`, CACertFile: "/literal/`ca`", CAKeyFile: `/literal/'key`}
		if err := saveServerEnvConfig(path, cfg); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := loadServerRuntimeConfig(path, "")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, cfg) {
			t.Fatal("config values changed")
		}
		expected := []string{"-l", cfg.Listen, "-p", password, "--cert-dir", cfg.CertDir, "--cert-file", cfg.CertFile, "--key-file", cfg.KeyFile, "--ca-cert", cfg.CACertFile, "--ca-key", cfg.CAKeyFile}
		if !reflect.DeepEqual(serverConfigRuntimeArgs(got), expected) {
			t.Fatal("runtime TLS/listen/password argv changed")
		}
		passwordPath := filepath.Join(d, "server.password")
		if err := os.WriteFile(passwordPath, []byte(password+"different\n"), 0600); err != nil {
			t.Fatal(err)
		}
		got, err = loadServerRuntimeConfig(path, "")
		if err != nil || got.Password != password+"different" {
			t.Fatalf("password file not authoritative: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(before) != string(after) {
			t.Fatal("runtime loader rewrote config")
		}
	}
}
