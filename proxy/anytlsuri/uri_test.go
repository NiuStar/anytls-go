package anytlsuri

import (
	"strings"
	"testing"
)

func TestParseWithTLSOptions(t *testing.T) {
	node, err := Parse("anytls://pass%40word@example.com:443?sni=test.example&egress-ip=203.0.113.9&egress-rule=all%3D203.0.113.1&insecure=0&ca-cert-path=%2Fetc%2Fanytls%2Fca.crt")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if node.Server != "example.com:443" {
		t.Fatalf("server mismatch: %q", node.Server)
	}
	if node.Password != "pass@word" {
		t.Fatalf("password mismatch: %q", node.Password)
	}
	if node.SNI != "test.example" {
		t.Fatalf("sni mismatch: %q", node.SNI)
	}
	if node.EgressIP != "203.0.113.9" {
		t.Fatalf("egress ip mismatch: %q", node.EgressIP)
	}
	if node.EgressRule != "all=203.0.113.1" {
		t.Fatalf("egress rule mismatch: %q", node.EgressRule)
	}
	if node.AllowInsecure == nil || *node.AllowInsecure {
		t.Fatalf("allow_insecure should be false, got %+v", node.AllowInsecure)
	}
	if node.CACertPath != "/etc/anytls/ca.crt" {
		t.Fatalf("ca_cert_path mismatch: %q", node.CACertPath)
	}
}

func TestBuildWithTLSOptions(t *testing.T) {
	allowInsecure := false
	raw, err := Build(Node{
		Server:        "example.com:443",
		Password:      "pass@word",
		SNI:           "test.example",
		EgressIP:      "203.0.113.9",
		EgressRule:    "all=203.0.113.1",
		AllowInsecure: &allowInsecure,
		CACertPath:    "/etc/anytls/ca.crt",
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if !strings.HasPrefix(raw, "anytls://pass%40word@example.com:443/?") {
		t.Fatalf("uri should keep slash path style, got: %s", raw)
	}
	node, err := Parse(raw)
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	if node.Server != "example.com:443" || node.Password != "pass@word" || node.SNI != "test.example" {
		t.Fatalf("round trip mismatch: %+v", node)
	}
	if node.AllowInsecure == nil || *node.AllowInsecure {
		t.Fatalf("allow_insecure should be false, got %+v", node.AllowInsecure)
	}
	if node.CACertPath != "/etc/anytls/ca.crt" {
		t.Fatalf("ca_cert_path mismatch: %q", node.CACertPath)
	}
}
