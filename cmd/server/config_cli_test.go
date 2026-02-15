package main

import (
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
}
