package util

import "testing"

func TestWireClientTagDefaultsToEmpty(t *testing.T) {
	t.Setenv("ANYTLS_WIRE_CLIENT_TAG", "")
	if got := WireClientTag(); got != "" {
		t.Fatalf("default client tag should be empty, got %q", got)
	}
}

func TestWireClientTagExplicitOverride(t *testing.T) {
	t.Setenv("ANYTLS_WIRE_CLIENT_TAG", " custom-client ")
	if got := WireClientTag(); got != "custom-client" {
		t.Fatalf("unexpected client tag: %q", got)
	}
}
