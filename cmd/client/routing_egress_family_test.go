package main

import (
	"errors"
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestResolveDestinationForNodeEgressFamilyFQDNFromCache(t *testing.T) {
	node := clientNodeConfig{
		Name:     "node-v6",
		EgressIP: "240e:6b0:d00:803::a096:b",
	}
	destination := M.Socksaddr{
		Fqdn: "www.google.com",
		Port: 443,
	}
	called := false
	resolver := func(host string, family nodeEgressIPFamily) ([]netip.Addr, error) {
		called = true
		return nil, nil
	}
	got, err := resolveDestinationForNodeEgressFamilyWithResolver(node, destination, nil, nil, resolver)
	if err != nil {
		t.Fatalf("resolve destination failed: %v", err)
	}
	if !got.IsFqdn() || got.Fqdn != "www.google.com" {
		t.Fatalf("expected fqdn destination unchanged, got %+v", got)
	}
	if called {
		t.Fatalf("resolver should not be called for fqdn destination")
	}
}

func TestResolveDestinationForNodeEgressFamilyIPMismatchByHintedHost(t *testing.T) {
	node := clientNodeConfig{
		Name:     "node-v6",
		EgressIP: "240e:6b0:d00:803::a096:b",
	}
	destination := M.Socksaddr{
		Addr: netip.MustParseAddr("142.250.72.68"),
		Port: 443,
	}
	called := false
	resolver := func(host string, family nodeEgressIPFamily) ([]netip.Addr, error) {
		called = true
		return nil, nil
	}
	got, err := resolveDestinationForNodeEgressFamilyWithResolver(node, destination, []string{"www.google.com"}, nil, resolver)
	if err != nil {
		t.Fatalf("resolve destination failed: %v", err)
	}
	if !got.IsFqdn() || got.Fqdn != "www.google.com" {
		t.Fatalf("expected fqdn rewrite by hinted host, got %+v", got)
	}
	if called {
		t.Fatalf("resolver should not be called when hinted host can be used directly")
	}
}

func TestResolveDestinationForNodeEgressFamilyNoMatchingFamily(t *testing.T) {
	node := clientNodeConfig{
		Name:     "node-v6",
		EgressIP: "240e:6b0:d00:803::a096:b",
	}
	destination := M.Socksaddr{
		Fqdn: "www.example.com",
		Port: 443,
	}
	got, err := resolveDestinationForNodeEgressFamilyWithResolver(node, destination, nil, nil, nil)
	if err != nil {
		t.Fatalf("expected fqdn keep success, got err=%v", err)
	}
	if !got.IsFqdn() || got.Fqdn != "www.example.com" {
		t.Fatalf("expected original fqdn destination, got %+v", got)
	}
}

func TestResolveDestinationForNodeEgressFamilyIPMismatchWithoutHintsFallbackOriginal(t *testing.T) {
	node := clientNodeConfig{
		Name:     "node-v6",
		EgressIP: "240e:6b0:d00:803::a096:b",
	}
	destination := M.Socksaddr{
		Addr: netip.MustParseAddr("142.250.72.68"),
		Port: 443,
	}
	got, err := resolveDestinationForNodeEgressFamilyWithResolver(node, destination, nil, nil, nil)
	if err != nil {
		t.Fatalf("expected no hard-fail, got err=%v", err)
	}
	if got.String() != destination.String() {
		t.Fatalf("expected original destination fallback, got=%s want=%s", got.String(), destination.String())
	}
}

func TestResolveDestinationForNodeEgressFamilyStrictIPv6UDPRejectsIPv4Literal(t *testing.T) {
	node := clientNodeConfig{
		Name:     "node-v6",
		EgressIP: "240e:6b0:d00:803::a096:b",
	}
	destination := M.Socksaddr{
		Addr: netip.MustParseAddr("142.250.72.68"),
		Port: 443,
	}
	_, err := resolveDestinationForNodeEgressFamilyWithMode(node, destination, nil, nil, nil, true, true)
	if err == nil {
		t.Fatalf("expected strict IPv6 UDP mismatch to fail")
	}
	if !errors.Is(err, errRouteRejected) {
		t.Fatalf("expected errRouteRejected, got: %v", err)
	}
}

func TestResolveDestinationForNodeEgressFamilyStrictIPv6TCPRequiresHostHint(t *testing.T) {
	node := clientNodeConfig{
		Name:     "node-v6",
		EgressIP: "240e:6b0:d00:803::a096:b",
	}
	destination := M.Socksaddr{
		Addr: netip.MustParseAddr("142.250.72.68"),
		Port: 443,
	}
	_, err := resolveDestinationForNodeEgressFamilyWithMode(node, destination, nil, nil, nil, true, false)
	if err == nil {
		t.Fatalf("expected strict IPv6 TCP mismatch without hints to fail")
	}
}
