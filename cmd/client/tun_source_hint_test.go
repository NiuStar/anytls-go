package main

import (
	"net"
	"testing"
	"time"
)

func resetTunSourceHintStoreForTest() {
	tunSourceHintStore.mu.Lock()
	defer tunSourceHintStore.mu.Unlock()
	tunSourceHintStore.byEndpoint = make(map[string]tunSourceHintEntry)
	tunSourceHintStore.byPort = make(map[string]tunSourceHintEntry)
	tunSourceHintStore.lastCleanup = time.Time{}
}

func TestResolveRoutingSourceClientFromTunHint(t *testing.T) {
	resetTunSourceHintStoreForTest()
	registerTunSourceHint(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40123}, "192.168.10.8:51234")

	got := resolveRoutingSourceClient("127.0.0.1:40123")
	if got != "192.168.10.8" {
		t.Fatalf("expected mapped source 192.168.10.8, got %q", got)
	}
}

func TestResolveRoutingSourceClientKeepsNonLoopback(t *testing.T) {
	resetTunSourceHintStoreForTest()
	got := resolveRoutingSourceClient("192.168.1.25:43001")
	if got != "192.168.1.25" {
		t.Fatalf("expected non-loopback normalized source, got %q", got)
	}
}

func TestResolveRoutingSourceClientExpiredHintFallback(t *testing.T) {
	resetTunSourceHintStoreForTest()
	tunSourceHintStore.mu.Lock()
	tunSourceHintStore.byEndpoint["127.0.0.1:40001"] = tunSourceHintEntry{source: "192.168.2.9", expireAt: time.Now().Add(-time.Second)}
	tunSourceHintStore.byPort["40001"] = tunSourceHintEntry{source: "192.168.2.9", expireAt: time.Now().Add(-time.Second)}
	tunSourceHintStore.mu.Unlock()

	got := resolveRoutingSourceClient("127.0.0.1:40001")
	if got != "127.0.0.1" {
		t.Fatalf("expected fallback loopback source, got %q", got)
	}
}
