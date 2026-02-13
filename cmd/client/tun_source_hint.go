package main

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tunSourceHintTTL = 2 * time.Minute
const tunSourceHintMax = 8192

type tunSourceHintEntry struct {
	source   string
	expireAt time.Time
}

var tunSourceHintStore = struct {
	mu          sync.Mutex
	byEndpoint  map[string]tunSourceHintEntry
	byPort      map[string]tunSourceHintEntry
	lastCleanup time.Time
}{
	byEndpoint: make(map[string]tunSourceHintEntry, 512),
	byPort:     make(map[string]tunSourceHintEntry, 512),
}

func registerTunSourceHint(localAddr net.Addr, source string) {
	source = normalizeRoutingHitSourceClient(source)
	if source == "" || localAddr == nil {
		return
	}
	endpointKey, portKey, ok := loopbackEndpointKeys(localAddr.String())
	if !ok {
		return
	}

	now := time.Now()
	expireAt := now.Add(tunSourceHintTTL)

	tunSourceHintStore.mu.Lock()
	defer tunSourceHintStore.mu.Unlock()

	tunSourceHintStore.byEndpoint[endpointKey] = tunSourceHintEntry{source: source, expireAt: expireAt}
	tunSourceHintStore.byPort[portKey] = tunSourceHintEntry{source: source, expireAt: expireAt}

	if len(tunSourceHintStore.byEndpoint) > tunSourceHintMax || now.Sub(tunSourceHintStore.lastCleanup) > 30*time.Second {
		pruneTunSourceHintsLocked(now)
	}
}

func resolveRoutingSourceClient(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	endpointKey, portKey, ok := loopbackEndpointKeys(raw)
	if !ok {
		return normalizeRoutingHitSourceClient(raw)
	}

	now := time.Now()
	tunSourceHintStore.mu.Lock()
	defer tunSourceHintStore.mu.Unlock()

	if entry, exists := tunSourceHintStore.byEndpoint[endpointKey]; exists {
		if now.Before(entry.expireAt) {
			return entry.source
		}
		delete(tunSourceHintStore.byEndpoint, endpointKey)
	}
	if entry, exists := tunSourceHintStore.byPort[portKey]; exists {
		if now.Before(entry.expireAt) {
			return entry.source
		}
		delete(tunSourceHintStore.byPort, portKey)
	}
	return normalizeRoutingHitSourceClient(raw)
}

func loopbackEndpointKeys(raw string) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", "", false
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil || !ip.IsLoopback() {
		return "", "", false
	}
	if _, err := strconv.Atoi(strings.TrimSpace(port)); err != nil {
		return "", "", false
	}
	return strings.ToLower(net.JoinHostPort(ip.String(), strings.TrimSpace(port))), strings.TrimSpace(port), true
}

func pruneTunSourceHintsLocked(now time.Time) {
	for key, entry := range tunSourceHintStore.byEndpoint {
		if now.After(entry.expireAt) {
			delete(tunSourceHintStore.byEndpoint, key)
		}
	}
	for key, entry := range tunSourceHintStore.byPort {
		if now.After(entry.expireAt) {
			delete(tunSourceHintStore.byPort, key)
		}
	}
	tunSourceHintStore.lastCleanup = now
}
