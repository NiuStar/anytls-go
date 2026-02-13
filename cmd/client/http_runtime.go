package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func runtimeRequestURLCandidates(rawURL string) []string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	mirrored := withRuntimeGitHubMirror(rawURL)
	if mirrored == "" || mirrored == rawURL {
		return []string{rawURL}
	}
	return []string{mirrored, rawURL}
}

func runtimeResolverServers() []string {
	servers := make([]string, 0, 8)
	servers = append(servers, discoverSystemDNSServers()...)
	servers = append(servers,
		"223.5.5.5:53",
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
	)
	return dedupStringList(servers)
}

func newRuntimeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	resolverDialer := &net.Dialer{Timeout: 2 * time.Second}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			servers := runtimeResolverServers()
			if len(servers) == 0 {
				return resolverDialer.DialContext(ctx, network, address)
			}
			networks := make([]string, 0, 3)
			for _, proto := range []string{network, "udp", "tcp"} {
				proto = strings.TrimSpace(proto)
				if proto == "" {
					continue
				}
				dup := false
				for _, existing := range networks {
					if existing == proto {
						dup = true
						break
					}
				}
				if !dup {
					networks = append(networks, proto)
				}
			}
			var lastErr error
			for _, server := range servers {
				for _, proto := range networks {
					conn, err := resolverDialer.DialContext(ctx, proto, server)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
			}
			if lastErr != nil {
				return nil, fmt.Errorf("all resolver upstreams failed: %w", lastErr)
			}
			return resolverDialer.DialContext(ctx, network, address)
		},
	}
	dialTimeout := 8 * time.Second
	if timeout < dialTimeout {
		dialTimeout = timeout
	}
	if dialTimeout < 2*time.Second {
		dialTimeout = 2 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
