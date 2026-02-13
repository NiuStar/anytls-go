package main

import (
	"net"
	"net/url"
	"os"
	"strings"
)

func runtimeGitHubMirrorPrefix() string {
	raw := strings.TrimSpace(os.Getenv("ANYTLS_GITHUB_MIRROR_PREFIX"))
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return ""
	}
	return strings.TrimRight(raw, "/") + "/"
}

func withRuntimeGitHubMirror(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return rawURL
	}
	prefix := runtimeGitHubMirrorPrefix()
	if prefix == "" || strings.HasPrefix(rawURL, prefix) {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rawURL
	}
	host := u.Hostname()
	if !isGitHubLikeHost(host) {
		return rawURL
	}
	// github API is generally reachable directly and mirrors may not proxy it correctly.
	if strings.EqualFold(host, "api.github.com") {
		return rawURL
	}
	return prefix + rawURL
}

func isGitHubLikeHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.ToLower(strings.TrimSpace(h))
	}
	if host == "github.com" || host == "raw.githubusercontent.com" {
		return true
	}
	return strings.HasSuffix(host, ".github.com") || strings.HasSuffix(host, ".githubusercontent.com")
}
