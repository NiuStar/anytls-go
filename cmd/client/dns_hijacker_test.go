package main

import (
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestShouldUseDoHOnlyOpenWrtDomainPolicy(t *testing.T) {
	h := &dnsHijacker{openwrt: true}
	if !h.shouldUseDoHOnly("www.google.com") {
		t.Fatalf("expected public non-cn domain to use DoH only on openwrt")
	}
	if h.shouldUseDoHOnly("www.baidu.cn") {
		t.Fatalf("expected .cn domain to allow plain DNS fallback on openwrt")
	}
	if h.shouldUseDoHOnly("router.lan") {
		t.Fatalf("expected local domain to bypass DoH-only policy")
	}
}

func TestShouldUseDoHOnlyDarwinPolicy(t *testing.T) {
	h := &dnsHijacker{darwinPublicDoHOnly: true}
	if !h.shouldUseDoHOnly("www.cloudflare.com") {
		t.Fatalf("expected darwin public domain to use DoH only")
	}
	if h.shouldUseDoHOnly("nas.local") {
		t.Fatalf("expected darwin local domain to bypass DoH-only policy")
	}
}

func TestDefaultDoHUpstreamsContainIPv6AndIPv4(t *testing.T) {
	items := defaultDoHUpstreams()
	if len(items) == 0 {
		t.Fatalf("default DoH upstreams should not be empty")
	}
	hasV4 := false
	hasV6 := false
	for _, item := range items {
		host := strings.TrimSpace(item.Addr)
		if host == "" {
			continue
		}
		h, _, err := net.SplitHostPort(host)
		if err != nil {
			t.Fatalf("invalid upstream addr %q: %v", item.Addr, err)
		}
		h = strings.Trim(h, "[]")
		ip := net.ParseIP(h)
		if ip == nil {
			t.Fatalf("upstream addr host is not IP: %q", item.Addr)
		}
		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	if !hasV4 || !hasV6 {
		t.Fatalf("expected mixed IPv4/IPv6 DoH upstreams, got v4=%v v6=%v", hasV4, hasV6)
	}
}

func TestShouldReplyEmptyByEgressFamily(t *testing.T) {
	h := &dnsHijacker{}
	h.SetDomainFamilyResolver(func(domain string) nodeEgressIPFamily {
		if strings.Contains(domain, "v6") {
			return nodeEgressFamilyIPv6
		}
		if strings.Contains(domain, "v4") {
			return nodeEgressFamilyIPv4
		}
		return nodeEgressFamilyAny
	})

	blocked, reason := h.shouldReplyEmptyByEgressFamily("api.v6.example", dnsmessage.TypeA)
	if !blocked || reason == "" {
		t.Fatalf("expected A query to be blocked for ipv6 egress, blocked=%v reason=%q", blocked, reason)
	}
	blocked, reason = h.shouldReplyEmptyByEgressFamily("api.v6.example", dnsmessage.TypeAAAA)
	if blocked {
		t.Fatalf("expected AAAA query to pass for ipv6 egress, blocked=%v reason=%q", blocked, reason)
	}

	blocked, reason = h.shouldReplyEmptyByEgressFamily("api.v4.example", dnsmessage.TypeAAAA)
	if !blocked || reason == "" {
		t.Fatalf("expected AAAA query to be blocked for ipv4 egress, blocked=%v reason=%q", blocked, reason)
	}
	blocked, reason = h.shouldReplyEmptyByEgressFamily("api.v4.example", dnsmessage.TypeA)
	if blocked {
		t.Fatalf("expected A query to pass for ipv4 egress, blocked=%v reason=%q", blocked, reason)
	}
}
