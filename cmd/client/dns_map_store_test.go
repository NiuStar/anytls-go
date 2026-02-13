package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestDNSDomainMapRecordLookupAndExpire(t *testing.T) {
	m := newDNSDomainMap()
	ip := netip.MustParseAddr("1.1.1.1")
	m.Record("Example.com", []netip.Addr{ip}, 80*time.Millisecond)

	got := m.LookupByIP("1.1.1.1")
	if len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("unexpected lookup result: %+v", got)
	}

	time.Sleep(120 * time.Millisecond)
	got = m.LookupByIP("1.1.1.1")
	if len(got) != 0 {
		t.Fatalf("expected expired mapping to be removed, got: %+v", got)
	}
}

func TestDNSDomainMapLookupByDomain(t *testing.T) {
	m := newDNSDomainMap()
	ip1 := netip.MustParseAddr("1.1.1.1")
	ip2 := netip.MustParseAddr("8.8.8.8")
	m.Record("www.baidu.com", []netip.Addr{ip1, ip2}, 5*time.Minute)

	ips := m.LookupByDomain("WWW.BAIDU.COM")
	if len(ips) != 2 {
		t.Fatalf("unexpected ip count: %d", len(ips))
	}
	if ips[0] != ip1 || ips[1] != ip2 {
		t.Fatalf("unexpected lookup by domain result: %+v", ips)
	}
}

func TestDNSDomainMapRemoveDomainsCleansBothDirections(t *testing.T) {
	m := newDNSDomainMap()
	ip := netip.MustParseAddr("1.1.1.1")
	m.Record("www.baidu.com", []netip.Addr{ip}, 5*time.Minute)

	removed := m.RemoveDomains([]string{"WWW.BAIDU.COM"})
	if removed != 1 {
		t.Fatalf("unexpected removed count: %d", removed)
	}
	if got := m.LookupByDomain("www.baidu.com"); len(got) != 0 {
		t.Fatalf("expected domain mapping removed, got %+v", got)
	}
	if got := m.LookupByIP("1.1.1.1"); len(got) != 0 {
		t.Fatalf("expected reverse ip mapping removed, got %+v", got)
	}
}

func TestDNSDomainMapBlockDomainIPsSkipsRecordAndLookup(t *testing.T) {
	m := newDNSDomainMap()
	blockedCount := m.BlockDomainIPs("www.google.com", []string{"31.13.94.41"}, 5*time.Minute)
	if blockedCount != 1 {
		t.Fatalf("unexpected blocked count: %d", blockedCount)
	}

	allowed := netip.MustParseAddr("142.251.40.100")
	blocked := netip.MustParseAddr("31.13.94.41")
	m.Record("www.google.com", []netip.Addr{blocked, allowed}, 5*time.Minute)

	ips := m.LookupByDomain("WWW.GOOGLE.COM")
	if len(ips) != 1 || ips[0] != allowed {
		t.Fatalf("expected only allowed ip, got %+v", ips)
	}

	blockedDomains := m.LookupByIP("31.13.94.41")
	if len(blockedDomains) != 0 {
		t.Fatalf("blocked ip should not have reverse mapping, got %+v", blockedDomains)
	}
}

func TestDNSDomainMapBlockedEntryExpires(t *testing.T) {
	m := newDNSDomainMap()
	_ = m.BlockDomainIPs("www.google.com", []string{"31.13.94.41"}, 80*time.Millisecond)
	time.Sleep(120 * time.Millisecond)

	blocked := netip.MustParseAddr("31.13.94.41")
	m.Record("www.google.com", []netip.Addr{blocked}, 5*time.Minute)
	ips := m.LookupByDomain("www.google.com")
	if len(ips) != 1 || ips[0] != blocked {
		t.Fatalf("expected blocked entry expired and ip recorded, got %+v", ips)
	}
}
