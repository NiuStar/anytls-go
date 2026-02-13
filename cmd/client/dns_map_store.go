package main

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type dnsDomainMap struct {
	lock             sync.Mutex
	ipDomains        map[string]map[string]time.Time
	domainIPs        map[string]map[string]time.Time
	domainBlockedIPs map[string]map[string]time.Time
}

func newDNSDomainMap() *dnsDomainMap {
	return &dnsDomainMap{
		ipDomains:        make(map[string]map[string]time.Time),
		domainIPs:        make(map[string]map[string]time.Time),
		domainBlockedIPs: make(map[string]map[string]time.Time),
	}
}

func (m *dnsDomainMap) Record(domain string, ips []netip.Addr, ttl time.Duration) {
	if m == nil {
		return
	}
	domain = normalizeHost(domain)
	if domain == "" || len(ips) == 0 {
		return
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	expireAt := time.Now().Add(ttl)

	m.lock.Lock()
	defer m.lock.Unlock()
	m.cleanupExpiredLocked(time.Now())
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		key := ip.Unmap().String()
		if key == "" {
			continue
		}
		if m.isDomainIPBlockedLocked(domain, key, time.Now()) {
			continue
		}
		if _, ok := m.ipDomains[key]; !ok {
			m.ipDomains[key] = make(map[string]time.Time)
		}
		m.ipDomains[key][domain] = expireAt
		if _, ok := m.domainIPs[domain]; !ok {
			m.domainIPs[domain] = make(map[string]time.Time)
		}
		m.domainIPs[domain][key] = expireAt
	}
}

func (m *dnsDomainMap) LookupByIP(ip string) []string {
	if m == nil {
		return nil
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	now := time.Now()
	m.lock.Lock()
	defer m.lock.Unlock()
	domainMap, ok := m.ipDomains[ip]
	if !ok || len(domainMap) == 0 {
		return nil
	}
	out := make([]string, 0, len(domainMap))
	for domain, expireAt := range domainMap {
		if now.After(expireAt) {
			m.removeMappingLocked(ip, domain)
			continue
		}
		out = append(out, domain)
	}
	if len(domainMap) == 0 {
		delete(m.ipDomains, ip)
	}
	sort.Strings(out)
	return out
}

func (m *dnsDomainMap) LookupByDomain(domain string) []netip.Addr {
	if m == nil {
		return nil
	}
	domain = normalizeHost(domain)
	if domain == "" {
		return nil
	}
	now := time.Now()
	m.lock.Lock()
	defer m.lock.Unlock()
	ipMap, ok := m.domainIPs[domain]
	if !ok || len(ipMap) == 0 {
		return nil
	}
	ipKeys := make([]string, 0, len(ipMap))
	for ip, expireAt := range ipMap {
		if now.After(expireAt) {
			m.removeMappingLocked(ip, domain)
			continue
		}
		if m.isDomainIPBlockedLocked(domain, ip, now) {
			m.removeMappingLocked(ip, domain)
			continue
		}
		ipKeys = append(ipKeys, ip)
	}
	if len(ipMap) == 0 {
		delete(m.domainIPs, domain)
	}
	sort.Strings(ipKeys)
	out := make([]netip.Addr, 0, len(ipKeys))
	for _, ipKey := range ipKeys {
		addr, err := netip.ParseAddr(ipKey)
		if err != nil || !addr.IsValid() {
			m.removeMappingLocked(ipKey, domain)
			continue
		}
		out = append(out, addr)
	}
	return out
}

func (m *dnsDomainMap) cleanupExpiredLocked(now time.Time) {
	for ip, domainMap := range m.ipDomains {
		for domain, expireAt := range domainMap {
			if now.After(expireAt) {
				m.removeMappingLocked(ip, domain)
			}
		}
		if len(domainMap) == 0 {
			delete(m.ipDomains, ip)
		}
	}
	for domain, ipMap := range m.domainIPs {
		for ip, expireAt := range ipMap {
			if now.After(expireAt) {
				m.removeMappingLocked(ip, domain)
			}
		}
		if len(ipMap) == 0 {
			delete(m.domainIPs, domain)
		}
	}
	for domain, ipMap := range m.domainBlockedIPs {
		for ip, expireAt := range ipMap {
			if now.After(expireAt) {
				delete(ipMap, ip)
			}
		}
		if len(ipMap) == 0 {
			delete(m.domainBlockedIPs, domain)
		}
	}
}

func (m *dnsDomainMap) Stats() (ipCount int, mappingCount int) {
	if m == nil {
		return 0, 0
	}
	now := time.Now()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.cleanupExpiredLocked(now)
	ipCount = len(m.ipDomains)
	for _, domainMap := range m.ipDomains {
		mappingCount += len(domainMap)
	}
	return ipCount, mappingCount
}

func (m *dnsDomainMap) RemoveDomains(domains []string) int {
	if m == nil {
		return 0
	}
	domains = appendUniqueStrings(nil, domains...)
	if len(domains) == 0 {
		return 0
	}
	domainSet := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		host := normalizeHost(raw)
		if host == "" {
			continue
		}
		domainSet[host] = struct{}{}
	}
	if len(domainSet) == 0 {
		return 0
	}

	removed := 0
	now := time.Now()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.cleanupExpiredLocked(now)
	for domain := range domainSet {
		ipMap := m.domainIPs[domain]
		for ip := range ipMap {
			m.removeMappingLocked(ip, domain)
			removed++
		}
		delete(m.domainBlockedIPs, domain)
	}
	return removed
}

func (m *dnsDomainMap) BlockDomainIPs(domain string, ips []string, ttl time.Duration) int {
	if m == nil {
		return 0
	}
	domain = normalizeHost(domain)
	if domain == "" || len(ips) == 0 {
		return 0
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	expireAt := time.Now().Add(ttl)
	uniqueIPs := appendUniqueStrings(nil, ips...)
	if len(uniqueIPs) == 0 {
		return 0
	}

	blocked := 0
	now := time.Now()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.cleanupExpiredLocked(now)
	if _, ok := m.domainBlockedIPs[domain]; !ok {
		m.domainBlockedIPs[domain] = make(map[string]time.Time)
	}
	for _, raw := range uniqueIPs {
		ipText := strings.TrimSpace(strings.Trim(raw, "[]"))
		if ipText == "" {
			continue
		}
		addr, err := netip.ParseAddr(ipText)
		if err != nil || !addr.IsValid() {
			continue
		}
		key := addr.Unmap().String()
		if key == "" {
			continue
		}
		m.domainBlockedIPs[domain][key] = expireAt
		m.removeMappingLocked(key, domain)
		blocked++
	}
	return blocked
}

func (m *dnsDomainMap) CountBlockedDomainIPs(domain string, ips []netip.Addr) int {
	if m == nil {
		return 0
	}
	domain = normalizeHost(domain)
	if domain == "" || len(ips) == 0 {
		return 0
	}
	now := time.Now()
	count := 0
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		if m.isDomainIPBlockedLocked(domain, ip.Unmap().String(), now) {
			count++
		}
	}
	return count
}

func (m *dnsDomainMap) FilterBlockedDomainIPs(domain string, ips []netip.Addr) ([]netip.Addr, int) {
	if m == nil {
		return append([]netip.Addr(nil), ips...), 0
	}
	domain = normalizeHost(domain)
	if domain == "" || len(ips) == 0 {
		return append([]netip.Addr(nil), ips...), 0
	}
	now := time.Now()
	filtered := make([]netip.Addr, 0, len(ips))
	blocked := 0
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		key := ip.Unmap().String()
		if key == "" {
			continue
		}
		if m.isDomainIPBlockedLocked(domain, key, now) {
			blocked++
			continue
		}
		filtered = append(filtered, ip.Unmap())
	}
	return filtered, blocked
}

func (m *dnsDomainMap) isDomainIPBlockedLocked(domain string, ip string, now time.Time) bool {
	domain = normalizeHost(domain)
	ip = strings.TrimSpace(ip)
	if domain == "" || ip == "" {
		return false
	}
	blockedMap := m.domainBlockedIPs[domain]
	if len(blockedMap) == 0 {
		return false
	}
	expireAt, ok := blockedMap[ip]
	if !ok {
		return false
	}
	if now.After(expireAt) {
		delete(blockedMap, ip)
		if len(blockedMap) == 0 {
			delete(m.domainBlockedIPs, domain)
		}
		return false
	}
	return true
}

func (m *dnsDomainMap) removeMappingLocked(ip string, domain string) {
	ip = strings.TrimSpace(ip)
	domain = normalizeHost(domain)
	if ip != "" {
		if domainMap, ok := m.ipDomains[ip]; ok {
			delete(domainMap, domain)
			if len(domainMap) == 0 {
				delete(m.ipDomains, ip)
			}
		}
	}
	if domain != "" {
		if ipMap, ok := m.domainIPs[domain]; ok {
			delete(ipMap, ip)
			if len(ipMap) == 0 {
				delete(m.domainIPs, domain)
			}
		}
	}
}
