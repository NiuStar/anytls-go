package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
	xproxy "golang.org/x/net/proxy"
)

type dnsHijacker struct {
	domainMap *dnsDomainMap
	upstreams []string
	doh       []dnsDoHUpstream
	timeout   time.Duration
	openwrt   bool
	socks     string
	dialer    xproxy.Dialer
	dialTO    time.Duration
	lastAAAA  time.Time
	mu        sync.Mutex
	health    map[string]*dnsUpstreamHealth

	udpQueries uint64
	tcpQueries uint64
	successes  uint64
	failures   uint64
}

type dnsSocksContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type dnsTimeoutForwardDialer struct {
	timeout time.Duration
}

func (d dnsTimeoutForwardDialer) Dial(network, addr string) (net.Conn, error) {
	t := d.timeout
	if t <= 0 {
		t = 3 * time.Second
	}
	netDialer := &net.Dialer{Timeout: t}
	return netDialer.Dial(network, addr)
}

type dnsUpstreamHealth struct {
	FailCount    int
	BlockedUntil time.Time
	LastError    string
	LastSuccess  time.Time
	LastFailure  time.Time
}

type dnsDoHUpstream struct {
	Name    string
	Addr    string
	Server  string
	URL     string
	Host    string
	Timeout time.Duration
}

func newDNSHijacker(domainMap *dnsDomainMap, socksListen string) *dnsHijacker {
	upstreams := discoverSystemDNSServers()
	if len(upstreams) == 0 {
		upstreams = []string{
			"223.5.5.5:53",
			"1.1.1.1:53",
			"8.8.8.8:53",
		}
	}
	dohUpstreams := defaultDoHUpstreams()
	h := &dnsHijacker{
		domainMap: domainMap,
		upstreams: upstreams,
		doh:       dohUpstreams,
		timeout:   1500 * time.Millisecond,
		openwrt:   runtime.GOOS == "linux" && isOpenWrtRuntime(),
		socks:     strings.TrimSpace(socksListen),
		dialTO:    3 * time.Second,
		health:    make(map[string]*dnsUpstreamHealth, len(upstreams)),
	}
	if h.timeout > h.dialTO {
		h.dialTO = h.timeout
	}
	if h.socks != "" {
		dialer, err := newSocksDialerWithTimeout(h.socks, h.dialTO)
		if err != nil {
			logrus.Warnf("[Client] dns hijack doh socks disabled: %v", err)
		} else {
			h.dialer = dialer
			logrus.Infof("[Client] dns hijack doh socks: %s timeout=%s", h.socks, h.dialTO)
		}
	}
	for _, target := range upstreams {
		h.health[target] = &dnsUpstreamHealth{}
	}
	for _, item := range dohUpstreams {
		h.health[item.Addr] = &dnsUpstreamHealth{}
	}
	logrus.Infoln("[Client] dns hijack upstreams:", strings.Join(h.upstreams, ", "))
	if len(h.doh) > 0 {
		names := make([]string, 0, len(h.doh))
		for _, item := range h.doh {
			names = append(names, item.Name)
		}
		logrus.Infoln("[Client] dns hijack doh:", strings.Join(names, ", "))
	}
	return h
}

func (h *dnsHijacker) Upstreams() []string {
	if h == nil {
		return nil
	}
	out := make([]string, 0, len(h.upstreams)+len(h.doh))
	out = append(out, h.upstreams...)
	for _, item := range h.doh {
		if strings.TrimSpace(item.Addr) == "" {
			continue
		}
		out = append(out, item.Addr)
	}
	return out
}

func (h *dnsHijacker) RouteBypassTargets() []string {
	if h == nil {
		return nil
	}
	// On OpenWrt keep all DNS targets out of bypass list, otherwise dns queries
	// may escape to polluted physical uplink instead of staying in the proxy path.
	if h.openwrt {
		return nil
	}
	return h.Upstreams()
}

func (h *dnsHijacker) Snapshot() (udpQueries, tcpQueries, successes, failures uint64) {
	if h == nil {
		return 0, 0, 0, 0
	}
	return atomic.LoadUint64(&h.udpQueries),
		atomic.LoadUint64(&h.tcpQueries),
		atomic.LoadUint64(&h.successes),
		atomic.LoadUint64(&h.failures)
}

func (h *dnsHijacker) logProgressMaybe() {
	if h == nil {
		return
	}
	udp, tcp, okCount, failCount := h.Snapshot()
	total := udp + tcp
	if total == 0 || total%50 != 0 {
		return
	}
	logrus.Infof("[Client] dns hijack stats: total=%d udp=%d tcp=%d success=%d failure=%d", total, udp, tcp, okCount, failCount)
}

func (h *dnsHijacker) HandlePacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	if h == nil || conn == nil {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		buffer := buf.NewPacket()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		request := append([]byte(nil), buffer.Bytes()...)
		buffer.Release()
		if len(request) == 0 {
			continue
		}
		atomic.AddUint64(&h.udpQueries, 1)
		target := destination
		if !target.IsValid() {
			target = metadata.Destination
		}
		response, err := h.exchange(ctx, target, request)
		if err != nil {
			atomic.AddUint64(&h.failures, 1)
			logrus.Warnln("[Client] dns hijack exchange failed:", err)
			h.logProgressMaybe()
			continue
		}
		atomic.AddUint64(&h.successes, 1)
		h.logProgressMaybe()
		h.captureResponse(response)
		out := buf.NewSize(len(response))
		_, _ = out.Write(response)
		if err := conn.WritePacket(out, target); err != nil {
			out.Release()
			return err
		}
		out.Release()
	}
}

func (h *dnsHijacker) HandleConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if h == nil || conn == nil {
		return nil
	}
	var lenBuf [2]byte
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Minute))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen <= 0 || msgLen > 65535 {
			return errors.New("invalid dns tcp message length")
		}

		request := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, request); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		atomic.AddUint64(&h.tcpQueries, 1)

		response, err := h.exchangeTCP(ctx, metadata.Destination, request)
		if err != nil {
			atomic.AddUint64(&h.failures, 1)
			logrus.Warnln("[Client] dns hijack tcp exchange failed:", err)
			h.logProgressMaybe()
			return err
		}
		atomic.AddUint64(&h.successes, 1)
		h.logProgressMaybe()
		h.captureResponse(response)
		if len(response) > 65535 {
			return errors.New("dns tcp response too large")
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(response)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := conn.Write(response); err != nil {
			return err
		}
	}
}

func (h *dnsHijacker) exchange(ctx context.Context, destination M.Socksaddr, request []byte) ([]byte, error) {
	queryDomain, queryType := extractDNSQueryMeta(request)
	if h.shouldReplyEmptyAAAA(queryDomain, queryType) {
		h.logAAAABypassMaybe(queryDomain)
		return buildEmptyDNSNoAnswerResponse(request)
	}
	dohOnly := h.shouldUseDoHOnly(queryDomain)

	var lastErr error
	if len(h.doh) > 0 {
		resp, err := h.exchangeDoH(ctx, request)
		if err == nil {
			if blocked := h.responseBlockedIPCount(resp); blocked == 0 {
				return resp, nil
			}
			lastErr = fmt.Errorf("doh response contains quarantined ip answer")
		} else {
			lastErr = err
		}
	}
	if dohOnly {
		if lastErr == nil {
			lastErr = errors.New("public domain dns requires doh upstream")
		}
		return nil, lastErr
	}

	targets := h.buildTargets(destination)
	for _, target := range targets {
		if h.isUpstreamBlocked(target, time.Now()) {
			continue
		}
		// Prefer TCP to reduce UDP-based DNS poisoning/interception on some networks.
		startAt := time.Now()
		resp, err := h.exchangeSingleTCP(ctx, target, request)
		if err == nil {
			if blocked := h.responseBlockedIPCount(resp); blocked > 0 {
				rejectErr := fmt.Errorf("dns response contains %d quarantined ip answer(s)", blocked)
				h.markUpstreamFailure(target, rejectErr, startAt)
				lastErr = rejectErr
				continue
			}
			h.markUpstreamSuccess(target, startAt)
			return resp, nil
		}
		h.markUpstreamFailure(target, err, startAt)
		udpStart := time.Now()
		resp, err = h.exchangeSingle(ctx, target, request)
		if err == nil {
			if blocked := h.responseBlockedIPCount(resp); blocked > 0 {
				rejectErr := fmt.Errorf("dns response contains %d quarantined ip answer(s)", blocked)
				h.markUpstreamFailure(target, rejectErr, udpStart)
				lastErr = rejectErr
				continue
			}
			h.markUpstreamSuccess(target, udpStart)
			return resp, nil
		}
		h.markUpstreamFailure(target, err, udpStart)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no dns upstream available")
	}
	return nil, lastErr
}

func (h *dnsHijacker) exchangeTCP(ctx context.Context, destination M.Socksaddr, request []byte) ([]byte, error) {
	queryDomain, queryType := extractDNSQueryMeta(request)
	if h.shouldReplyEmptyAAAA(queryDomain, queryType) {
		h.logAAAABypassMaybe(queryDomain)
		return buildEmptyDNSNoAnswerResponse(request)
	}
	dohOnly := h.shouldUseDoHOnly(queryDomain)

	var lastErr error
	if len(h.doh) > 0 {
		resp, err := h.exchangeDoH(ctx, request)
		if err == nil {
			if blocked := h.responseBlockedIPCount(resp); blocked == 0 {
				return resp, nil
			}
			lastErr = fmt.Errorf("doh response contains quarantined ip answer")
		} else {
			lastErr = err
		}
	}
	if dohOnly {
		if lastErr == nil {
			lastErr = errors.New("public domain dns requires doh upstream")
		}
		return nil, lastErr
	}

	targets := h.buildTargets(destination)
	for _, target := range targets {
		if h.isUpstreamBlocked(target, time.Now()) {
			continue
		}
		startAt := time.Now()
		resp, err := h.exchangeSingleTCP(ctx, target, request)
		if err == nil {
			if blocked := h.responseBlockedIPCount(resp); blocked > 0 {
				rejectErr := fmt.Errorf("dns response contains %d quarantined ip answer(s)", blocked)
				h.markUpstreamFailure(target, rejectErr, startAt)
				lastErr = rejectErr
				continue
			}
			h.markUpstreamSuccess(target, startAt)
			return resp, nil
		}
		h.markUpstreamFailure(target, err, startAt)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no dns upstream available")
	}
	return nil, lastErr
}

func (h *dnsHijacker) buildTargets(destination M.Socksaddr) []string {
	targets := make([]string, 0, len(h.upstreams)+1)
	if destination.IsValid() && destination.Port == 53 {
		dest := destination.String()
		if host, _, err := net.SplitHostPort(dest); err == nil {
			if !isLoopbackOrUnspecifiedHost(host) {
				targets = append(targets, dest)
			}
		} else {
			// Keep legacy behavior when host:port parse fails unexpectedly.
			targets = append(targets, dest)
		}
	}
	targets = append(targets, h.upstreams...)
	targets = dedupStringList(targets)
	return h.prioritizeTargets(targets)
}

func (h *dnsHijacker) exchangeSingle(ctx context.Context, target string, request []byte) ([]byte, error) {
	timeout := h.timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	upCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(upCtx, "udp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	bufResp := make([]byte, 4096)
	n, err := conn.Read(bufResp)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), bufResp[:n]...), nil
}

func (h *dnsHijacker) exchangeSingleTCP(ctx context.Context, target string, request []byte) ([]byte, error) {
	timeout := h.timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	upCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(upCtx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var lenBuf [2]byte
	if len(request) > 65535 {
		return nil, errors.New("dns request too large")
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(request)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen <= 0 || respLen > 65535 {
		return nil, errors.New("invalid dns tcp response length")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *dnsHijacker) exchangeDoH(ctx context.Context, request []byte) ([]byte, error) {
	var lastErr error
	blockedTargets := make([]dnsDoHUpstream, 0, len(h.doh))
	attempted := false
	for _, item := range h.doh {
		if strings.TrimSpace(item.Addr) == "" || strings.TrimSpace(item.Server) == "" || strings.TrimSpace(item.URL) == "" {
			continue
		}
		if h.isUpstreamBlocked(item.Addr, time.Now()) {
			blockedTargets = append(blockedTargets, item)
			continue
		}
		attempted = true
		startAt := time.Now()
		resp, err := h.exchangeSingleDoH(ctx, item, request)
		if err == nil {
			h.markUpstreamSuccess(item.Addr, startAt)
			return resp, nil
		}
		h.markUpstreamFailure(item.Addr, err, startAt)
		lastErr = err
	}
	if !attempted && len(blockedTargets) > 0 {
		logrus.Warnf("[Client] dns doh upstreams are all blocked, force probing blocked targets: %d", len(blockedTargets))
		for _, item := range blockedTargets {
			startAt := time.Now()
			resp, err := h.exchangeSingleDoH(ctx, item, request)
			if err == nil {
				h.markUpstreamSuccess(item.Addr, startAt)
				return resp, nil
			}
			h.markUpstreamFailure(item.Addr, err, startAt)
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no doh upstream available")
	}
	return nil, lastErr
}

func (h *dnsHijacker) exchangeSingleDoH(ctx context.Context, upstream dnsDoHUpstream, request []byte) ([]byte, error) {
	timeout := upstream.Timeout
	if timeout <= 0 {
		timeout = h.timeout * 2
		if timeout < 2*time.Second {
			timeout = 2 * time.Second
		}
	}
	upCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return h.dialDoHUpstream(ctx, timeout, upstream.Addr)
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: upstream.Server,
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout + 1500*time.Millisecond,
	}
	req, err := http.NewRequestWithContext(upCtx, http.MethodPost, upstream.URL, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	if host := strings.TrimSpace(upstream.Host); host != "" {
		req.Host = host
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "anytls-dns-hijack/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(body) == 0 {
			return nil, fmt.Errorf("doh http status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("doh http status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty doh response")
	}
	return raw, nil
}

func (h *dnsHijacker) dialDoHUpstream(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
	var socksErr error
	if h != nil && h.openwrt && h.dialer != nil {
		conn, err := h.dialDoHViaSocks(ctx, timeout, addr)
		if err == nil {
			return conn, nil
		}
		socksErr = err
	}

	directDialer := net.Dialer{Timeout: timeout}
	conn, err := directDialer.DialContext(ctx, "tcp", addr)
	if err == nil {
		if socksErr != nil {
			logrus.Warnf("[Client] dns doh fallback to direct: target=%s error=%v", addr, socksErr)
		}
		return conn, nil
	}
	if socksErr != nil {
		return nil, fmt.Errorf("socks dial failed: %v; direct dial failed: %w", socksErr, err)
	}
	return nil, err
}

func (h *dnsHijacker) dialDoHViaSocks(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
	if h == nil || h.dialer == nil {
		return nil, errors.New("socks dialer unavailable")
	}
	if d, ok := h.dialer.(dnsSocksContextDialer); ok {
		return d.DialContext(ctx, "tcp", addr)
	}
	dialer := h.dialer
	if strings.TrimSpace(h.socks) != "" {
		effectiveTimeout := timeout
		if effectiveTimeout <= 0 {
			effectiveTimeout = h.dialTO
		}
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining > 0 && remaining < effectiveTimeout {
				effectiveTimeout = remaining
			}
		}
		if effectiveTimeout <= 0 {
			effectiveTimeout = h.dialTO
		}
		if rebuilt, err := newSocksDialerWithTimeout(h.socks, effectiveTimeout); err == nil {
			dialer = rebuilt
		}
	}
	return dialer.Dial("tcp", addr)
}

func newSocksDialerWithTimeout(socksAddr string, timeout time.Duration) (xproxy.Dialer, error) {
	addr := strings.TrimSpace(socksAddr)
	if addr == "" {
		return nil, errors.New("empty socks address")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return xproxy.SOCKS5("tcp", addr, nil, dnsTimeoutForwardDialer{timeout: timeout})
}

func (h *dnsHijacker) captureResponse(response []byte) {
	if h == nil || h.domainMap == nil || len(response) == 0 {
		return
	}
	records, err := parseDNSAnswerRecords(response)
	if err != nil || len(records) == 0 {
		return
	}
	for _, record := range records {
		ips, blocked := h.domainMap.FilterBlockedDomainIPs(record.Domain, record.IPs)
		if blocked > 0 {
			logrus.Warnf("[Client] dns hijack filtered quarantined answers: domain=%s blocked=%d", record.Domain, blocked)
		}
		if len(ips) == 0 {
			continue
		}
		h.domainMap.Record(record.Domain, ips, record.TTL)
	}
}

func (h *dnsHijacker) responseBlockedIPCount(response []byte) int {
	if h == nil || h.domainMap == nil || len(response) == 0 {
		return 0
	}
	records, err := parseDNSAnswerRecords(response)
	if err != nil || len(records) == 0 {
		return 0
	}
	blocked := 0
	for _, record := range records {
		blocked += h.domainMap.CountBlockedDomainIPs(record.Domain, record.IPs)
	}
	return blocked
}

type dnsAnswerRecord struct {
	Domain string
	IPs    []netip.Addr
	TTL    time.Duration
}

func parseDNSAnswerRecords(raw []byte) ([]dnsAnswerRecord, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(raw)
	if err != nil {
		return nil, err
	}
	if !header.Response {
		return nil, nil
	}
	questionDomains := make([]string, 0, 4)
	for {
		question, err := parser.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		domain := normalizeDNSName(question.Name.String())
		if domain != "" {
			questionDomains = append(questionDomains, domain)
		}
	}
	type item struct {
		ips []netip.Addr
		ttl uint32
	}
	byDomain := make(map[string]*item)
	for {
		ah, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		domain := normalizeDNSName(ah.Name.String())
		if domain == "" {
			domain = firstString(questionDomains)
		}
		if domain == "" {
			if err := parser.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		cur := byDomain[domain]
		if cur == nil {
			cur = &item{ttl: ah.TTL}
			byDomain[domain] = cur
		}
		if ah.TTL < cur.ttl {
			cur.ttl = ah.TTL
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			resource, err := parser.AResource()
			if err != nil {
				return nil, err
			}
			cur.ips = append(cur.ips, netip.AddrFrom4(resource.A))
		case dnsmessage.TypeAAAA:
			resource, err := parser.AAAAResource()
			if err != nil {
				return nil, err
			}
			cur.ips = append(cur.ips, netip.AddrFrom16(resource.AAAA))
		default:
			if err := parser.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
	for domain, data := range byDomain {
		seen := map[string]struct{}{}
		unique := make([]netip.Addr, 0, len(data.ips))
		for _, ip := range data.ips {
			key := ip.Unmap().String()
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			unique = append(unique, ip.Unmap())
		}
		data.ips = unique
		if len(data.ips) == 0 {
			delete(byDomain, domain)
		}
	}
	if len(byDomain) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(byDomain))
	for domain := range byDomain {
		keys = append(keys, domain)
	}
	sort.Strings(keys)
	out := make([]dnsAnswerRecord, 0, len(keys))
	for _, domain := range keys {
		item := byDomain[domain]
		ttl := time.Duration(item.ttl) * time.Second
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		out = append(out, dnsAnswerRecord{
			Domain: domain,
			IPs:    item.ips,
			TTL:    ttl,
		})
	}
	return out, nil
}

func normalizeDNSName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return normalizeHost(name)
}

func firstString(items []string) string {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			return item
		}
	}
	return ""
}

func extractDNSQueryMeta(raw []byte) (string, dnsmessage.Type) {
	if len(raw) == 0 {
		return "", 0
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		return "", 0
	}
	question, err := parser.Question()
	if err != nil {
		return "", 0
	}
	return normalizeDNSName(question.Name.String()), question.Type
}

func buildEmptyDNSNoAnswerResponse(request []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(request)
	if err != nil {
		return nil, err
	}
	questions := make([]dnsmessage.Question, 0, 1)
	for {
		question, qErr := parser.Question()
		if qErr == dnsmessage.ErrSectionDone {
			break
		}
		if qErr != nil {
			return nil, qErr
		}
		questions = append(questions, question)
	}

	respHeader := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		OpCode:             header.OpCode,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	}
	builder := dnsmessage.NewBuilder(nil, respHeader)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	for _, question := range questions {
		if err := builder.Question(question); err != nil {
			return nil, err
		}
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if err := builder.StartAuthorities(); err != nil {
		return nil, err
	}
	if err := builder.StartAdditionals(); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func (h *dnsHijacker) shouldReplyEmptyAAAA(domain string, queryType dnsmessage.Type) bool {
	if h == nil || !h.openwrt {
		return false
	}
	if queryType != dnsmessage.TypeAAAA {
		return false
	}
	// Keep local/private domains untouched; for public domains on OpenWrt,
	// suppress AAAA to avoid unstable IPv6 path causing TLS EOF.
	return h.shouldUseDoHOnly(domain)
}

func (h *dnsHijacker) logAAAABypassMaybe(domain string) {
	if h == nil {
		return
	}
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.lastAAAA.IsZero() && now.Sub(h.lastAAAA) < 30*time.Second {
		return
	}
	h.lastAAAA = now
	if domain == "" {
		logrus.Debugln("[Client] dns hijack openwrt: suppress AAAA for public domain query")
		return
	}
	logrus.Debugf("[Client] dns hijack openwrt: suppress AAAA for domain %s", domain)
}

func (h *dnsHijacker) shouldUseDoHOnly(domain string) bool {
	if h == nil {
		return false
	}
	if !h.openwrt {
		return false
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return false
	}
	if strings.HasSuffix(domain, ".local") ||
		strings.HasSuffix(domain, ".lan") ||
		strings.HasSuffix(domain, ".home.arpa") ||
		strings.HasSuffix(domain, ".in-addr.arpa") ||
		strings.HasSuffix(domain, ".ip6.arpa") {
		return false
	}
	// Keep domestic/private suffixes on plain DNS fallback to reduce breakage.
	if strings.HasSuffix(domain, ".cn") {
		return false
	}
	return true
}

func dedupStringList(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func (h *dnsHijacker) prioritizeTargets(targets []string) []string {
	if h == nil || len(targets) <= 1 {
		return targets
	}
	now := time.Now()
	out := append([]string(nil), targets...)
	sort.SliceStable(out, func(i, j int) bool {
		aBlocked := h.isUpstreamBlocked(out[i], now)
		bBlocked := h.isUpstreamBlocked(out[j], now)
		if aBlocked != bBlocked {
			return !aBlocked && bBlocked
		}
		aFail := h.getUpstreamFailCount(out[i])
		bFail := h.getUpstreamFailCount(out[j])
		if aFail != bFail {
			return aFail < bFail
		}
		return false
	})
	return out
}

func (h *dnsHijacker) ensureUpstreamHealthLocked(target string) *dnsUpstreamHealth {
	if h.health == nil {
		h.health = make(map[string]*dnsUpstreamHealth, len(h.upstreams))
	}
	info := h.health[target]
	if info == nil {
		info = &dnsUpstreamHealth{}
		h.health[target] = info
	}
	return info
}

func (h *dnsHijacker) isUpstreamBlocked(target string, now time.Time) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	info := h.ensureUpstreamHealthLocked(target)
	return !info.BlockedUntil.IsZero() && info.BlockedUntil.After(now)
}

func (h *dnsHijacker) getUpstreamFailCount(target string) int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	info := h.ensureUpstreamHealthLocked(target)
	return info.FailCount
}

func (h *dnsHijacker) markUpstreamSuccess(target string, _ time.Time) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	info := h.ensureUpstreamHealthLocked(target)
	wasBlocked := !info.BlockedUntil.IsZero() && info.BlockedUntil.After(time.Now())
	info.FailCount = 0
	info.BlockedUntil = time.Time{}
	info.LastError = ""
	info.LastSuccess = time.Now()
	if wasBlocked {
		logrus.Infof("[Client] dns upstream recovered: %s", target)
	}
}

func (h *dnsHijacker) markUpstreamFailure(target string, err error, _ time.Time) {
	if h == nil || err == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	info := h.ensureUpstreamHealthLocked(target)
	info.FailCount++
	info.LastFailure = time.Now()
	info.LastError = err.Error()
	if isDNSTimeoutLikeError(err) && info.FailCount >= 2 {
		blockFor := 90 * time.Second
		if h.openwrt {
			// OpenWrt path tends to flap under node switch; reduce penalty window to improve recovery speed.
			blockFor = 45 * time.Second
		}
		until := time.Now().Add(blockFor)
		alreadyBlocked := !info.BlockedUntil.IsZero() && info.BlockedUntil.After(time.Now())
		info.BlockedUntil = until
		if !alreadyBlocked {
			logrus.Warnf("[Client] dns upstream blocked for %s due to repeated timeout: %s", blockFor, target)
		}
	}
}

func (h *dnsHijacker) ResetUpstreamHealth(reason string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	reset := 0
	for target, info := range h.health {
		if info == nil {
			continue
		}
		wasBlocked := !info.BlockedUntil.IsZero() && info.BlockedUntil.After(time.Now())
		wasFailed := info.FailCount > 0
		if !wasBlocked && !wasFailed && strings.TrimSpace(info.LastError) == "" {
			continue
		}
		info.FailCount = 0
		info.BlockedUntil = time.Time{}
		info.LastError = ""
		if info.LastSuccess.IsZero() {
			info.LastSuccess = time.Now()
		}
		h.health[target] = info
		reset++
	}
	if reset == 0 {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "manual"
	}
	logrus.Infof("[Client] dns upstream health reset (%s): %d target(s)", reason, reset)
}

func isDNSTimeoutLikeError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "i/o timeout") ||
		strings.Contains(text, "deadline exceeded") ||
		strings.Contains(text, "context deadline exceeded")
}

func defaultDoHUpstreams() []dnsDoHUpstream {
	return []dnsDoHUpstream{
		{
			Name:    "cloudflare",
			Addr:    "1.1.1.1:443",
			Server:  "cloudflare-dns.com",
			Host:    "cloudflare-dns.com",
			URL:     "https://cloudflare-dns.com/dns-query",
			Timeout: 2500 * time.Millisecond,
		},
		{
			Name:    "google",
			Addr:    "8.8.8.8:443",
			Server:  "dns.google",
			Host:    "dns.google",
			URL:     "https://dns.google/dns-query",
			Timeout: 2500 * time.Millisecond,
		},
		{
			Name:    "quad9",
			Addr:    "9.9.9.9:443",
			Server:  "dns.quad9.net",
			Host:    "dns.quad9.net",
			URL:     "https://dns.quad9.net/dns-query",
			Timeout: 2500 * time.Millisecond,
		},
	}
}

func discoverSystemDNSServers() []string {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	lines := strings.Split(string(raw), "\n")
	out := make([]string, 0, 4)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		host := strings.TrimSpace(fields[1])
		if host == "" {
			continue
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		// Avoid self-recursive local resolvers in hijack path (127.0.0.1 / ::1 / 0.0.0.0 / ::).
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		out = append(out, net.JoinHostPort(host, "53"))
	}
	return dedupStringList(out)
}

func isLoopbackOrUnspecifiedHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}
