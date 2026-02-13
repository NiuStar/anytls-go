package main

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type routingMatchRequest struct {
	Target      string `json:"target"`
	Network     string `json:"network"`
	DefaultNode string `json:"default_node"`
	Record      *bool  `json:"record"`
}

type routingEgressProbeRequest struct {
	Target    string `json:"target"`
	TimeoutMS int    `json:"timeout_ms"`
}

func (s *apiState) handleRoutingMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req routingMatchRequest
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	destination, err := parseRoutingMatchTarget(req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	network := strings.ToLower(strings.TrimSpace(req.Network))
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "udp" {
		writeError(w, http.StatusBadRequest, "network must be tcp or udp")
		return
	}

	record := true
	if req.Record != nil {
		record = *req.Record
	}

	s.lock.Lock()
	engine := s.routing
	defaultNode := s.manager.CurrentNodeName()
	dnsMap := s.dnsMap
	if v := strings.TrimSpace(req.DefaultNode); v != "" {
		if _, ok := findNodeByName(s.cfg.Nodes, v); !ok {
			s.lock.Unlock()
			writeError(w, http.StatusNotFound, "default_node not found")
			return
		}
		defaultNode = v
	}
	store := s.routingHits
	s.lock.Unlock()
	if store == nil {
		s.lock.Lock()
		if s.routingHits == nil {
			s.routingHits = newRoutingHitStore(6000)
		}
		store = s.routingHits
		s.lock.Unlock()
	}

	var hints []string
	var ipHints []netip.Addr
	if dnsMap != nil && destination.IsIP() {
		hints = dnsMap.LookupByIP(destination.Addr.Unmap().String())
	}
	if dnsMap != nil && destination.IsFqdn() {
		ipHints = dnsMap.LookupByDomain(destination.Fqdn)
	}
	decision := decideRoutingWithDomainHintsAndIPHints(engine, destination, defaultNode, hints, ipHints)
	if record && store != nil {
		store.append("test", network, destination, decision, time.Now(), "", hints...)
	}
	action, node := formatRouteDecisionAction(decision.action)
	host := ""
	ip := ""
	if destination.IsFqdn() {
		host = strings.TrimSpace(destination.Fqdn)
	}
	if destination.IsIP() {
		ip = destination.Addr.Unmap().String()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"network":      network,
		"destination":  destination.String(),
		"host":         host,
		"ip":           ip,
		"port":         destination.Port,
		"default_node": defaultNode,
		"action":       action,
		"node":         node,
		"rule":         decision.matchedRule,
		"recorded":     record,
	})
}

func (s *apiState) handleRoutingEgressProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req routingEgressProbeRequest
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	targetURL, parsedURL, destination, err := parseRoutingEgressProbeTarget(req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}
	if timeout < 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}

	s.lock.Lock()
	engine := s.routing
	defaultNode := s.manager.CurrentNodeName()
	dnsMap := s.dnsMap
	s.lock.Unlock()

	var hints []string
	var ipHints []netip.Addr
	if dnsMap != nil && destination.IsIP() {
		hints = dnsMap.LookupByIP(destination.Addr.Unmap().String())
	}
	if dnsMap != nil && destination.IsFqdn() {
		ipHints = dnsMap.LookupByDomain(destination.Fqdn)
	}
	decision := decideRoutingWithDomainHintsAndIPHints(engine, destination, defaultNode, hints, ipHints)
	actionName, nodeName := formatRouteDecisionAction(decision.action)
	result := map[string]any{
		"ok":           false,
		"url":          targetURL,
		"destination":  destination.String(),
		"host":         strings.TrimSpace(parsedURL.Hostname()),
		"time":         time.Now().Format(time.RFC3339),
		"timeout_ms":   timeout.Milliseconds(),
		"default_node": defaultNode,
		"action":       actionName,
		"node":         nodeName,
		"rule":         strings.TrimSpace(decision.matchedRule),
	}
	writeProbeResult := func(payload map[string]any) {
		s.setRoutingEgressProbeLast(payload)
		writeJSON(w, http.StatusOK, payload)
	}

	startAt := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	var conn net.Conn
	switch decision.action.kind {
	case routeActionReject:
		result["error"] = "route rejected"
		result["duration_ms"] = time.Since(startAt).Milliseconds()
		writeProbeResult(result)
		return
	case routeActionDirect:
		targetHostPort := net.JoinHostPort(strings.TrimSpace(parsedURL.Hostname()), parsedURL.Port())
		if strings.TrimSpace(parsedURL.Port()) == "" {
			targetHostPort = net.JoinHostPort(strings.TrimSpace(parsedURL.Hostname()), "443")
		}
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = dialer.DialContext(ctx, "tcp", targetHostPort)
	case routeActionNode:
		client, clientErr := s.manager.ClientForNode(strings.TrimSpace(decision.action.node))
		if clientErr != nil {
			err = clientErr
			break
		}
		conn, err = client.CreateProxy(ctx, destination)
	default:
		err = fmt.Errorf("unsupported route action: %d", decision.action.kind)
	}
	if err != nil {
		result["error"] = err.Error()
		result["duration_ms"] = time.Since(startAt).Milliseconds()
		writeProbeResult(result)
		return
	}
	defer conn.Close()

	requestPath := parsedURL.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	if parsedURL.RawQuery != "" {
		requestPath += "?" + parsedURL.RawQuery
	}
	statusCode, certSubject, certDNSNames, probeErr := runRoutingEgressHTTPSProbe(ctx, conn, strings.TrimSpace(parsedURL.Hostname()), requestPath, timeout)
	result["duration_ms"] = time.Since(startAt).Milliseconds()
	if probeErr != nil {
		result["error"] = probeErr.Error()
		lower := strings.ToLower(probeErr.Error())
		if strings.Contains(lower, "no alternative certificate subject name matches") ||
			strings.Contains(lower, "certificate is valid for") ||
			strings.Contains(lower, "hostname") {
			result["error_type"] = "hostname_mismatch"
		}
		writeProbeResult(result)
		return
	}

	result["ok"] = true
	result["status_code"] = statusCode
	if certSubject != "" {
		result["cert_subject"] = certSubject
	}
	if len(certDNSNames) > 0 {
		result["cert_dns_names"] = certDNSNames
	}
	writeProbeResult(result)
}

func (s *apiState) handleRoutingHits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	sinceID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("since_id")), 10, 64)
	source := strings.TrimSpace(q.Get("source"))
	sourceClient := strings.TrimSpace(q.Get("source_client"))
	network := strings.TrimSpace(q.Get("network"))
	action := strings.TrimSpace(q.Get("action"))
	search := strings.TrimSpace(q.Get("search"))
	node := strings.TrimSpace(q.Get("node"))
	rule := strings.TrimSpace(q.Get("rule"))
	windowSec, _ := strconv.Atoi(strings.TrimSpace(q.Get("window_sec")))

	s.lock.Lock()
	store := s.routingHits
	s.lock.Unlock()
	if store == nil {
		s.lock.Lock()
		if s.routingHits == nil {
			s.routingHits = newRoutingHitStore(6000)
		}
		store = s.routingHits
		s.lock.Unlock()
	}

	items, stats := store.listWithStats(limit, source, sourceClient, network, action, search, node, rule, sinceID, windowSec)
	writeJSON(w, http.StatusOK, map[string]any{
		"items":     items,
		"latest_id": store.latestID(),
		"count":     len(items),
		"stats":     stats,
	})
}

func (s *apiState) handleRoutingHitsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.lock.Lock()
	store := s.routingHits
	s.lock.Unlock()
	if store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
		return
	}
	store.clear()
	writeJSON(w, http.StatusOK, map[string]any{
		"cleared": true,
	})
}

func parseRoutingMatchTarget(raw string) (M.Socksaddr, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return M.Socksaddr{}, fmt.Errorf("target is required")
	}

	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil && strings.TrimSpace(u.Host) != "" {
			target = strings.TrimSpace(u.Host)
		}
	}

	destination := M.ParseSocksaddr(target)
	if destination.IsValid() {
		if destination.Port == 0 {
			destination.Port = 443
		}
		return destination, nil
	}

	if _, _, err := net.SplitHostPort(target); err != nil {
		trimmed := strings.Trim(target, "[]")
		if ip := net.ParseIP(trimmed); ip != nil {
			target = net.JoinHostPort(ip.String(), "443")
		} else {
			if normalized, normalizeErr := normalizeProbeTarget(target); normalizeErr == nil {
				target = normalized
			} else {
				target = net.JoinHostPort(target, "443")
			}
		}
	}

	destination = M.ParseSocksaddr(target)
	if !destination.IsValid() {
		return M.Socksaddr{}, fmt.Errorf("invalid target: %s", strings.TrimSpace(raw))
	}
	if destination.Port == 0 {
		destination.Port = 443
	}
	return destination, nil
}

func parseRoutingEgressProbeTarget(raw string) (string, *url.URL, M.Socksaddr, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		target = "https://www.google.com/generate_204"
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", nil, M.Socksaddr{}, fmt.Errorf("invalid target: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(parsed.Scheme), "https") {
		return "", nil, M.Socksaddr{}, fmt.Errorf("target must be https url")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", nil, M.Socksaddr{}, fmt.Errorf("target host is empty")
	}
	port := 443
	if p := strings.TrimSpace(parsed.Port()); p != "" {
		value, convErr := strconv.Atoi(p)
		if convErr != nil || value <= 0 || value > 65535 {
			return "", nil, M.Socksaddr{}, fmt.Errorf("invalid target port")
		}
		port = value
	}
	var destination M.Socksaddr
	if ip := net.ParseIP(host); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			destination = M.Socksaddr{
				Addr: addr.Unmap(),
				Port: uint16(port),
			}
		}
	}
	if !destination.IsValid() {
		destination = M.Socksaddr{
			Fqdn: host,
			Port: uint16(port),
		}
	}
	if !destination.IsValid() {
		return "", nil, M.Socksaddr{}, fmt.Errorf("invalid destination")
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), parsed, destination, nil
}

func runRoutingEgressHTTPSProbe(ctx context.Context, conn net.Conn, host, path string, timeout time.Duration) (int, string, []string, error) {
	if conn == nil {
		return 0, "", nil, fmt.Errorf("empty connection")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return 0, "", nil, fmt.Errorf("empty host")
	}
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, "", nil, err
	}
	certSubject := ""
	certDNSNames := []string(nil)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		certSubject = strings.TrimSpace(leaf.Subject.CommonName)
		if len(leaf.DNSNames) > 0 {
			limit := len(leaf.DNSNames)
			if limit > 8 {
				limit = 8
			}
			certDNSNames = append([]string(nil), leaf.DNSNames[:limit]...)
		}
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: anytls-egress-probe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host)
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return 0, certSubject, certDNSNames, err
	}
	reader := std_bufio.NewReader(tlsConn)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	resp, err := http.ReadResponse(reader, httpReq)
	if err != nil {
		return 0, certSubject, certDNSNames, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, certSubject, certDNSNames, nil
}
