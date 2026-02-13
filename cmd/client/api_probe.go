package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	defaultLatencyTarget   = "1.1.1.1:443"
	defaultBandwidthURL    = "https://speed.cloudflare.com/__down?bytes=5000000"
	defaultProbeTimeoutMS  = 2000
	maxProbeTimeoutMS      = 2000
	defaultLatencyCount    = 3
	defaultBandwidthBytes  = 5 * 1024 * 1024
	minBandwidthBytes      = 256 * 1024
	maxBandwidthBytes      = 200 * 1024 * 1024
	maxLatencyProbeSamples = 10
)

type latencyProbeResult struct {
	Name      string    `json:"name"`
	Target    string    `json:"target"`
	Count     int       `json:"count"`
	Success   int       `json:"success"`
	AvgMS     float64   `json:"avg_ms,omitempty"`
	MinMS     float64   `json:"min_ms,omitempty"`
	MaxMS     float64   `json:"max_ms,omitempty"`
	SamplesMS []float64 `json:"samples_ms,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type bandwidthProbeResult struct {
	Name       string  `json:"name"`
	URL        string  `json:"url"`
	Bytes      int64   `json:"bytes,omitempty"`
	DurationMS int64   `json:"duration_ms,omitempty"`
	Mbps       float64 `json:"mbps,omitempty"`
	Error      string  `json:"error,omitempty"`
}

func (s *apiState) handleTestLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Name      string   `json:"name"`
		Names     []string `json:"names"`
		Target    string   `json:"target"`
		Count     int      `json:"count"`
		TimeoutMS int      `json:"timeout_ms"`
	}
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.maybeHandleAsyncTask(w, r, "test_latency", http.MethodPost, "/api/v1/test/latency", req, s.handleTestLatency) {
		return
	}

	target, err := normalizeProbeTarget(req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	count := req.Count
	if count <= 0 {
		count = defaultLatencyCount
	}
	if count > maxLatencyProbeSamples {
		count = maxLatencyProbeSamples
	}

	timeoutMS := req.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultProbeTimeoutMS
	}
	if timeoutMS > maxProbeTimeoutMS {
		timeoutMS = maxProbeTimeoutMS
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond

	nodes, minIdle, err := s.resolveProbeNodes(req.Name, req.Names)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	results := make([]latencyProbeResult, 0, len(nodes))
	for _, node := range nodes {
		results = append(results, measureNodeLatency(node, target, count, timeout, minIdle))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target":  target,
		"count":   count,
		"results": results,
	})
}

func (s *apiState) handleTestBandwidth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Name      string   `json:"name"`
		Names     []string `json:"names"`
		URL       string   `json:"url"`
		MaxBytes  int64    `json:"max_bytes"`
		TimeoutMS int      `json:"timeout_ms"`
	}
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.maybeHandleAsyncTask(w, r, "test_bandwidth", http.MethodPost, "/api/v1/test/bandwidth", req, s.handleTestBandwidth) {
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		targetURL = defaultBandwidthURL
	}
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		writeError(w, http.StatusBadRequest, "url must start with http:// or https://")
		return
	}

	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultBandwidthBytes
	}
	if maxBytes < minBandwidthBytes {
		maxBytes = minBandwidthBytes
	}
	if maxBytes > maxBandwidthBytes {
		maxBytes = maxBandwidthBytes
	}

	timeoutMS := req.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultProbeTimeoutMS
	}
	if timeoutMS > maxProbeTimeoutMS {
		timeoutMS = maxProbeTimeoutMS
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond

	nodes, minIdle, err := s.resolveProbeNodes(req.Name, req.Names)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	probeURLs := []string{targetURL}

	results := make([]bandwidthProbeResult, 0, len(nodes))
	for _, node := range nodes {
		results = append(results, measureNodeBandwidth(node, probeURLs, maxBytes, timeout, minIdle))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":        targetURL,
		"probe_urls": probeURLs,
		"max_bytes":  maxBytes,
		"results":    results,
	})
}

func (s *apiState) resolveProbeNodes(name string, names []string) ([]clientNodeConfig, int, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	minIdle := s.cfg.MinIdleSession
	if minIdle <= 0 {
		minIdle = 5
	}

	raw := make([]string, 0, len(names)+1)
	if v := strings.TrimSpace(name); v != "" {
		raw = append(raw, v)
	}
	for _, item := range names {
		if v := strings.TrimSpace(item); v != "" {
			raw = append(raw, v)
		}
	}
	if len(raw) == 0 {
		for _, n := range s.cfg.Nodes {
			raw = append(raw, n.Name)
		}
	}
	if len(raw) == 0 {
		return nil, minIdle, fmt.Errorf("no nodes available")
	}

	seen := make(map[string]struct{}, len(raw))
	out := make([]clientNodeConfig, 0, len(raw))
	for _, item := range raw {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		node, ok := findNodeByName(s.cfg.Nodes, item)
		if !ok {
			return nil, minIdle, fmt.Errorf("node not found: %s", item)
		}
		out = append(out, node)
	}
	return out, minIdle, nil
}

func measureNodeLatency(node clientNodeConfig, target string, count int, timeout time.Duration, minIdle int) latencyProbeResult {
	result := latencyProbeResult{
		Name:   node.Name,
		Target: target,
		Count:  count,
	}
	client, err := buildClientFromNode(context.Background(), node, minIdle)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer client.Close()

	destination := M.ParseSocksaddr(target)
	if !destination.IsValid() {
		result.Error = "invalid probe target"
		return result
	}

	samples := make([]float64, 0, count)
	for i := 0; i < count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		start := time.Now()
		conn, probeErr := client.CreateProxy(ctx, destination)
		elapsed := time.Since(start)
		cancel()
		if probeErr != nil {
			result.Error = probeErr.Error()
			continue
		}
		_ = conn.Close()
		ms := float64(elapsed.Microseconds()) / 1000.0
		samples = append(samples, ms)
	}
	result.Success = len(samples)
	if len(samples) == 0 {
		if result.Error == "" {
			result.Error = "all probes failed"
		}
		return result
	}
	result.SamplesMS = samples
	result.MinMS = samples[0]
	result.MaxMS = samples[0]
	sum := 0.0
	for _, item := range samples {
		sum += item
		if item < result.MinMS {
			result.MinMS = item
		}
		if item > result.MaxMS {
			result.MaxMS = item
		}
	}
	result.AvgMS = sum / float64(len(samples))
	return result
}

func measureNodeBandwidth(node clientNodeConfig, probeURLs []string, maxBytes int64, timeout time.Duration, minIdle int) bandwidthProbeResult {
	if len(probeURLs) == 0 {
		probeURLs = []string{defaultBandwidthURL}
	}
	result := bandwidthProbeResult{Name: node.Name, URL: probeURLs[0]}
	last := measureNodeBandwidthOnce(node, probeURLs[0], maxBytes, timeout, minIdle)
	if last.Error == "" {
		return last
	}
	result.Error = fmt.Sprintf("%s: %s", probeURLs[0], last.Error)
	return result
}

func measureNodeBandwidthOnce(node clientNodeConfig, targetURL string, maxBytes int64, timeout time.Duration, minIdle int) bandwidthProbeResult {
	result := bandwidthProbeResult{Name: node.Name, URL: targetURL}

	clientCtx, clientCancel := context.WithTimeout(context.Background(), timeout*2)
	defer clientCancel()
	client, err := buildClientFromNode(clientCtx, node, minIdle)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer client.Close()

	transport := &http.Transport{
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				network = "tcp"
			}
			dest := M.ParseSocksaddr(addr)
			if !dest.IsValid() {
				return nil, fmt.Errorf("invalid destination: %s", addr)
			}
			return client.CreateProxy(ctx, dest)
		},
	}
	defer transport.CloseIdleConnections()

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	reqCtx, reqCancel := context.WithTimeout(context.Background(), timeout)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		result.Error = fmt.Sprintf("http status %d", resp.StatusCode)
		return result
	}

	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		duration := time.Since(start)
		// If we already received enough bytes, keep result instead of hard-failing on close race.
		if n >= minBandwidthBytes && (isClosedConnProbeError(err.Error()) || isTimeoutProbeError(err.Error())) {
			if duration <= 0 {
				duration = time.Millisecond
			}
			result.Bytes = n
			result.DurationMS = duration.Milliseconds()
			result.Mbps = float64(n) * 8 / duration.Seconds() / 1_000_000
			return result
		}
		result.Error = err.Error()
		return result
	}
	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Millisecond
	}
	result.Bytes = n
	result.DurationMS = duration.Milliseconds()
	result.Mbps = float64(n) * 8 / duration.Seconds() / 1_000_000
	return result
}

func isClosedConnProbeError(errText string) bool {
	errText = strings.ToLower(strings.TrimSpace(errText))
	if errText == "" {
		return false
	}
	return strings.Contains(errText, "use of closed network connection") ||
		strings.Contains(errText, io.ErrClosedPipe.Error()) ||
		strings.Contains(errText, net.ErrClosed.Error()) ||
		strings.Contains(errText, context.Canceled.Error()) ||
		strings.Contains(errText, "broken pipe") ||
		strings.Contains(errText, "connection reset by peer")
}

func isTimeoutProbeError(errText string) bool {
	errText = strings.ToLower(strings.TrimSpace(errText))
	if errText == "" {
		return false
	}
	return strings.Contains(errText, context.DeadlineExceeded.Error()) ||
		strings.Contains(errText, "timeout")
}

func normalizeProbeTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		target = defaultLatencyTarget
	}
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target, nil
	}
	if strings.Count(target, ":") > 1 {
		return "", fmt.Errorf("invalid target %q: IPv6 host must include port", target)
	}
	return net.JoinHostPort(target, "443"), nil
}
