package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
)

const (
	defaultLatencyTarget      = "1.1.1.1:443"
	defaultBandwidthURL       = "https://speed.cloudflare.com/__down?bytes=5000000"
	defaultLatencyTimeoutMS   = 2000
	maxLatencyTimeoutMS       = 2000
	defaultBandwidthTimeoutMS = 20000
	maxBandwidthTimeoutMS     = 120000
	minBandwidthTimeoutMS     = 200
	defaultLatencyCount       = 3
	defaultBandwidthBytes     = 5 * 1024 * 1024
	minBandwidthBytes         = 256 * 1024
	maxBandwidthBytes         = 200 * 1024 * 1024
	maxLatencyProbeSamples    = 10
	defaultBrowserProbeURL    = "https://ip.sb"
	defaultBrowserTimeoutMS   = 12000
	minBrowserTimeoutMS       = 1000
	maxBrowserTimeoutMS       = 45000
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
		timeoutMS = defaultLatencyTimeoutMS
	}
	if timeoutMS > maxLatencyTimeoutMS {
		timeoutMS = maxLatencyTimeoutMS
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
		timeoutMS = defaultBandwidthTimeoutMS
	}
	if timeoutMS < minBandwidthTimeoutMS {
		timeoutMS = minBandwidthTimeoutMS
	}
	if timeoutMS > maxBandwidthTimeoutMS {
		timeoutMS = maxBandwidthTimeoutMS
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

func (s *apiState) handleTestBrowserAvailability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.maybeHandleAsyncTask(w, r, "test_browser", http.MethodPost, "/api/v1/test/browser", req, s.handleTestBrowserAvailability) {
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		targetURL = defaultBrowserProbeURL
	}
	parsed, err := neturl.Parse(targetURL)
	if err != nil || parsed == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid url: %q", targetURL))
		return
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	host := strings.TrimSpace(parsed.Hostname())
	if (scheme != "http" && scheme != "https") || host == "" {
		writeError(w, http.StatusBadRequest, "url must be http(s) with valid host")
		return
	}

	timeoutMS := req.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultBrowserTimeoutMS
	}
	if timeoutMS < minBrowserTimeoutMS {
		timeoutMS = minBrowserTimeoutMS
	}
	if timeoutMS > maxBrowserTimeoutMS {
		timeoutMS = maxBrowserTimeoutMS
	}
	timeoutSec := timeoutMS / 1000
	if timeoutMS%1000 != 0 {
		timeoutSec++
	}
	if timeoutSec <= 0 {
		timeoutSec = 1
	}

	currentNode := ""
	if s.manager != nil {
		currentNode = strings.TrimSpace(s.manager.CurrentNodeName())
	}
	if currentNode == "" {
		s.lock.Lock()
		if s.cfg != nil {
			currentNode = strings.TrimSpace(s.cfg.DefaultNode)
		}
		s.lock.Unlock()
	}

	nodeName := strings.TrimSpace(req.Name)
	stepRows := make([]map[string]any, 0, 24)
	traceStep := func(step, detail string) {
		item := map[string]any{
			"time":   time.Now().Format(time.RFC3339),
			"step":   strings.TrimSpace(step),
			"detail": strings.TrimSpace(detail),
		}
		stepRows = append(stepRows, item)
		logrus.Infof("[Client] browser probe: step=%s detail=%s", item["step"], item["detail"])
	}
	traceStep("start", fmt.Sprintf("url=%s timeout_ms=%d current=%s node=%s", targetURL, timeoutMS, currentNode, nodeName))

	// Node-forced mode: test the selected node directly so each row button can test itself.
	if nodeName != "" {
		traceStep("mode", "node_forced")
		startAt := time.Now()
		nodeProbeRes, nodeProbeErr := s.runTunHTTPSProbeViaNode(nodeName, []string{targetURL}, time.Duration(timeoutMS)*time.Millisecond)
		durationMS := time.Since(startAt).Milliseconds()
		ok := false
		if summary, okSummary := nodeProbeRes["summary"].(map[string]any); okSummary {
			ok = anyToBool(summary["ok"])
		}
		resp := map[string]any{
			"ok":              ok && nodeProbeErr == nil,
			"url":             targetURL,
			"host":            host,
			"timeout_ms":      timeoutMS,
			"duration_ms":     durationMS,
			"current":         currentNode,
			"node":            nodeName,
			"mode":            "node_forced",
			"time":            time.Now().Format(time.RFC3339),
			"steps":           stepRows,
			"auto_dns_repair": map[string]any{"attempted": false, "reason": "node_forced_mode"},
		}
		if nodeProbeRes != nil {
			resp["node_probe"] = nodeProbeRes
		}
		if nodeProbeErr != nil || !ok {
			errText := ""
			if nodeProbeErr != nil {
				errText = strings.TrimSpace(nodeProbeErr.Error())
			} else {
				errText = "node probe failed"
			}
			if row := firstBrowserNodeProbeRow(nodeProbeRes); len(row) > 0 {
				if rowErr := strings.TrimSpace(anyToString(row["error"])); rowErr != "" {
					errText = rowErr
				}
			}
			resp["ok"] = false
			resp["error"] = errText
			resp["error_type"] = classifyBrowserProbeErrorType(errText)
			traceStep("finish", fmt.Sprintf("ok=false duration_ms=%d error=%s", durationMS, errText))
		} else {
			traceStep("finish", fmt.Sprintf("ok=true duration_ms=%d", durationMS))
			preview, statusCode, previewErr := s.fetchNodeBrowserPreview(nodeName, targetURL, time.Duration(timeoutMS)*time.Millisecond)
			if previewErr != nil {
				resp["response_fetch_error"] = previewErr.Error()
				traceStep("result_fetch", fmt.Sprintf("ok=false error=%v", previewErr))
			} else {
				resp["response_preview"] = preview
				resp["response_status_code"] = statusCode
				traceStep("result_fetch", fmt.Sprintf("ok=true status_code=%d preview_len=%d", statusCode, len(preview)))
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	openwrtMode := runtime.GOOS == "linux" && isOpenWrtRuntime()

	startAt := time.Now()
	probeErr := runSystemCurlProbeCommandWithTrace(targetURL, timeoutSec, openwrtMode, traceStep)
	durationMS := time.Since(startAt).Milliseconds()
	errorType := ""
	if probeErr != nil {
		errorType = classifyBrowserProbeErrorType(strings.TrimSpace(probeErr.Error()))
		traceStep("finish", fmt.Sprintf("ok=false duration_ms=%d error=%v", durationMS, probeErr))
	} else {
		traceStep("finish", fmt.Sprintf("ok=true duration_ms=%d", durationMS))
	}
	autoRepair := map[string]any{
		"attempted": false,
	}
	var dnsProbeRes map[string]any
	var resolvedFallbackRes map[string]any
	if probeErr != nil && errorType == "dns_path_unstable" {
		traceStep("dns_probe_start", fmt.Sprintf("host=%s", host))
		dnsProbe, dnsProbeErr := s.runTunDNSResolutionProbe([]string{host}, browserDNSProbeServers(), 3*time.Second)
		if dnsProbe != nil {
			dnsProbeRes = dnsProbe
			autoRepair["dns_probe"] = dnsProbe
			for _, row := range browserDNSProbeRows(dnsProbe) {
				server := strings.TrimSpace(anyToString(row["dns_server"]))
				durationMS := anyToInt(row["duration_ms"])
				if anyToBool(row["ok"]) {
					traceStep("dns_probe_row", fmt.Sprintf("server=%s ok=true duration_ms=%d", server, durationMS))
				} else {
					traceStep("dns_probe_row", fmt.Sprintf("server=%s ok=false duration_ms=%d error=%s", server, durationMS, strings.TrimSpace(anyToString(row["error"]))))
				}
			}
		}
		if dnsProbeErr != nil {
			traceStep("dns_probe_result", fmt.Sprintf("ok=false error=%v", dnsProbeErr))
		} else {
			traceStep("dns_probe_result", "ok=true")
		}
		resolvedIPs := selectResolvedProbeIPsFromDNSProbe(dnsProbeRes)
		if len(resolvedIPs) > 0 && strings.EqualFold(scheme, "https") {
			traceStep("resolved_fallback_start", fmt.Sprintf("ips=%s", strings.Join(resolvedIPs, ",")))
			resolvedProbeStart := time.Now()
			resolvedProbe, resolvedErr := runHTTPSProbeViaResolvedIPs(targetURL, host, resolvedIPs, minDuration(time.Duration(timeoutMS)*time.Millisecond, 8*time.Second))
			resolvedFallbackRes = map[string]any{
				"url":          targetURL,
				"host":         host,
				"resolved_ips": append([]string(nil), resolvedIPs...),
				"duration_ms":  time.Since(resolvedProbeStart).Milliseconds(),
			}
			if resolvedErr != nil {
				resolvedFallbackRes["ok"] = false
				resolvedFallbackRes["error"] = resolvedErr.Error()
				if isHostnameMismatchError(resolvedErr) {
					resolvedFallbackRes["error_type"] = "hostname_mismatch"
				}
				traceStep("resolved_fallback_result", fmt.Sprintf("ok=false error=%v", resolvedErr))
			} else {
				resolvedFallbackRes["ok"] = true
				resolvedFallbackRes["status_code"] = resolvedProbe.StatusCode
				if strings.TrimSpace(resolvedProbe.UsedIP) != "" {
					resolvedFallbackRes["resolved_ip"] = strings.TrimSpace(resolvedProbe.UsedIP)
				}
				if strings.TrimSpace(resolvedProbe.CertSubject) != "" {
					resolvedFallbackRes["cert_subject"] = strings.TrimSpace(resolvedProbe.CertSubject)
				}
				if len(resolvedProbe.CertDNSNames) > 0 {
					resolvedFallbackRes["cert_dns_names"] = append([]string(nil), resolvedProbe.CertDNSNames...)
				}
				traceStep("resolved_fallback_result", fmt.Sprintf("ok=true status_code=%d", resolvedProbe.StatusCode))
			}
		}
		if runtime.GOOS == "darwin" {
			autoRepair["attempted"] = true
			autoRepair["platform"] = "darwin"
			repairServers := selectDarwinRepairDNSServersFromProbe(dnsProbeRes)
			if len(repairServers) == 0 {
				repairServers = defaultDarwinManagedDNSServers()
			}
			autoRepair["target_dns_servers"] = append([]string(nil), repairServers...)
			traceStep("auto_dns_repair_start", fmt.Sprintf("enforce darwin system dns servers=%s and flush cache", strings.Join(repairServers, ",")))
			_, changed, repErr := enforceDarwinSystemDNS(repairServers)
			autoRepair["config_changed"] = changed > 0
			if repErr != nil {
				autoRepair["ok"] = false
				autoRepair["error"] = repErr.Error()
				traceStep("auto_dns_repair_result", fmt.Sprintf("ok=false changed=%d error=%v", changed, repErr))
			} else {
				autoRepair["ok"] = true
				traceStep("auto_dns_repair_result", fmt.Sprintf("ok=true changed=%d", changed))
				flushDarwinDNSCache()
				traceStep("auto_dns_repair_retry", fmt.Sprintf("retry url=%s", targetURL))
				retryStart := time.Now()
				retryErr := runSystemCurlProbeCommandWithTrace(targetURL, timeoutSec, openwrtMode, traceStep)
				retryDurationMS := time.Since(retryStart).Milliseconds()
				autoRepair["retry_duration_ms"] = retryDurationMS
				if retryErr != nil {
					autoRepair["retry_ok"] = false
					autoRepair["retry_error"] = retryErr.Error()
					traceStep("auto_dns_repair_retry_result", fmt.Sprintf("ok=false duration_ms=%d error=%v", retryDurationMS, retryErr))
					probeErr = retryErr
					errorType = classifyBrowserProbeErrorType(strings.TrimSpace(retryErr.Error()))
				} else {
					autoRepair["retry_ok"] = true
					traceStep("auto_dns_repair_retry_result", fmt.Sprintf("ok=true duration_ms=%d", retryDurationMS))
					probeErr = nil
					errorType = ""
				}
			}
		}
	}

	resp := map[string]any{
		"ok":              probeErr == nil,
		"url":             targetURL,
		"host":            host,
		"timeout_ms":      timeoutMS,
		"duration_ms":     durationMS,
		"current":         currentNode,
		"time":            time.Now().Format(time.RFC3339),
		"steps":           stepRows,
		"auto_dns_repair": autoRepair,
	}
	if probeErr == nil {
		preview, statusCode, previewErr := runSystemCurlFetchPreview(targetURL, timeoutSec)
		if previewErr != nil {
			resp["response_fetch_error"] = previewErr.Error()
			traceStep("result_fetch", fmt.Sprintf("ok=false error=%v", previewErr))
		} else {
			resp["response_preview"] = preview
			resp["response_status_code"] = statusCode
			traceStep("result_fetch", fmt.Sprintf("ok=true status_code=%d preview_len=%d", statusCode, len(preview)))
		}
	}
	if dnsProbeRes != nil {
		resp["dns_probe"] = dnsProbeRes
	}
	if resolvedFallbackRes != nil {
		resp["resolved_fallback"] = resolvedFallbackRes
	}
	if probeErr != nil {
		errText := strings.TrimSpace(probeErr.Error())
		resp["error"] = errText
		resp["error_type"] = errorType
		if resolvedFallbackRes != nil && anyToBool(resolvedFallbackRes["ok"]) {
			resp["hint"] = "system dns path is broken, but resolved fallback is reachable; browser likely fails due to local dns"
		}
	}
	writeJSON(w, http.StatusOK, resp)
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
			result.Error = enrichEgressIPProbeError(probeErr.Error(), node)
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
		result.Error = enrichEgressIPProbeError(err.Error(), node)
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

func enrichEgressIPProbeError(errText string, node clientNodeConfig) string {
	errText = strings.TrimSpace(errText)
	if errText == "" {
		return ""
	}
	lowerErr := strings.ToLower(errText)
	if node.EgressIP == "" {
		return errText
	}
	if strings.Contains(lowerErr, "egress-ip is not local") || strings.Contains(lowerErr, "invalid egress-ip") {
		return fmt.Sprintf("%s (hint: node egress_ip=%s is not usable on server; clear egress_ip or set a server-local source IP)", errText, node.EgressIP)
	}
	return errText
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

func classifyBrowserProbeErrorType(errText string) string {
	lower := strings.ToLower(strings.TrimSpace(errText))
	if lower == "" {
		return ""
	}
	if isHostnameMismatchErrorText(lower) {
		return "hostname_mismatch"
	}
	if strings.Contains(lower, "could not resolve host") ||
		strings.Contains(lower, "resolving timed out") ||
		strings.Contains(lower, "system dns path failed") ||
		strings.Contains(lower, "name or service not known") {
		return "dns_path_unstable"
	}
	if strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "timeout") {
		return "timeout"
	}
	return "probe_failed"
}

func browserDNSProbeServers() []string {
	return []string{
		"127.0.0.1:53",
		"223.5.5.5:53",
		"119.29.29.29:53",
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
	}
}

func browserDNSProbeRows(res map[string]any) []map[string]any {
	if len(res) == 0 {
		return nil
	}
	if rows, ok := res["results"].([]map[string]any); ok {
		return rows
	}
	rawRows, ok := res["results"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(rawRows))
	for _, item := range rawRows {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, row)
	}
	return out
}

func firstBrowserNodeProbeRow(res map[string]any) map[string]any {
	if len(res) == 0 {
		return nil
	}
	if rows, ok := res["results"].([]map[string]any); ok {
		if len(rows) > 0 {
			return rows[0]
		}
		return nil
	}
	rawRows, ok := res["results"].([]any)
	if !ok || len(rawRows) == 0 {
		return nil
	}
	row, _ := rawRows[0].(map[string]any)
	return row
}

func selectDarwinRepairDNSServersFromProbe(res map[string]any) []string {
	type candidate struct {
		Server     string
		DurationMS int
	}
	rows := browserDNSProbeRows(res)
	if len(rows) == 0 {
		return nil
	}
	candidates := make([]candidate, 0, len(rows))
	for _, row := range rows {
		if !anyToBool(row["ok"]) {
			continue
		}
		server := strings.TrimSpace(anyToString(row["dns_server"]))
		if server == "" {
			continue
		}
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			host = server
		}
		host = strings.TrimSpace(strings.Trim(host, "[]"))
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			continue
		}
		candidates = append(candidates, candidate{
			Server:     host,
			DurationMS: anyToInt(row["duration_ms"]),
		})
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].DurationMS != candidates[j].DurationMS {
			return candidates[i].DurationMS < candidates[j].DurationMS
		}
		return candidates[i].Server < candidates[j].Server
	})
	out := make([]string, 0, 4)
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		key := strings.ToLower(strings.TrimSpace(c.Server))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c.Server)
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func selectResolvedProbeIPsFromDNSProbe(res map[string]any) []string {
	rows := browserDNSProbeRows(res)
	if len(rows) == 0 {
		return nil
	}
	out := make([]string, 0, 8)
	seen := make(map[string]struct{}, 16)
	appendIP := func(raw string) {
		ipText := strings.TrimSpace(strings.Trim(raw, "[]"))
		if ipText == "" {
			return
		}
		ip := net.ParseIP(ipText)
		if ip == nil {
			return
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	for _, row := range rows {
		if !anyToBool(row["ok"]) {
			continue
		}
		if rawIPs, ok := row["ips"].([]string); ok {
			for _, ip := range rawIPs {
				appendIP(ip)
			}
		} else if rawAny, ok := row["ips"].([]any); ok {
			for _, cell := range rawAny {
				appendIP(anyToString(cell))
			}
		}
		if len(out) >= 6 {
			break
		}
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func anyToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return fmt.Sprintf("%v", v)
	}
}

func anyToInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	case float32:
		return int(x)
	default:
		return 0
	}
}

func anyToBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		text := strings.ToLower(strings.TrimSpace(x))
		return text == "1" || text == "true" || text == "yes" || text == "on"
	default:
		return false
	}
}

func (s *apiState) fetchNodeBrowserPreview(nodeName, targetURL string, timeout time.Duration) (string, int, error) {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return "", 0, fmt.Errorf("empty node name")
	}
	if s.manager == nil {
		return "", 0, fmt.Errorf("runtime manager not initialized")
	}
	client, err := s.manager.ClientForNode(nodeName)
	if err != nil {
		return "", 0, err
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
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
	reqCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return sanitizeBrowserPreview(string(body)), resp.StatusCode, nil
}

func runSystemCurlFetchPreview(targetURL string, timeoutSec int) (string, int, error) {
	if !commandExists("curl") {
		return "", 0, fmt.Errorf("curl not found")
	}
	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	if timeoutSec > 30 {
		timeoutSec = 30
	}
	connectSec := timeoutSec
	if connectSec > 4 {
		connectSec = 4
	}
	args := []string{
		"-q",
		"-sS",
		"--proxy", "",
		"--noproxy", "*",
		"--max-time", strconv.Itoa(timeoutSec),
		"--connect-timeout", strconv.Itoa(connectSec),
		"-L",
		"-w", "\n__ANYTLS_STATUS__:%{http_code}",
		targetURL,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+2)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "curl", args...)
	cmd.Env = append(os.Environ(),
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"ALL_PROXY=",
		"NO_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"all_proxy=",
		"no_proxy=",
	)
	output, err := cmd.CombinedOutput()
	text := string(output)
	if ctx.Err() == context.DeadlineExceeded {
		return "", 0, fmt.Errorf("curl fetch timeout after %ds", timeoutSec)
	}
	if err != nil {
		return "", 0, fmt.Errorf("curl fetch failed: %w: %s", err, strings.TrimSpace(text))
	}
	body, statusCode := parseSystemCurlPreviewOutput(text)
	return sanitizeBrowserPreview(body), statusCode, nil
}

func parseSystemCurlPreviewOutput(output string) (string, int) {
	output = strings.TrimSpace(output)
	if output == "" {
		return "", 0
	}
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return output, 0
	}
	last := strings.TrimSpace(lines[len(lines)-1])
	const prefix = "__ANYTLS_STATUS__:"
	if !strings.HasPrefix(last, prefix) {
		return output, 0
	}
	statusText := strings.TrimSpace(strings.TrimPrefix(last, prefix))
	statusCode, _ := strconv.Atoi(statusText)
	body := strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
	return body, statusCode
}

func sanitizeBrowserPreview(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return ""
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	runes := []rune(text)
	if len(runes) > 600 {
		runes = runes[:600]
		text = string(runes) + "..."
	}
	return strings.TrimSpace(text)
}
