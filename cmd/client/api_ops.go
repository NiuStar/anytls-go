package main

import (
	"anytls/util"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type diagnoseCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Error   string `json:"error,omitempty"`
	Latency int64  `json:"latency_ms,omitempty"`
}

func (s *apiState) handleRouteSelfHeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.lock.Lock()
	cfg := *s.cfg
	cfg.Nodes = append([]clientNodeConfig(nil), s.cfg.Nodes...)
	tunRunning := s.tun != nil
	nodeBypass := s.nodeBypass
	s.lock.Unlock()
	s.routeSelfHealMu.Lock()
	events := append([]routeSelfHealEvent(nil), s.routeSelfHealEvents...)
	s.routeSelfHealMu.Unlock()

	tunEnabled := cfg.Tun != nil && cfg.Tun.Enabled
	tunAutoRoute := cfg.Tun != nil && cfg.Tun.AutoRoute
	tunName := ""
	if cfg.Tun != nil {
		tunName = normalizeTunDeviceNameForOS(runtime.GOOS, strings.TrimSpace(cfg.Tun.Name))
	}
	if tunName == "" {
		tunName = "anytls0"
	}

	recent := make([]routeSelfHealEvent, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		recent = append(recent, events[i])
		if len(recent) >= 60 {
			break
		}
	}

	routeInfo := map[string]any{
		"default_v4": map[string]any{
			"output": "",
			"error":  "",
			"device": "",
			"via":    "",
			"ok":     false,
		},
		"split_v4": map[string]any{
			"route_0_1": map[string]any{
				"present": false,
				"on_tun":  false,
				"output":  "",
				"error":   "",
			},
			"route_128_1": map[string]any{
				"present": false,
				"on_tun":  false,
				"output":  "",
				"error":   "",
			},
		},
	}

	issues := make([]string, 0, 6)
	appendIssue := func(msg string) {
		msg = strings.TrimSpace(msg)
		if msg == "" {
			return
		}
		issues = append(issues, msg)
	}

	if runtime.GOOS == "linux" {
		defaultMap := routeInfo["default_v4"].(map[string]any)
		out, err := runCommand("ip", "-4", "route", "show", "default")
		if err != nil {
			defaultMap["error"] = err.Error()
			appendIssue("读取默认 IPv4 路由失败")
		} else {
			defaultMap["output"] = out
			spec, via, dev, ok := parseLinuxDefaultRouteOutput(out)
			defaultMap["ok"] = ok
			defaultMap["device"] = dev
			defaultMap["via"] = via
			defaultMap["spec"] = spec
			if !ok {
				appendIssue("默认 IPv4 路由无法解析")
			}
			if tunRunning && strings.TrimSpace(dev) == strings.TrimSpace(tunName) {
				appendIssue(fmt.Sprintf("默认路由仍指向 TUN(%s)，存在断网风险", tunName))
			}
		}

		splitMap := routeInfo["split_v4"].(map[string]any)
		checkSplit := func(key, cidr string) {
			entry := splitMap[key].(map[string]any)
			out, err := runCommand("ip", "-4", "route", "show", cidr)
			if err != nil {
				entry["error"] = err.Error()
				return
			}
			entry["output"] = out
			present := strings.TrimSpace(out) != ""
			entry["present"] = present
			entry["on_tun"] = present && strings.Contains(" "+out+" ", " dev "+tunName+" ")
		}
		checkSplit("route_0_1", "0.0.0.0/1")
		checkSplit("route_128_1", "128.0.0.0/1")

		if tunRunning && tunAutoRoute {
			r01 := splitMap["route_0_1"].(map[string]any)
			r128 := splitMap["route_128_1"].(map[string]any)
			if !r01["present"].(bool) || !r01["on_tun"].(bool) {
				appendIssue("分片路由 0.0.0.0/1 未正确指向 TUN")
			}
			if !r128["present"].(bool) || !r128["on_tun"].(bool) {
				appendIssue("分片路由 128.0.0.0/1 未正确指向 TUN")
			}
		}
	}

	if tunEnabled && !tunRunning {
		appendIssue("配置启用了 TUN，但运行时未启动")
	}
	if tunRunning && nodeBypass.Failed > 0 {
		appendIssue(fmt.Sprintf("节点旁路存在失败目标: %d", nodeBypass.Failed))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"time": time.Now().Format(time.RFC3339),
		"os":   runtime.GOOS,
		"arch": runtime.GOARCH,
		"tun": map[string]any{
			"enabled":    tunEnabled,
			"running":    tunRunning,
			"auto_route": tunAutoRoute,
			"name":       tunName,
		},
		"bypass": map[string]any{
			"node_total":      nodeBypass.Total,
			"node_success":    nodeBypass.Success,
			"node_failed":     nodeBypass.Failed,
			"node_skipped":    nodeBypass.Skipped,
			"failed_targets":  nodeBypass.FailedTargets,
			"skipped_targets": nodeBypass.SkippedTargets,
			"updated_at":      nodeBypass.UpdatedAt,
		},
		"route": routeInfo,
		"self_heal": map[string]any{
			"recent": recent,
			"count":  len(events),
		},
		"health": map[string]any{
			"ok":     len(issues) == 0,
			"issues": issues,
		},
	})
}

func (s *apiState) handleRouteCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.lock.Lock()
	cfg := *s.cfg
	cfg.Nodes = append([]clientNodeConfig(nil), s.cfg.Nodes...)
	current := s.manager.CurrentNodeName()
	tunRunning := s.tun != nil
	s.lock.Unlock()

	node, ok := findNodeByName(cfg.Nodes, current)
	if !ok {
		writeError(w, http.StatusBadRequest, "current node not found")
		return
	}

	serverHost, err := resolveTargetHost(node.Server)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("parse server host failed: %v", err))
		return
	}

	tunEnabled := cfg.Tun != nil && cfg.Tun.Enabled
	tunAutoRoute := cfg.Tun != nil && cfg.Tun.AutoRoute
	tunName := ""
	if cfg.Tun != nil {
		tunName = normalizeTunDeviceNameForOS(runtime.GOOS, strings.TrimSpace(cfg.Tun.Name))
	}

	check := map[string]any{
		"ok":        false,
		"risk_loop": false,
		"advice":    []string{},
	}
	appendAdvice := func(text string) {
		if strings.TrimSpace(text) == "" {
			return
		}
		list := check["advice"].([]string)
		list = append(list, text)
		check["advice"] = list
	}

	switch runtime.GOOS {
	case "darwin":
		cmd := fmt.Sprintf("route -n get %s", serverHost)
		check["command"] = cmd
		output, routeErr := runCommand("route", "-n", "get", serverHost)
		check["raw"] = output
		if routeErr != nil {
			check["error"] = routeErr.Error()
			appendAdvice("未能读取路由信息，请确认已授权并重试。")
			break
		}
		gateway, iface := parseDarwinRouteGetOutput(output)
		check["gateway"] = gateway
		check["interface"] = iface
		if strings.TrimSpace(iface) == "" {
			check["error"] = "cannot parse interface from route output"
			appendAdvice("路由输出里没有 interface 字段，请检查系统路由表。")
			break
		}

		loop := strings.HasPrefix(strings.ToLower(iface), "utun")
		check["risk_loop"] = loop
		if loop {
			appendAdvice(fmt.Sprintf("当前到服务端的路由走了 %s，存在 TUN 回环风险。", iface))
			appendAdvice("请先关闭其它代理/VPN，再重新开启 AnyTLS 的 TUN。")
		}
		if tunEnabled && !tunRunning {
			appendAdvice("配置启用了 TUN，但运行时未启动，请先启动 TUN。")
		}
		if tunRunning && tunAutoRoute && !loop {
			check["ok"] = true
		}
		if tunRunning && !tunAutoRoute && !loop {
			check["ok"] = true
			appendAdvice("当前未启用 auto_route；如果要全局接管，请开启自动路由。")
		}
		if !tunRunning && !loop {
			check["ok"] = true
		}
	case "linux":
		target, family, resolveErr := routeProbeTarget(serverHost)
		if resolveErr != nil {
			check["error"] = resolveErr.Error()
			appendAdvice("服务端域名解析失败，请检查 DNS。")
			break
		}
		check["target_ip"] = target
		if family == "ipv6" {
			check["command"] = fmt.Sprintf("ip -6 route get %s", target)
			output, routeErr := runCommand("ip", "-6", "route", "get", target)
			check["raw"] = output
			if routeErr != nil {
				check["error"] = routeErr.Error()
				appendAdvice("未能读取 IPv6 路由信息，请检查系统路由工具。")
				break
			}
			via, dev, src := parseLinuxRouteGetOutput(output)
			check["gateway"] = via
			check["interface"] = dev
			check["source"] = src
			if strings.TrimSpace(dev) == "" {
				check["error"] = "cannot parse interface from route output"
				appendAdvice("路由输出里没有 dev 字段，请检查系统路由表。")
				break
			}
			loop := strings.TrimSpace(tunName) != "" && dev == tunName
			check["risk_loop"] = loop
			if loop {
				appendAdvice(fmt.Sprintf("当前到服务端的路由走了 %s，存在 TUN 回环风险。", dev))
			}
			check["ok"] = !loop
		} else {
			check["command"] = fmt.Sprintf("ip -4 route get %s", target)
			output, routeErr := runCommand("ip", "-4", "route", "get", target)
			check["raw"] = output
			if routeErr != nil {
				check["error"] = routeErr.Error()
				appendAdvice("未能读取 IPv4 路由信息，请检查系统路由工具。")
				break
			}
			via, dev, src := parseLinuxRouteGetOutput(output)
			check["gateway"] = via
			check["interface"] = dev
			check["source"] = src
			if strings.TrimSpace(dev) == "" {
				check["error"] = "cannot parse interface from route output"
				appendAdvice("路由输出里没有 dev 字段，请检查系统路由表。")
				break
			}
			loop := strings.TrimSpace(tunName) != "" && dev == tunName
			check["risk_loop"] = loop
			if loop {
				appendAdvice(fmt.Sprintf("当前到服务端的路由走了 %s，存在 TUN 回环风险。", dev))
			}
			check["ok"] = !loop
		}
	default:
		check["error"] = fmt.Sprintf("route self-check is not implemented on %s", runtime.GOOS)
		appendAdvice("当前平台暂不支持自动路由自检，请手动检查系统路由。")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"time":        time.Now().Format(time.RFC3339),
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"current":     current,
		"server":      node.Server,
		"server_host": serverHost,
		"tun": map[string]any{
			"enabled":    tunEnabled,
			"running":    tunRunning,
			"auto_route": tunAutoRoute,
			"name":       tunName,
		},
		"check": check,
	})
}

func routeProbeTarget(host string) (target string, family string, err error) {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip != nil {
		if ip.To4() != nil {
			return ip.String(), "ipv4", nil
		}
		return ip.String(), "ipv6", nil
	}

	ips, err := lookupIPsWithTimeout(host, routeResolveTimeout)
	if err != nil {
		return "", "", fmt.Errorf("resolve %s failed: %w", host, err)
	}
	for _, item := range ips {
		if item == nil {
			continue
		}
		if item.To4() != nil {
			return item.String(), "ipv4", nil
		}
	}
	for _, item := range ips {
		if item == nil {
			continue
		}
		return item.String(), "ipv6", nil
	}
	return "", "", fmt.Errorf("resolve %s returned no ip", host)
}

func parseLinuxRouteGetOutput(output string) (via string, dev string, src string) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				via = fields[i+1]
			case "dev":
				dev = fields[i+1]
			case "src":
				src = fields[i+1]
			}
		}
		if dev != "" || via != "" || src != "" {
			return via, dev, src
		}
	}
	return "", "", ""
}

func (s *apiState) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.lock.Lock()
	cfg := *s.cfg
	cfg.Nodes = append([]clientNodeConfig(nil), s.cfg.Nodes...)
	current := s.manager.CurrentNodeName()
	tunEnabled := cfg.Tun != nil && cfg.Tun.Enabled
	tunRunning := s.tun != nil
	tunAutoRecoverRunning := s.tunAutoRecoverRunning
	tunAutoRecoverState := s.tunAutoRecoverState
	tunAutoRecoverSuspend := s.tunAutoRecoverSuspend
	tunAutoRecoverReason := s.tunAutoRecoverReason
	mitmEnabled := cfg.MITM != nil && cfg.MITM.Enabled
	mitmRunning := s.mitm != nil
	mitmDoHDoTEnabled := cfg.MITM != nil && cfg.MITM.DoHDoT != nil && cfg.MITM.DoHDoT.Enabled
	mitmDoHHostCount := 0
	mitmDoTHostCount := 0
	if cfg.MITM != nil && cfg.MITM.DoHDoT != nil {
		mitmDoHHostCount = len(cfg.MITM.DoHDoT.DoHHosts)
		mitmDoTHostCount = len(cfg.MITM.DoHDoT.DoTHosts)
	}
	mitmListen := ""
	mitmHostCount := 0
	mitmURLRejectCount := 0
	mitmURLRejectHitCount := uint64(0)
	mitmURLRejectLastHitAt := ""
	mitmURLRejectLastURL := ""
	mitmURLRejectLastRule := ""
	mitmURLRejectTopRules := make([]map[string]any, 0)
	if s.mitm != nil {
		mitmListen = s.mitm.ListenAddr()
		mitmHostCount = s.mitm.HostCount()
		mitmURLRejectCount = s.mitm.URLRejectCount()
		hitCount, lastAt, lastURL, lastRule, topRules := s.mitm.URLRejectStats()
		mitmURLRejectHitCount = hitCount
		if !lastAt.IsZero() {
			mitmURLRejectLastHitAt = lastAt.Format(time.RFC3339)
		}
		mitmURLRejectLastURL = lastURL
		mitmURLRejectLastRule = lastRule
		for _, item := range topRules {
			lastHitAt := ""
			if !item.LastAt.IsZero() {
				lastHitAt = item.LastAt.Format(time.RFC3339)
			}
			mitmURLRejectTopRules = append(mitmURLRejectTopRules, map[string]any{
				"rule":        item.Rule,
				"hits":        item.Hits,
				"last_hit_at": lastHitAt,
			})
		}
	}
	failoverEnabled := cfg.Failover != nil && cfg.Failover.Enabled
	failoverBestLatencyEnabled := cfg.Failover != nil && cfg.Failover.BestLatencyEnabled
	routingEnabled := cfg.Routing != nil && cfg.Routing.Enabled
	routingRuleCount := 0
	routingProviderCount := 0
	dnsMapIPCount := 0
	dnsMapMappingCount := 0
	dnsUpstreamCount := 0
	dnsQueriesUDP := uint64(0)
	dnsQueriesTCP := uint64(0)
	dnsQuerySuccess := uint64(0)
	dnsQueryFailure := uint64(0)
	nodeBypass := s.nodeBypass
	routingHitStore := s.routingHits
	egressProbeLast := s.getRoutingEgressProbeLastLocked()
	if cfg.Routing != nil {
		routingRuleCount = len(cfg.Routing.Rules)
		routingProviderCount = len(cfg.Routing.RuleProviders)
	}
	if s.dnsMap != nil {
		dnsMapIPCount, dnsMapMappingCount = s.dnsMap.Stats()
	}
	if s.dnsHijacker != nil {
		dnsUpstreamCount = len(s.dnsHijacker.Upstreams())
		dnsQueriesUDP, dnsQueriesTCP, dnsQuerySuccess, dnsQueryFailure = s.dnsHijacker.Snapshot()
	}
	started := s.startedAt
	configPath := s.configPath
	activeListen := s.activeListen
	activeControl := s.activeControl
	s.lock.Unlock()

	uptime := int64(0)
	if !started.IsZero() {
		uptime = int64(time.Since(started).Seconds())
	}
	openwrtRuntime := runtime.GOOS == "linux" && isOpenWrtRuntime()

	recentRoutingNode := ""
	recentRoutingAction := ""
	recentRoutingRule := ""
	recentRoutingTime := ""
	recentRoutingDestination := ""
	recentRoutingNetwork := ""
	recentRoutingSource := ""
	if routingHitStore != nil {
		if items := routingHitStore.list(1, "live", "", "", "", "", "", "", 0, 0); len(items) > 0 {
			item := items[0]
			recentRoutingNode = strings.TrimSpace(item.Node)
			recentRoutingAction = strings.ToUpper(strings.TrimSpace(item.Action))
			recentRoutingRule = strings.TrimSpace(item.Rule)
			recentRoutingTime = item.Time
			recentRoutingDestination = strings.TrimSpace(item.Destination)
			recentRoutingNetwork = strings.ToLower(strings.TrimSpace(item.Network))
			recentRoutingSource = strings.ToLower(strings.TrimSpace(item.Source))
		}
	}

	issues := make([]string, 0, 4)
	if strings.TrimSpace(current) == "" {
		issues = append(issues, "current node is empty")
	} else if _, ok := findNodeByName(cfg.Nodes, current); !ok {
		issues = append(issues, "current node not found in config")
	}
	if strings.TrimSpace(cfg.DefaultNode) == "" {
		issues = append(issues, "default node is empty")
	} else if _, ok := findNodeByName(cfg.Nodes, cfg.DefaultNode); !ok {
		issues = append(issues, "default node not found in config")
	}
	if tunEnabled && !tunRunning {
		issues = append(issues, "tun enabled in config but runtime not running")
	}
	if !tunEnabled && tunRunning {
		issues = append(issues, "tun runtime running but config disabled")
	}
	if mitmEnabled && !mitmRunning {
		issues = append(issues, "mitm enabled in config but runtime not running")
	}
	if !mitmEnabled && mitmRunning {
		issues = append(issues, "mitm runtime running but config disabled")
	}

	failoverStatus := map[string]any{
		"enabled":              failoverEnabled,
		"best_latency_enabled": failoverBestLatencyEnabled,
	}
	for k, v := range failoverRuntimeStatsSnapshot() {
		failoverStatus[k] = v
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":        util.VersionName(),
		"commit":         util.CommitID(),
		"build_time":     util.BuildTime(),
		"build_info":     util.BuildInfo(),
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"openwrt":        openwrtRuntime,
		"pid":            os.Getpid(),
		"started_at":     started.Format(time.RFC3339),
		"uptime_sec":     uptime,
		"config_path":    configPath,
		"active_listen":  activeListen,
		"active_control": activeControl,
		"current":        current,
		"default":        cfg.DefaultNode,
		"node_count":     len(cfg.Nodes),
		"tun": map[string]any{
			"enabled":                    tunEnabled,
			"running":                    tunRunning,
			"auto_recover_running":       tunAutoRecoverRunning,
			"auto_recover_suspended":     tunAutoRecoverSuspend,
			"auto_recover_suspend_cause": tunAutoRecoverReason,
			"auto_recover_last_attempt":  tunAutoRecoverState.LastAttemptAt,
			"auto_recover_last_success":  tunAutoRecoverState.LastSuccessAt,
			"auto_recover_last_error":    tunAutoRecoverState.LastError,
		},
		"mitm": map[string]any{
			"enabled":                  mitmEnabled,
			"running":                  mitmRunning,
			"listen":                   mitmListen,
			"host_count":               mitmHostCount,
			"url_reject_count":         mitmURLRejectCount,
			"url_reject_hit_count":     mitmURLRejectHitCount,
			"url_reject_last_hit_at":   mitmURLRejectLastHitAt,
			"url_reject_last_hit_url":  mitmURLRejectLastURL,
			"url_reject_last_hit_rule": mitmURLRejectLastRule,
			"url_reject_top_rules":     mitmURLRejectTopRules,
			"doh_dot_enabled":          mitmDoHDoTEnabled,
			"doh_host_count":           mitmDoHHostCount,
			"dot_host_count":           mitmDoTHostCount,
		},
		"failover": failoverStatus,
		"routing": map[string]any{
			"enabled":             routingEnabled,
			"rule_count":          routingRuleCount,
			"provider_count":      routingProviderCount,
			"dns_map_ip_count":    dnsMapIPCount,
			"dns_map_match_count": dnsMapMappingCount,
			"dns_upstream_count":  dnsUpstreamCount,
			"dns_queries_udp":     dnsQueriesUDP,
			"dns_queries_tcp":     dnsQueriesTCP,
			"dns_query_success":   dnsQuerySuccess,
			"dns_query_failure":   dnsQueryFailure,
			"recent_node":         recentRoutingNode,
			"recent_action":       recentRoutingAction,
			"recent_rule":         recentRoutingRule,
			"recent_time":         recentRoutingTime,
			"recent_destination":  recentRoutingDestination,
			"recent_network":      recentRoutingNetwork,
			"recent_source":       recentRoutingSource,
			"egress_probe_last":   egressProbeLast,
		},
		"bypass": map[string]any{
			"node_total":      nodeBypass.Total,
			"node_success":    nodeBypass.Success,
			"node_failed":     nodeBypass.Failed,
			"node_skipped":    nodeBypass.Skipped,
			"failed_targets":  nodeBypass.FailedTargets,
			"skipped_targets": nodeBypass.SkippedTargets,
			"updated_at":      nodeBypass.UpdatedAt,
		},
		"inbound": inboundRuntimeStatsSnapshot(),
		"health": map[string]any{
			"ok":     len(issues) == 0,
			"issues": issues,
		},
	})
}

func (s *apiState) handleMITMCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	caPEM, err := s.loadMITMCAPEM()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="anytls-mitm-ca.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(caPEM)
}

func (s *apiState) handleMITMCAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	caPEM, err := s.loadMITMCAPEM()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	status, err := detectMITMCAInstallStatus(caPEM)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *apiState) handleMITMCAInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	caPEM, err := s.loadMITMCAPEM()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	mode, location, installMsg, err := autoInstallMITMCA(caPEM)
	if err != nil {
		msg := strings.TrimSpace(err.Error())
		code := http.StatusInternalServerError
		if isPermissionLikeError(err) {
			code = http.StatusForbidden
			if msg == "" {
				msg = "permission denied"
			}
			msg += " (请使用 root/管理员权限运行 anytls-client 后重试，或使用“复制安装 CA 命令”)"
		}
		writeError(w, code, msg)
		return
	}

	status, derr := detectMITMCAInstallStatus(caPEM)
	if derr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"mode":     mode,
			"location": location,
			"message":  installMsg,
		})
		return
	}

	resp := map[string]any{
		"ok":       true,
		"mode":     mode,
		"location": location,
		"message":  installMsg,
		"status":   status,
	}
	if installed, _ := status["installed"].(bool); !installed {
		resp["warning"] = "安装步骤已执行，但未检测到系统证书库生效，请稍后重试或手动检查"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *apiState) handleMITMCAInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	caPEM, err := s.loadMITMCAPEM()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	script := buildMITMCAInstallShellScript(caPEM)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="anytls-install-mitm-ca.sh"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, script)
}

func (s *apiState) handleOpenWrtDNSRepair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if runtime.GOOS != "linux" || !isOpenWrtRuntime() {
		writeError(w, http.StatusBadRequest, "openwrt dns repair is only supported on openwrt")
		return
	}

	targetDomains := []string{
		"raw.githubusercontent.com",
		"githubusercontent.com",
		"github.com",
		"www.google.com",
	}
	rep := repairOpenWrtDNSDomains(targetDomains)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                rep.OK,
		"time":              rep.Time,
		"openwrt":           true,
		"domains":           rep.Domains,
		"address_removed":   rep.AddressRemoved,
		"address_patterns":  rep.AddressPatterns,
		"server_removed":    rep.ServerRemoved,
		"server_patterns":   rep.ServerPatterns,
		"server_reset":      rep.ServerReset,
		"server_upstreams":  rep.ServerUpstreams,
		"options_forced":    rep.OptionsForced,
		"uci_committed":     rep.UCICommitted,
		"hosts_removed":     rep.HostsRemoved,
		"config_changed":    rep.ConfigChanged,
		"dnsmasq_restarted": rep.DNSMasqRestarted,
		"issues":            rep.Issues,
		"message":           rep.Message,
	})
}

type openwrtDNSRepairResult struct {
	OK               bool
	Time             string
	Domains          []string
	AddressRemoved   int
	AddressPatterns  []string
	ServerRemoved    int
	ServerPatterns   []string
	ServerReset      bool
	ServerUpstreams  []string
	OptionsForced    map[string]string
	UCICommitted     bool
	HostsRemoved     int
	ConfigChanged    bool
	DNSMasqRestarted bool
	Issues           []string
	Message          string
}

func repairOpenWrtDNSDomains(targetDomains []string) openwrtDNSRepairResult {
	defaultUpstreams := []string{
		"1.1.1.1",
		"8.8.8.8",
		"9.9.9.9",
		"208.67.222.222",
	}
	blockTargets := []string{"0.0.0.0", "::"}
	removedAddress := make([]string, 0, len(targetDomains)*len(blockTargets))
	addressRemovedCount := 0
	removedServer := make([]string, 0, 8)
	serverRemovedCount := 0
	serverReset := false
	forcedOptions := make(map[string]string)
	lookupIssues := make([]string, 0)
	deleteIssues := make([]string, 0)
	optionIssues := make([]string, 0)
	addServerIssues := make([]string, 0)
	targetSet := make(map[string]struct{}, len(targetDomains))
	for _, domain := range targetDomains {
		dom := strings.TrimSpace(strings.ToLower(domain))
		if dom == "" {
			continue
		}
		targetSet[dom] = struct{}{}
	}
	for _, domain := range targetDomains {
		dom := strings.TrimSpace(strings.ToLower(domain))
		if dom == "" {
			continue
		}
		for _, blocked := range blockTargets {
			pattern := fmt.Sprintf("/%s/%s", dom, blocked)
			expectedDeleteCount, countErr := countDNSMasqAddressEntries(pattern)
			if countErr != nil {
				lookupIssues = append(lookupIssues, fmt.Sprintf("%s: %v", pattern, countErr))
				continue
			}
			if expectedDeleteCount <= 0 {
				continue
			}
			deletedCount := 0
			for i := 0; i < expectedDeleteCount; i++ {
				_, err := runCommand("uci", "-q", "del_list", "dhcp.@dnsmasq[0].address="+pattern)
				if err != nil {
					deleteIssues = append(deleteIssues, fmt.Sprintf("%s: %v", pattern, err))
					break
				}
				deletedCount++
			}
			if deletedCount > 0 {
				addressRemovedCount += deletedCount
				removedAddress = append(removedAddress, pattern)
			}
		}
	}

	serverValues, serverScanErr := listDNSMasqListValues("server")
	if serverScanErr != nil {
		lookupIssues = append(lookupIssues, "server scan: "+serverScanErr.Error())
	}
	for _, serverValue := range serverValues {
		for _, entry := range splitDNSMasqServerValue(serverValue) {
			serverText := strings.TrimSpace(entry)
			if serverText == "" {
				continue
			}
			if shouldRemoveDNSMasqServerEntry(serverText, targetSet) && !containsString(removedServer, serverText) {
				removedServer = append(removedServer, serverText)
			}
		}
	}
	if len(serverValues) > 0 {
		if _, err := runCommand("uci", "-q", "delete", "dhcp.@dnsmasq[0].server"); err != nil {
			deleteIssues = append(deleteIssues, fmt.Sprintf("server reset: %v", err))
		} else {
			serverReset = true
			serverRemovedCount = len(appendUniqueStrings(nil, removedServer...))
		}
	}
	for _, upstream := range defaultUpstreams {
		upstream = strings.TrimSpace(upstream)
		if upstream == "" {
			continue
		}
		if _, err := runCommand("uci", "-q", "add_list", "dhcp.@dnsmasq[0].server="+upstream); err != nil {
			addServerIssues = append(addServerIssues, fmt.Sprintf("%s: %v", upstream, err))
			continue
		}
		serverReset = true
	}
	for _, kv := range []struct {
		Key   string
		Value string
	}{
		{Key: "noresolv", Value: "1"},
		{Key: "allservers", Value: "0"},
		{Key: "strictorder", Value: "1"},
	} {
		if _, err := runCommand("uci", "-q", "set", "dhcp.@dnsmasq[0]."+kv.Key+"="+kv.Value); err != nil {
			optionIssues = append(optionIssues, fmt.Sprintf("%s=%s: %v", kv.Key, kv.Value, err))
			continue
		}
		forcedOptions[kv.Key] = kv.Value
	}

	hostsRemovedCount, hostsErr := removeHostsDomainOverrides("/etc/hosts", targetDomains)
	committed := false
	commitError := ""
	configChanged := addressRemovedCount > 0 || hostsRemovedCount > 0 || serverRemovedCount > 0 || serverReset || len(forcedOptions) > 0
	if configChanged {
		if _, err := runCommand("uci", "commit", "dhcp"); err != nil {
			commitError = err.Error()
		} else {
			committed = true
		}
	}
	dnsmasqRestarted := false
	dnsmasqRestartErr := ""
	if configChanged {
		if _, err := runCommand("/etc/init.d/dnsmasq", "restart"); err != nil {
			dnsmasqRestartErr = err.Error()
		} else {
			dnsmasqRestarted = true
		}
	}

	if len(removedAddress) > 1 {
		sort.Strings(removedAddress)
	}
	if len(removedServer) > 1 {
		sort.Strings(removedServer)
	}
	issues := make([]string, 0, 3)
	if commitError != "" {
		issues = append(issues, "uci commit failed: "+commitError)
	}
	if hostsErr != nil {
		issues = append(issues, "hosts cleanup failed: "+hostsErr.Error())
	}
	if dnsmasqRestartErr != "" {
		issues = append(issues, "dnsmasq restart failed: "+dnsmasqRestartErr)
	}
	if len(lookupIssues) > 0 {
		issues = append(issues, "dnsmasq address scan issues: "+strings.Join(lookupIssues, "; "))
	}
	if len(deleteIssues) > 0 {
		issues = append(issues, "dnsmasq address delete issues: "+strings.Join(deleteIssues, "; "))
	}
	if len(addServerIssues) > 0 {
		issues = append(issues, "dnsmasq server add issues: "+strings.Join(addServerIssues, "; "))
	}
	if len(optionIssues) > 0 {
		issues = append(issues, "dnsmasq option set issues: "+strings.Join(optionIssues, "; "))
	}

	return openwrtDNSRepairResult{
		OK:               len(issues) == 0,
		Time:             time.Now().Format(time.RFC3339),
		Domains:          targetDomains,
		AddressRemoved:   addressRemovedCount,
		AddressPatterns:  removedAddress,
		ServerRemoved:    serverRemovedCount,
		ServerPatterns:   removedServer,
		ServerReset:      serverReset,
		ServerUpstreams:  append([]string(nil), defaultUpstreams...),
		OptionsForced:    forcedOptions,
		UCICommitted:     committed,
		HostsRemoved:     hostsRemovedCount,
		ConfigChanged:    configChanged,
		DNSMasqRestarted: dnsmasqRestarted,
		Issues:           issues,
		Message:          fmt.Sprintf("DNS 修复完成: address移除=%d, server移除=%d, hosts移除=%d", addressRemovedCount, serverRemovedCount, hostsRemovedCount),
	}
}

func listDNSMasqListValues(option string) ([]string, error) {
	option = strings.TrimSpace(option)
	if option == "" {
		return nil, fmt.Errorf("empty option")
	}
	out, err := runCommand("uci", "-q", "show", "dhcp.@dnsmasq[0]")
	if err != nil {
		return nil, err
	}
	needlePrefix := "." + option + "="
	values := make([]string, 0, 8)
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || !strings.Contains(line, needlePrefix) {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 || idx >= len(line)-1 {
			continue
		}
		value := strings.TrimSpace(line[idx+1:])
		value = strings.Trim(value, "'\"")
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return values, nil
}

func shouldRemoveDNSMasqServerEntry(serverValue string, domains map[string]struct{}) bool {
	value := strings.ToLower(strings.TrimSpace(serverValue))
	if value == "" || !strings.HasPrefix(value, "/") {
		return false
	}
	for domain := range domains {
		if strings.Contains(value, "/"+domain+"/") {
			return true
		}
	}
	return false
}

func splitDNSMasqServerValue(serverValue string) []string {
	value := strings.TrimSpace(serverValue)
	if value == "" {
		return nil
	}
	if !strings.Contains(value, " ") {
		return []string{strings.Trim(value, "'\"")}
	}
	parts := strings.Fields(value)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		text := strings.Trim(strings.TrimSpace(part), "'\"")
		if text == "" {
			continue
		}
		out = append(out, text)
	}
	if len(out) == 0 {
		text := strings.Trim(value, "'\"")
		if text != "" {
			out = append(out, text)
		}
	}
	return appendUniqueStrings(nil, out...)
}

func containsString(list []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

func countDNSMasqAddressEntries(pattern string) (int, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return 0, nil
	}
	out, err := runCommand("uci", "-q", "show", "dhcp.@dnsmasq[0]")
	if err != nil {
		return 0, err
	}
	needleSuffix := ".address='" + pattern + "'"
	needleMid := ".address=" + pattern
	count := 0
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.Contains(line, needleSuffix) || strings.Contains(line, needleMid) {
			count++
		}
	}
	return count, nil
}

func detectMITMCAInstallStatus(caPEM []byte) (map[string]any, error) {
	fingerprint, subject, err := mitmCertFingerprint(caPEM)
	if err != nil {
		return nil, err
	}
	status := map[string]any{
		"os":               runtime.GOOS,
		"installed":        false,
		"mode":             "",
		"location":         "",
		"message":          "",
		"fingerprint":      fingerprint,
		"subject":          subject,
		"can_auto_install": runtime.GOOS == "linux" || runtime.GOOS == "darwin",
	}

	switch runtime.GOOS {
	case "linux":
		openwrt := isOpenWrtRuntime()
		status["openwrt"] = openwrt
		if openwrt {
			path := "/etc/ssl/certs/anytls-mitm-ca.crt"
			ok, ferr := matchMITMCertFile(path, fingerprint)
			status["mode"] = "openwrt"
			status["location"] = path
			if ferr != nil {
				status["message"] = ferr.Error()
				return status, nil
			}
			status["installed"] = ok
			if ok {
				status["message"] = "MITM CA 已安装 (OpenWrt)"
			} else {
				status["message"] = "MITM CA 未安装到 OpenWrt 证书目录"
			}
			return status, nil
		}

		paths := []struct {
			mode string
			path string
		}{
			{mode: "linux-ca-certificates", path: "/usr/local/share/ca-certificates/anytls-mitm-ca.crt"},
			{mode: "linux-generic", path: "/etc/ssl/certs/anytls-mitm-ca.crt"},
		}
		for _, item := range paths {
			ok, ferr := matchMITMCertFile(item.path, fingerprint)
			if ferr != nil {
				continue
			}
			if ok {
				status["installed"] = true
				status["mode"] = item.mode
				status["location"] = item.path
				status["message"] = "MITM CA 已安装"
				return status, nil
			}
		}
		status["mode"] = "linux"
		status["message"] = "未检测到 MITM CA 安装"
		return status, nil
	case "darwin":
		ok, derr := detectDarwinMITMCAInstalled(fingerprint)
		status["mode"] = "darwin-keychain"
		status["location"] = "/Library/Keychains/System.keychain"
		if derr != nil {
			status["message"] = derr.Error()
			return status, nil
		}
		status["installed"] = ok
		if ok {
			status["message"] = "MITM CA 已安装到系统钥匙串"
		} else {
			status["message"] = "未检测到 MITM CA（系统钥匙串）"
		}
		return status, nil
	default:
		status["mode"] = runtime.GOOS
		status["can_auto_install"] = false
		status["message"] = "当前平台暂不支持自动检测"
		return status, nil
	}
}

func autoInstallMITMCA(caPEM []byte) (mode, location, message string, err error) {
	tmpPath := filepath.Join(os.TempDir(), "anytls-mitm-ca.crt")
	if werr := os.WriteFile(tmpPath, caPEM, 0644); werr != nil {
		return "", "", "", werr
	}

	switch runtime.GOOS {
	case "linux":
		if isOpenWrtRuntime() {
			dest := "/etc/ssl/certs/anytls-mitm-ca.crt"
			if err := os.MkdirAll("/etc/ssl/certs", 0755); err != nil {
				return "", "", "", err
			}
			if err := os.WriteFile(dest, caPEM, 0644); err != nil {
				return "", "", "", err
			}
			return "openwrt", dest, "OpenWrt MITM CA 已安装", nil
		}

		if commandExists("update-ca-certificates") && dirExists("/usr/local/share/ca-certificates") {
			dest := "/usr/local/share/ca-certificates/anytls-mitm-ca.crt"
			if err := os.WriteFile(dest, caPEM, 0644); err != nil {
				return "", "", "", err
			}
			if _, err := runCommand("update-ca-certificates"); err != nil {
				return "", "", "", err
			}
			return "linux-ca-certificates", dest, "Linux MITM CA 已安装并刷新证书库", nil
		}
		if commandExists("trust") {
			if _, err := runCommand("trust", "anchor", tmpPath); err != nil {
				return "", "", "", err
			}
			return "linux-trust-anchor", tmpPath, "Linux MITM CA 已通过 trust anchor 安装", nil
		}
		dest := "/etc/ssl/certs/anytls-mitm-ca.crt"
		if err := os.MkdirAll("/etc/ssl/certs", 0755); err != nil {
			return "", "", "", err
		}
		if err := os.WriteFile(dest, caPEM, 0644); err != nil {
			return "", "", "", err
		}
		return "linux-generic", dest, "证书已写入系统目录，请手动刷新系统证书库", nil
	case "darwin":
		if _, err := runCommand("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", tmpPath); err != nil {
			return "", "", "", err
		}
		return "darwin-keychain", "/Library/Keychains/System.keychain", "MITM CA 已安装到 macOS 系统钥匙串", nil
	default:
		return "", "", "", fmt.Errorf("auto install is not supported on %s", runtime.GOOS)
	}
}

func mitmCertFingerprint(certPEM []byte) (fingerprint string, subject string, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", "", fmt.Errorf("invalid pem certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), cert.Subject.String(), nil
}

func matchMITMCertFile(path, expectedFingerprint string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	found, _, err := mitmCertFingerprint(raw)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(found, expectedFingerprint), nil
}

func removeHostsDomainOverrides(path string, domains []string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	lines := strings.Split(string(raw), "\n")
	domainSet := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		dom := strings.TrimSpace(strings.ToLower(domain))
		if dom == "" {
			continue
		}
		domainSet[dom] = struct{}{}
	}
	if len(domainSet) == 0 {
		return 0, nil
	}

	out := make([]string, 0, len(lines))
	removed := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			out = append(out, line)
			continue
		}
		match := false
		for _, field := range fields[1:] {
			host := strings.Trim(strings.ToLower(strings.TrimSpace(field)), ".")
			if host == "" {
				continue
			}
			if _, ok := domainSet[host]; ok {
				match = true
				break
			}
		}
		if match {
			removed++
			continue
		}
		out = append(out, line)
	}

	if removed == 0 {
		return 0, nil
	}
	newContent := strings.Join(out, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
		return removed, err
	}
	return removed, nil
}

func detectDarwinMITMCAInstalled(expectedFingerprint string) (bool, error) {
	if !commandExists("security") {
		return false, fmt.Errorf("security command not found")
	}
	out, err := runCommand("security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
	if err != nil {
		return false, err
	}
	needle := strings.ToUpper(strings.TrimSpace(expectedFingerprint))
	if needle == "" {
		return false, fmt.Errorf("empty fingerprint")
	}
	text := strings.ToUpper(strings.ReplaceAll(out, ":", ""))
	return strings.Contains(text, needle), nil
}

func isOpenWrtRuntime() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), "openwrt")
}

func isPermissionLikeError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted")
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.IsDir()
}

func (s *apiState) loadMITMCAPEM() ([]byte, error) {
	s.lock.Lock()
	var caPEM []byte
	if s.mitm != nil {
		caPEM = s.mitm.CAPEM()
	}
	caPath := ""
	caKeyPath := ""
	if s.cfg != nil && s.cfg.MITM != nil {
		caPath = strings.TrimSpace(s.cfg.MITM.CACertPath)
		caKeyPath = strings.TrimSpace(s.cfg.MITM.CAKeyPath)
	}
	s.lock.Unlock()

	if len(caPEM) > 0 {
		return caPEM, nil
	}

	tmpCfg := &clientMITMConfig{
		Enabled:    false,
		CACertPath: caPath,
		CAKeyPath:  caKeyPath,
	}
	if err := normalizeMITMConfig(tmpCfg); err != nil {
		return nil, err
	}
	caPath = tmpCfg.CACertPath
	caKeyPath = tmpCfg.CAKeyPath

	raw, err := os.ReadFile(caPath)
	if err == nil {
		return raw, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	ca, err := loadOrCreateMITMCA(caPath, caKeyPath)
	if err != nil {
		return nil, err
	}
	return ca.certPEMRaw, nil
}

func buildMITMCAInstallShellScript(caPEM []byte) string {
	pem := strings.TrimSpace(string(caPEM)) + "\n"
	return "#!/bin/sh\n" +
		"set -eu\n\n" +
		"TMP_CA=\"/tmp/anytls-mitm-ca.crt\"\n" +
		"cat > \"$TMP_CA\" <<'__ANYTLS_CA__'\n" +
		pem +
		"__ANYTLS_CA__\n\n" +
		"run_root() {\n" +
		"  if [ \"$(id -u)\" -eq 0 ]; then\n" +
		"    \"$@\"\n" +
		"    return\n" +
		"  fi\n" +
		"  if command -v sudo >/dev/null 2>&1; then\n" +
		"    sudo \"$@\"\n" +
		"    return\n" +
		"  fi\n" +
		"  echo \"需要 root 权限，请使用 root 执行\" >&2\n" +
		"  exit 1\n" +
		"}\n\n" +
		"if [ -f /etc/openwrt_release ] || grep -qi openwrt /etc/os-release 2>/dev/null; then\n" +
		"  run_root mkdir -p /etc/ssl/certs\n" +
		"  run_root cp \"$TMP_CA\" /etc/ssl/certs/anytls-mitm-ca.crt\n" +
		"  run_root chmod 644 /etc/ssl/certs/anytls-mitm-ca.crt\n" +
		"  echo \"OpenWrt 已安装 MITM CA: /etc/ssl/certs/anytls-mitm-ca.crt\"\n" +
		"  exit 0\n" +
		"fi\n\n" +
		"OS_NAME=\"$(uname -s 2>/dev/null || true)\"\n" +
		"if [ \"$OS_NAME\" = \"Darwin\" ]; then\n" +
		"  run_root security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"$TMP_CA\"\n" +
		"  echo \"macOS 已安装 MITM CA 到系统钥匙串\"\n" +
		"  exit 0\n" +
		"fi\n\n" +
		"if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then\n" +
		"  run_root cp \"$TMP_CA\" /usr/local/share/ca-certificates/anytls-mitm-ca.crt\n" +
		"  run_root update-ca-certificates\n" +
		"  echo \"Linux 已安装 MITM CA 并刷新证书库\"\n" +
		"  exit 0\n" +
		"fi\n\n" +
		"if command -v trust >/dev/null 2>&1; then\n" +
		"  run_root trust anchor \"$TMP_CA\"\n" +
		"  echo \"Linux 已通过 trust anchor 安装 MITM CA\"\n" +
		"  exit 0\n" +
		"fi\n\n" +
		"echo \"已写出证书: $TMP_CA\"\n" +
		"echo \"未检测到自动导入工具，请手动导入该证书。\"\n"
}

func (s *apiState) handleConfigBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	backups, err := listClientConfigBackups(s.configPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config_path": s.configPath,
		"count":       len(backups),
		"backups":     backups,
	})
}

func (s *apiState) handleConfigRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Backup string `json:"backup"`
	}
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	restored, err := rollbackClientConfig(s.configPath, req.Backup)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	reloaded, err := loadClientConfig(s.configPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"restored":           restored,
		"restart_required":   true,
		"message":            "config rollback succeeded, restart anytls-client api to apply runtime state",
		"config_after_apply": reloaded,
	})
}

func (s *apiState) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.lock.Lock()
	cfgPath := s.configPath
	cfg := *s.cfg
	cfg.Nodes = append([]clientNodeConfig(nil), s.cfg.Nodes...)
	current := s.manager.CurrentNodeName()
	tunRunning := s.tun != nil
	s.lock.Unlock()

	checks := make([]diagnoseCheck, 0, 8)

	if _, err := os.Stat(cfgPath); err != nil {
		checks = append(checks, diagnoseCheck{Name: "config_file", OK: false, Error: err.Error()})
	} else {
		checks = append(checks, diagnoseCheck{Name: "config_file", OK: true, Detail: cfgPath})
	}

	if _, err := loadClientConfig(cfgPath); err != nil {
		checks = append(checks, diagnoseCheck{Name: "config_parse", OK: false, Error: err.Error()})
	} else {
		checks = append(checks, diagnoseCheck{Name: "config_parse", OK: true})
	}

	node, found := findNodeByName(cfg.Nodes, current)
	if !found || strings.TrimSpace(current) == "" {
		checks = append(checks, diagnoseCheck{Name: "current_node", OK: false, Error: "current node not found"})
	} else {
		checks = append(checks, diagnoseCheck{Name: "current_node", OK: true, Detail: current})
		start := time.Now()
		conn, err := net.DialTimeout("tcp", node.Server, 3*time.Second)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			checks = append(checks, diagnoseCheck{Name: "server_tcp", OK: false, Error: err.Error()})
		} else {
			_ = conn.Close()
			checks = append(checks, diagnoseCheck{Name: "server_tcp", OK: true, Detail: node.Server, Latency: latency})
		}

		minIdle := cfg.MinIdleSession
		if minIdle <= 0 {
			minIdle = 5
		}
		probeTimeout := 3 * time.Second
		if cfg.Failover != nil && cfg.Failover.ProbeTimeoutMS > 0 {
			probeTimeout = time.Duration(cfg.Failover.ProbeTimeoutMS) * time.Millisecond
		}
		// Diagnose should be less sensitive than runtime failover; avoid false negatives
		// under transient load spikes.
		if probeTimeout < 5*time.Second {
			probeTimeout = 5 * time.Second
		}
		probeTarget := defaultLatencyTarget
		if cfg.Failover != nil && strings.TrimSpace(cfg.Failover.ProbeTarget) != "" {
			probeTarget = strings.TrimSpace(cfg.Failover.ProbeTarget)
		}
		if runtime.GOOS == "linux" && isOpenWrtRuntime() &&
			strings.EqualFold(strings.TrimSpace(probeTarget), strings.TrimSpace(defaultLatencyTarget)) {
			probeTarget = "www.google.com:443"
		}
		probeTargets := parseFailoverProbeTargets(probeTarget)
		defaultProbeTarget := strings.TrimSpace(defaultLatencyTarget)
		hasDefaultProbeTarget := false
		for _, candidate := range probeTargets {
			if strings.EqualFold(strings.TrimSpace(candidate), defaultProbeTarget) {
				hasDefaultProbeTarget = true
				break
			}
		}
		lat := int64(0)
		handshakeErr := ""
		okAll := true
		degradedTargets := make([]string, 0, len(probeTargets))
		probeCount := 3
		for idx, target := range probeTargets {
			result := measureNodeLatency(node, target, probeCount, probeTimeout, minIdle)
			if result.Success > 0 && idx == 0 {
				switch {
				case result.AvgMS > 0:
					lat = int64(result.AvgMS)
				case len(result.SamplesMS) > 0:
					lat = int64(result.SamplesMS[0])
				}
			}
			if result.Success > 0 {
				if result.Success < probeCount {
					errText := strings.TrimSpace(result.Error)
					if errText == "" {
						errText = "partial success"
					}
					degradedTargets = append(degradedTargets, fmt.Sprintf("%s(%d/%d,%s)", target, result.Success, probeCount, errText))
				}
				continue
			}
			errMsg := strings.TrimSpace(result.Error)
			if errMsg == "" {
				errMsg = "probe failed"
			}

			// One relaxed retry to reduce transient false negatives under short bursts.
			retryTimeout := probeTimeout + 2*time.Second
			if retryTimeout < 7*time.Second {
				retryTimeout = 7 * time.Second
			}
			retryResult := measureNodeLatency(node, target, 1, retryTimeout, minIdle)
			if retryResult.Success > 0 {
				if lat == 0 {
					switch {
					case retryResult.AvgMS > 0:
						lat = int64(retryResult.AvgMS)
					case len(retryResult.SamplesMS) > 0:
						lat = int64(retryResult.SamplesMS[0])
					}
				}
				degradedTargets = append(degradedTargets, fmt.Sprintf("%s(0/%d,%s)->retry(1/1)", target, probeCount, errMsg))
				continue
			}

			// If configured failover target is flaky, fall back to DNS-free default probe target.
			if defaultProbeTarget != "" &&
				!hasDefaultProbeTarget &&
				!strings.EqualFold(strings.TrimSpace(target), defaultProbeTarget) {
				fallbackTimeout := probeTimeout
				if fallbackTimeout < 4*time.Second {
					fallbackTimeout = 4 * time.Second
				}
				fallbackResult := measureNodeLatency(node, defaultProbeTarget, 1, fallbackTimeout, minIdle)
				if fallbackResult.Success > 0 {
					if lat == 0 {
						switch {
						case fallbackResult.AvgMS > 0:
							lat = int64(fallbackResult.AvgMS)
						case len(fallbackResult.SamplesMS) > 0:
							lat = int64(fallbackResult.SamplesMS[0])
						}
					}
					degradedTargets = append(degradedTargets, fmt.Sprintf("%s(0/%d,%s)->fallback:%s(1/1)", target, probeCount, errMsg, defaultProbeTarget))
					continue
				}
			}

			okAll = false
			handshakeErr = fmt.Sprintf("target=%s: %s", target, errMsg)
			break
		}
		targetDetail := strings.Join(probeTargets, ",")
		if okAll {
			if len(degradedTargets) > 0 {
				targetDetail = fmt.Sprintf("%s; partial=%s", targetDetail, strings.Join(degradedTargets, ";"))
			}
			checks = append(checks, diagnoseCheck{Name: "proxy_handshake", OK: true, Detail: targetDetail, Latency: lat})
		} else {
			checks = append(checks, diagnoseCheck{Name: "proxy_handshake", OK: false, Error: handshakeErr})
		}
	}

	if cfg.Tun != nil && cfg.Tun.Enabled {
		if tunRunning {
			checks = append(checks, diagnoseCheck{Name: "tun", OK: true, Detail: fmt.Sprintf("%s (%s)", cfg.Tun.Name, cfg.Tun.Address)})
		} else {
			checks = append(checks, diagnoseCheck{Name: "tun", OK: false, Error: "tun enabled in config but runtime not active"})
		}
	} else {
		checks = append(checks, diagnoseCheck{Name: "tun", OK: true, Detail: "disabled"})
	}

	if cfg.Failover != nil && cfg.Failover.Enabled {
		probeTarget := strings.TrimSpace(cfg.Failover.ProbeTarget)
		if probeTarget == "" {
			probeTarget = defaultLatencyTarget
		}
		if runtime.GOOS == "linux" && isOpenWrtRuntime() &&
			strings.EqualFold(strings.TrimSpace(probeTarget), strings.TrimSpace(defaultLatencyTarget)) {
			probeTarget = "www.google.com:443"
		}
		targets := parseFailoverProbeTargets(probeTarget)
		checks = append(checks, diagnoseCheck{Name: "failover", OK: true, Detail: fmt.Sprintf("interval=%ds threshold=%d targets=%s", cfg.Failover.CheckIntervalSec, cfg.Failover.FailureThreshold, strings.Join(targets, ","))})
	} else {
		checks = append(checks, diagnoseCheck{Name: "failover", OK: true, Detail: "disabled"})
	}

	failed := 0
	for _, item := range checks {
		if !item.OK {
			failed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"time":    time.Now().Format(time.RFC3339),
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
		"current": current,
		"checks":  checks,
		"summary": map[string]any{
			"ok":     failed == 0,
			"failed": failed,
			"total":  len(checks),
		},
	})
}
