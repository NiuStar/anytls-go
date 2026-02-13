package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

type runtimeClientManager struct {
	ctx            context.Context
	minIdleSession int

	nodes     map[string]clientNodeConfig
	nodeOrder []string

	lock        sync.RWMutex
	currentName string
	clients     map[string]*myClient

	autoFailoverCancel context.CancelFunc
	onAutoSwitch       func(from, to string) error
	onFailoverExhaust  func(current string, failures int, cause error)
}

func newRuntimeClientManager(ctx context.Context, nodes []clientNodeConfig, selected string, minIdleSession int) (*runtimeClientManager, error) {
	m := &runtimeClientManager{
		ctx:            ctx,
		minIdleSession: minIdleSession,
		nodes:          make(map[string]clientNodeConfig, len(nodes)),
		nodeOrder:      make([]string, 0, len(nodes)),
		clients:        make(map[string]*myClient, len(nodes)),
	}
	for _, node := range nodes {
		m.nodes[node.Name] = node
		m.nodeOrder = append(m.nodeOrder, node.Name)
	}

	if err := m.Switch(selected); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *runtimeClientManager) buildClient(node clientNodeConfig) (*myClient, error) {
	return buildClientFromNode(m.ctx, node, m.minIdleSession)
}

func (m *runtimeClientManager) CurrentClient() *myClient {
	m.lock.RLock()
	name := m.currentName
	client := m.clients[name]
	m.lock.RUnlock()
	if client != nil || name == "" {
		return client
	}
	client, err := m.ClientForNode(name)
	if err != nil {
		logrus.Warnf("[Client] resolve current node client failed: %v", err)
		return nil
	}
	return client
}

func (m *runtimeClientManager) CurrentNodeName() string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.currentName
}

func (m *runtimeClientManager) Switch(name string) error {
	if _, ok := m.Node(name); !ok {
		return fmt.Errorf("node not found: %s", name)
	}

	if _, err := m.ClientForNode(name); err != nil {
		return err
	}

	var oldClient *myClient
	m.lock.Lock()
	prev := m.currentName
	if prev != "" && prev != name {
		oldClient = m.clients[prev]
		// Drop previous current-node client so future switch takes effect immediately.
		// Existing streams on old client will be closed below.
		delete(m.clients, prev)
	}
	m.currentName = name
	m.lock.Unlock()
	if oldClient != nil {
		if err := oldClient.Close(); err != nil {
			logrus.Warnf("[Client] switch node close old client failed: %s => %s: %v", prev, name, err)
		} else {
			logrus.Infof("[Client] switch node applied: %s => %s (old client closed)", prev, name)
		}
	} else if prev != "" && prev != name {
		logrus.Infof("[Client] switch node applied: %s => %s", prev, name)
	}
	return nil
}

func (m *runtimeClientManager) Node(name string) (clientNodeConfig, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	node, ok := m.nodes[name]
	return node, ok
}

func (m *runtimeClientManager) ClientForNode(name string) (*myClient, error) {
	m.lock.RLock()
	client := m.clients[name]
	node, ok := m.nodes[name]
	m.lock.RUnlock()
	if client != nil {
		return client, nil
	}
	if !ok {
		return nil, fmt.Errorf("node not found: %s", name)
	}

	newClient, err := m.buildClient(node)
	if err != nil {
		return nil, err
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	if client = m.clients[name]; client != nil {
		_ = newClient.Close()
		return client, nil
	}
	if _, ok := m.nodes[name]; !ok {
		_ = newClient.Close()
		return nil, fmt.Errorf("node not found: %s", name)
	}
	m.clients[name] = newClient
	return newClient, nil
}

func nodeClientRuntimeChanged(a, b clientNodeConfig) bool {
	return a.Server != b.Server ||
		a.Password != b.Password ||
		a.SNI != b.SNI ||
		a.EgressIP != b.EgressIP ||
		a.EgressRule != b.EgressRule
}

func (m *runtimeClientManager) Close() error {
	m.lock.Lock()
	cancel := m.autoFailoverCancel
	m.autoFailoverCancel = nil
	clients := make([]*myClient, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	m.clients = make(map[string]*myClient)
	m.currentName = ""
	m.lock.Unlock()

	if cancel != nil {
		cancel()
	}
	var firstErr error
	for _, client := range clients {
		if client == nil {
			continue
		}
		if err := client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *runtimeClientManager) ResetClients() error {
	m.lock.Lock()
	clients := make([]*myClient, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	m.clients = make(map[string]*myClient)
	current := m.currentName
	m.lock.Unlock()

	var firstErr error
	for _, client := range clients {
		if client == nil {
			continue
		}
		if err := client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if strings.TrimSpace(current) != "" {
		if _, err := m.ClientForNode(current); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *runtimeClientManager) ListNodes() []string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	out := make([]string, 0, len(m.nodeOrder))
	out = append(out, m.nodeOrder...)
	return out
}

func (m *runtimeClientManager) HasNode(name string) bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	_, ok := m.nodes[name]
	return ok
}

func (m *runtimeClientManager) UpsertNode(node clientNodeConfig) {
	var oldClient *myClient
	m.lock.Lock()
	if oldNode, ok := m.nodes[node.Name]; !ok {
		m.nodeOrder = append(m.nodeOrder, node.Name)
	} else if nodeClientRuntimeChanged(oldNode, node) {
		oldClient = m.clients[node.Name]
		delete(m.clients, node.Name)
	}
	m.nodes[node.Name] = node
	m.lock.Unlock()
	if oldClient != nil {
		_ = oldClient.Close()
	}
}

func (m *runtimeClientManager) DeleteNode(name string) {
	var oldClient *myClient
	m.lock.Lock()
	delete(m.nodes, name)
	oldClient = m.clients[name]
	delete(m.clients, name)
	for i, item := range m.nodeOrder {
		if item == name {
			m.nodeOrder = append(m.nodeOrder[:i], m.nodeOrder[i+1:]...)
			break
		}
	}
	if m.currentName == name {
		if len(m.nodeOrder) > 0 {
			m.currentName = m.nodeOrder[0]
		} else {
			m.currentName = ""
		}
	}
	m.lock.Unlock()
	if oldClient != nil {
		_ = oldClient.Close()
	}
}

func (m *runtimeClientManager) SetAutoSwitchHook(fn func(from, to string) error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.onAutoSwitch = fn
}

func (m *runtimeClientManager) SetFailoverExhaustHook(fn func(current string, failures int, cause error)) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.onFailoverExhaust = fn
}

func (m *runtimeClientManager) StartAutoFailover(cfg clientFailoverConfig) {
	m.lock.Lock()
	if m.autoFailoverCancel != nil {
		m.autoFailoverCancel()
		m.autoFailoverCancel = nil
	}
	if !cfg.Enabled {
		atomic.StoreInt64(&failoverProbeIntervalMSCurrent, 0)
		atomic.StoreInt64(&failoverProbeScaleCurrent, 0)
		m.lock.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.autoFailoverCancel = cancel
	m.lock.Unlock()

	interval := time.Duration(cfg.CheckIntervalSec) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
	}
	threshold := cfg.FailureThreshold
	if threshold <= 0 {
		threshold = 2
	}
	probeTarget := strings.TrimSpace(cfg.ProbeTarget)
	if probeTarget == "" {
		probeTarget = defaultLatencyTarget
	}
	// On OpenWrt, pure IP probe can be false-positive (IP reachable while
	// major TLS destinations like Google still fail). Keep legacy config, but
	// auto-upgrade the default target at runtime for better health semantics.
	if runtime.GOOS == "linux" && isOpenWrtRuntime() {
		if strings.EqualFold(strings.TrimSpace(probeTarget), strings.TrimSpace(defaultLatencyTarget)) {
			probeTarget = "www.google.com:443"
		}
	}
	probeTargets := parseFailoverProbeTargets(probeTarget)
	timeout := time.Duration(cfg.ProbeTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}

	go func() {
		failures := 0
		lastScale := int64(1)
		atomic.StoreInt64(&failoverProbeIntervalMSCurrent, interval.Milliseconds())
		atomic.StoreInt64(&failoverProbeScaleCurrent, 1)
		defer func() {
			atomic.StoreInt64(&failoverProbeIntervalMSCurrent, 0)
			atomic.StoreInt64(&failoverProbeScaleCurrent, 0)
		}()

		for {
			wait, scale, reason := failoverProbeIntervalByPressure(interval)
			atomic.StoreInt64(&failoverProbeIntervalMSCurrent, wait.Milliseconds())
			atomic.StoreInt64(&failoverProbeScaleCurrent, scale)
			if scale != lastScale {
				if scale > 1 {
					logrus.Warnf("[Client] failover probe interval adjusted: base=%s effective=%s scale=x%d %s", interval, wait, scale, reason)
				} else {
					logrus.Infof("[Client] failover probe interval recovered: base=%s effective=%s scale=x%d %s", interval, wait, scale, reason)
				}
				lastScale = scale
			}

			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
				if ok, failedTarget := m.probeCurrentNode(probeTargets, timeout); ok {
					failures = 0
					continue
				} else if failedTarget != "" {
					logrus.Warnf("[Client] failover probe target failed: node=%s target=%s", m.CurrentNodeName(), failedTarget)
				}
				failures++
				current := m.CurrentNodeName()
				logrus.Warnf("[Client] failover probe failed: node=%s failures=%d/%d", current, failures, threshold)
				if failures < threshold {
					continue
				}
				if switched, from, to, err := m.failoverSwitch(probeTargets, timeout, cfg.BestLatencyEnabled); err != nil {
					logrus.Warnf("[Client] failover switch failed: %v", err)
					m.lock.RLock()
					exhaustHook := m.onFailoverExhaust
					m.lock.RUnlock()
					if exhaustHook != nil {
						exhaustHook(current, failures, err)
					}
				} else if switched {
					failures = 0
					logrus.Warnf("[Client] auto failover switched %s => %s", from, to)
				}
			}
		}
	}()
}

func failoverProbeIntervalByPressure(base time.Duration) (time.Duration, int64, string) {
	scale := int64(1)
	level := atomic.LoadInt64(&inboundPressureLevel)
	cooldownMS := atomic.LoadInt64(&inboundEMFILECooldownMS)
	switch {
	case level >= 3:
		scale = 4
	case level == 2:
		scale = 3
	case level == 1:
		scale = 2
	}
	if cooldownMS > 0 && scale < 3 {
		scale = 3
	}
	wait := time.Duration(scale) * base
	if wait < base {
		wait = base
	}
	if wait > 120*time.Second {
		wait = 120 * time.Second
	}
	return wait, scale, fmt.Sprintf("pressure_level=%d emfile_cooldown_ms=%d", level, cooldownMS)
}

func (m *runtimeClientManager) probeCurrentNode(targets []string, timeout time.Duration) (bool, string) {
	m.lock.RLock()
	name := m.currentName
	node, ok := m.nodes[name]
	minIdle := m.minIdleSession
	m.lock.RUnlock()
	if !ok || name == "" {
		return false, ""
	}
	return probeNodeReachable(node, targets, timeout, minIdle)
}

func (m *runtimeClientManager) failoverSwitch(targets []string, timeout time.Duration, bestLatency bool) (bool, string, string, error) {
	m.lock.RLock()
	current := m.currentName
	if current == "" || len(m.nodeOrder) <= 1 {
		m.lock.RUnlock()
		return false, "", "", nil
	}
	names := append([]string(nil), m.nodeOrder...)
	nodes := make(map[string]clientNodeConfig, len(m.nodes))
	for k, v := range m.nodes {
		nodes[k] = v
	}
	minIdle := m.minIdleSession
	hook := m.onAutoSwitch
	m.lock.RUnlock()

	startIdx := 0
	for i, n := range names {
		if n == current {
			startIdx = (i + 1) % len(names)
			break
		}
	}

	if bestLatency {
		bestName := ""
		bestLatencyMS := 0.0
		for i := 0; i < len(names)-1; i++ {
			idx := (startIdx + i) % len(names)
			candidate := names[idx]
			node, ok := nodes[candidate]
			if !ok || candidate == current {
				continue
			}
			ok, latencyMS, _ := probeNodeReachableWithLatency(node, targets, timeout, minIdle)
			if !ok {
				continue
			}
			if bestName == "" || latencyMS < bestLatencyMS {
				bestName = candidate
				bestLatencyMS = latencyMS
			}
		}
		if bestName == "" {
			return false, current, "", fmt.Errorf("no healthy fallback node")
		}
		if err := m.Switch(bestName); err != nil {
			return false, current, bestName, err
		}
		if hook != nil {
			if err := hook(current, bestName); err != nil {
				logrus.Warnf("[Client] failover hook error: %v", err)
			}
		}
		logrus.Infof("[Client] failover switched by best latency: %s => %s (latency=%.2fms)", current, bestName, bestLatencyMS)
		return true, current, bestName, nil
	}

	for i := 0; i < len(names)-1; i++ {
		idx := (startIdx + i) % len(names)
		candidate := names[idx]
		node, ok := nodes[candidate]
		if !ok || candidate == current {
			continue
		}
		if ok, _ := probeNodeReachable(node, targets, timeout, minIdle); !ok {
			continue
		}
		if err := m.Switch(candidate); err != nil {
			return false, current, candidate, err
		}
		if hook != nil {
			if err := hook(current, candidate); err != nil {
				logrus.Warnf("[Client] failover hook error: %v", err)
			}
		}
		return true, current, candidate, nil
	}
	return false, current, "", fmt.Errorf("no healthy fallback node")
}

func parseFailoverProbeTargets(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '|' || r == '\n' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		target, err := normalizeProbeTarget(part)
		if err != nil {
			logrus.Warnf("[Client] ignore invalid failover probe target %q: %v", part, err)
			continue
		}
		out = append(out, target)
	}
	if len(out) == 0 {
		return []string{defaultLatencyTarget}
	}
	return out
}

func probeNodeReachable(node clientNodeConfig, targets []string, timeout time.Duration, minIdle int) (bool, string) {
	ok, _, failedTarget := probeNodeReachableWithLatency(node, targets, timeout, minIdle)
	return ok, failedTarget
}

func probeNodeReachableWithLatency(node clientNodeConfig, targets []string, timeout time.Duration, minIdle int) (bool, float64, string) {
	if len(targets) == 0 {
		targets = []string{defaultLatencyTarget}
	}
	totalLatencyMS := 0.0
	for _, target := range targets {
		result := measureNodeLatency(node, target, 1, timeout, minIdle)
		if result.Success <= 0 || result.Error != "" {
			return false, 0, target
		}
		latencyMS := result.AvgMS
		if latencyMS <= 0 && len(result.SamplesMS) > 0 {
			latencyMS = result.SamplesMS[0]
		}
		totalLatencyMS += latencyMS
	}
	return true, totalLatencyMS / float64(len(targets)), ""
}
