package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
	t2core "github.com/xjasonlyu/tun2socks/v2/core"
	t2device "github.com/xjasonlyu/tun2socks/v2/core/device"
	t2tun "github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	t2tunnel "github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type tunRuntime struct {
	lock sync.Mutex

	config   clientTunConfig
	device   t2device.Device
	netstack *stack.Stack

	route tunRouteManager

	routeNodeServer     string
	routeMaintainCancel context.CancelFunc
	routeBypassTargets  map[string]struct{}
}

type tunStepLogger struct {
	total  int
	step   int
	report tunStartProgressCallback
}

type tunStartProgressCallback func(message string)

type tunStartProgressContextKey struct{}

var runCommandSlots = make(chan struct{}, defaultCommandSlotLimit())
var runCommandPressureMu sync.Mutex
var runCommandBlockedUntil time.Time

func defaultCommandSlotLimit() int {
	if raw := strings.TrimSpace(os.Getenv("ANYTLS_CMD_SLOTS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 64 {
			return n
		}
	}
	if runtime.GOOS == "linux" && isOpenWrtRuntime() {
		return 4
	}
	return 16
}

func withTunStartProgressCallback(ctx context.Context, cb tunStartProgressCallback) context.Context {
	if ctx == nil || cb == nil {
		return ctx
	}
	return context.WithValue(ctx, tunStartProgressContextKey{}, cb)
}

func tunStartProgressCallbackFromContext(ctx context.Context) tunStartProgressCallback {
	if ctx == nil {
		return nil
	}
	cb, _ := ctx.Value(tunStartProgressContextKey{}).(tunStartProgressCallback)
	return cb
}

func newTunStepLogger(total int, report tunStartProgressCallback) *tunStepLogger {
	if total <= 0 {
		total = 1
	}
	return &tunStepLogger{total: total, report: report}
}

func (l *tunStepLogger) begin(title string) func() {
	l.step++
	idx := l.step
	started := time.Now()
	logrus.Infof("[Client] TUN 启动步骤 %d/%d: %s", idx, l.total, title)
	if l.report != nil {
		l.report(fmt.Sprintf("TUN 启动步骤 %d/%d: %s", idx, l.total, title))
	}
	return func() {
		logrus.Infof("[Client] TUN 启动步骤 %d/%d: 完成 %s (%s)", idx, l.total, title, time.Since(started).Round(time.Millisecond))
		if l.report != nil {
			l.report(fmt.Sprintf("TUN 启动步骤 %d/%d: 完成 %s", idx, l.total, title))
		}
	}
}

func startTunRuntime(ctx context.Context, cfg clientTunConfig, socksListen string, selectedNode clientNodeConfig) (*tunRuntime, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	steps := newTunStepLogger(7, tunStartProgressCallbackFromContext(ctx))

	done := steps.begin("预处理配置")
	cfg.Name = normalizeTunDeviceNameForOS(runtime.GOOS, cfg.Name)
	done()

	done = steps.begin("初始化 TUN 上游代理")
	proxyAddr, err := normalizeTunProxyAddr(socksListen)
	if err != nil {
		return nil, err
	}

	socksProxy, err := newTunAwareSocks5Dialer(proxyAddr, "", "")
	if err != nil {
		return nil, fmt.Errorf("create tun socks5 upstream failed: %w", err)
	}
	t2tunnel.T().SetDialer(socksProxy)
	done()

	done = steps.begin("打开 TUN 设备")
	device, err := t2tun.Open(cfg.Name, uint32(cfg.MTU))
	if err != nil && runtime.GOOS == "darwin" && isTunResourceBusyError(err) && cfg.Name != "utun" {
		// A fixed utunN can remain busy for a short time after previous teardown.
		// Fallback to auto-allocated utun avoids startup failure.
		fallbackName := "utun"
		device, err = t2tun.Open(fallbackName, uint32(cfg.MTU))
		if err == nil {
			cfg.Name = fallbackName
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}
	done()

	done = steps.begin("创建 TUN 网络栈")
	netstack, err := t2core.CreateStack(&t2core.Config{
		LinkEndpoint:     device,
		TransportHandler: t2tunnel.T(),
	})
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("create tun netstack failed: %w", err)
	}
	done()

	t := &tunRuntime{
		config:             cfg,
		device:             device,
		netstack:           netstack,
		routeBypassTargets: make(map[string]struct{}),
	}

	if runtime.GOOS == "linux" {
		done = steps.begin("配置 Linux TUN 接口")
		if err := setupLinuxTunInterface(device.Name(), cfg.Address); err != nil {
			t.Close()
			return nil, err
		}
		done()
		if cfg.AutoRoute {
			done = steps.begin("启用 Linux 自动路由")
			route, err := newLinuxRouteManager(device.Name())
			if err != nil {
				t.Close()
				return nil, err
			}
			if err := route.ActivateForNode(selectedNode.Server); err != nil {
				route.Close()
				t.Close()
				return nil, err
			}
			t.route = route
			t.routeNodeServer = selectedNode.Server
			done()
		}
	} else if runtime.GOOS == "darwin" {
		done = steps.begin("配置 macOS TUN 接口")
		if err := setupDarwinTunInterface(device.Name(), cfg.Address); err != nil {
			t.Close()
			return nil, err
		}
		done()
		done = steps.begin("关闭 macOS 系统代理")
		if changed, err := disableDarwinSystemProxies(); err != nil {
			logrus.Warnln("[Client] disable macOS system proxies failed:", err)
		} else if changed > 0 {
			logrus.Infof("[Client] disabled macOS system proxy settings (%d operations)", changed)
		}
		done()
		if cfg.DisableOtherProxies {
			done = steps.begin("关闭其他代理进程")
			killed, err := stopKnownDarwinProxyProcesses(os.Getpid())
			if err != nil {
				logrus.Warnln("[Client] stop other proxy processes failed:", err)
			} else if killed > 0 {
				logrus.Infof("[Client] stopped %d proxy process(es) before enabling TUN", killed)
			}
			done()
		}
		if cfg.AutoRoute {
			done = steps.begin("启用 macOS 自动路由")
			route, err := newDarwinRouteManager(device.Name())
			if err != nil {
				t.Close()
				return nil, err
			}
			if err := route.ActivateForNode(selectedNode.Server); err != nil {
				route.Close()
				t.Close()
				return nil, err
			}
			t.route = route
			t.routeNodeServer = selectedNode.Server
			done()
		}
	} else if cfg.AutoRoute {
		t.Close()
		return nil, fmt.Errorf("tun auto_route is not supported on %s", runtime.GOOS)
	}

	if t.route != nil {
		done = steps.begin("启动路由保活")
		maintainCtx, cancel := context.WithCancel(ctx)
		t.routeMaintainCancel = cancel
		go t.routeMaintenanceLoop(maintainCtx)
		done()
	}

	go func() {
		<-ctx.Done()
		_ = t.Close()
	}()

	return t, nil
}

type tunStartResult struct {
	runtime *tunRuntime
	err     error
}

func startTunRuntimeWithTimeout(ctx context.Context, cfg clientTunConfig, socksListen string, selectedNode clientNodeConfig, timeout time.Duration) (*tunRuntime, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ch := make(chan tunStartResult, 1)
	go func() {
		rt, err := startTunRuntime(ctx, cfg, socksListen, selectedNode)
		ch <- tunStartResult{runtime: rt, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		return result.runtime, result.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("start tun runtime timeout after %s", timeout)
	}
}

func (t *tunRuntime) routeMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.lock.Lock()
			route := t.route
			server := strings.TrimSpace(t.routeNodeServer)
			if route == nil || server == "" {
				t.lock.Unlock()
				continue
			}
			err := route.ActivateForNode(server)
			var failed []string
			if err == nil {
				failed = t.reapplyBypassTargetsLocked(route)
			}
			t.lock.Unlock()
			if err != nil {
				logrus.Warnf("[Client] tun route keepalive failed: %v", err)
			} else if len(failed) > 0 {
				logrus.Warnf("[Client] tun route keepalive bypass replay failed: %d target(s): %s", len(failed), strings.Join(failed, ", "))
			}
		}
	}
}

func (t *tunRuntime) Close() error {
	if t == nil {
		return nil
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	var firstErr error
	if t.routeMaintainCancel != nil {
		t.routeMaintainCancel()
		t.routeMaintainCancel = nil
	}
	if t.route != nil {
		if err := t.route.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.route = nil
		t.routeNodeServer = ""
		t.routeBypassTargets = make(map[string]struct{})
	}

	// Close netstack and device in a non-blocking-safe order:
	// device close first helps unblock packet loops before waiting netstack shutdown.
	netstack := t.netstack
	if t.netstack != nil {
		t.netstack.Close()
	}
	if t.device != nil {
		t.device.Close()
		t.device = nil
	}
	if netstack != nil {
		if err := waitNetstackClose(netstack, 3*time.Second); err != nil && firstErr == nil {
			firstErr = err
		}
		t.netstack = nil
	}
	return firstErr
}

func waitNetstackClose(ns *stack.Stack, timeout time.Duration) error {
	if ns == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	done := make(chan struct{}, 1)
	go func() {
		ns.Wait()
		done <- struct{}{}
	}()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("wait tun netstack close timeout after %s", timeout)
	}
}

func (t *tunRuntime) OnSwitch(node clientNodeConfig) error {
	if t == nil {
		return nil
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	if t.route == nil {
		return nil
	}
	t.routeNodeServer = node.Server
	if err := t.route.UpdateNode(node.Server); err != nil {
		return err
	}
	if failed := t.reapplyBypassTargetsLocked(t.route); len(failed) > 0 {
		logrus.Warnf("[Client] tun bypass replay after switch failed: %d target(s): %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

func (t *tunRuntime) EnsureDirectBypass(destination M.Socksaddr) error {
	if t == nil {
		return nil
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	if t.route == nil {
		return nil
	}
	rawTarget := strings.TrimSpace(destination.String())
	if rawTarget == "" {
		return nil
	}
	target := rawTarget
	if host, err := resolveTargetHost(rawTarget); err == nil {
		target = host
	}
	if _, exists := t.routeBypassTargets[target]; exists {
		return nil
	}
	if err := t.route.EnsureBypass(target); err != nil {
		return err
	}
	t.routeBypassTargets[target] = struct{}{}
	return nil
}

func (t *tunRuntime) reapplyBypassTargetsLocked(route tunRouteManager) []string {
	if route == nil || len(t.routeBypassTargets) == 0 {
		return nil
	}
	failed := make([]string, 0)
	for target := range t.routeBypassTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if err := route.EnsureBypass(target); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "resolve target host") ||
				strings.Contains(msg, "resolve server host") ||
				strings.Contains(msg, "no such host") ||
				strings.Contains(msg, "temporary failure in name resolution") ||
				(strings.Contains(msg, "lookup") && strings.Contains(msg, "i/o timeout")) {
				// Keep target in replay set, but don't treat transient DNS resolve failure as route failure.
				continue
			}
			failed = append(failed, target)
		}
	}
	return failed
}

func (t *tunRuntime) sameConfig(cfg clientTunConfig) bool {
	if t == nil {
		return false
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.config == cfg
}

func normalizeTunProxyAddr(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("invalid local listen for tun upstream (%s): %w", listen, err)
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func setupLinuxTunInterface(name, cidr string) error {
	if strings.TrimSpace(cidr) != "" {
		if err := ipAddrReplace(cidr, name); err != nil {
			return fmt.Errorf("setup tun address failed: %w", err)
		}
	}
	if _, err := runCommand("ip", "link", "set", "dev", name, "up"); err != nil {
		return fmt.Errorf("bring up tun failed: %w", err)
	}
	return nil
}

func setupDarwinTunInterface(name, cidr string) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid tun address %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("darwin tun currently supports IPv4 address only, got %s", cidr)
	}
	mask := net.IP(network.Mask).String()
	if mask == "" {
		return fmt.Errorf("invalid tun netmask for %s", cidr)
	}

	_, err = runCommand("ifconfig", name, "inet", ip4.String(), ip4.String(), "netmask", mask, "up")
	if err != nil {
		return fmt.Errorf("setup tun interface failed: %w", err)
	}
	return nil
}

type tunRouteManager interface {
	ActivateForNode(server string) error
	UpdateNode(server string) error
	EnsureBypass(target string) error
	Close() error
}

type linuxRouteManager struct {
	tunName string

	defaultV4Spec string
	defaultV4Via  string
	defaultV4Dev  string

	bypass      map[string]struct{}
	nodeBypass  map[string]struct{}
	extraBypass map[string]struct{}
}

type darwinRouteManager struct {
	tunName string

	defaultGateway  string
	defaultIf       string
	defaultGateway6 string
	defaultIf6      string

	bypass  map[string]struct{}
	bypass6 map[string]struct{}
}

type linuxDefaultRouteCandidate struct {
	spec   string
	via    string
	dev    string
	metric int
}

func (m *darwinRouteManager) hasUsableCachedIPv4Uplink() bool {
	if m == nil {
		return false
	}
	iface := strings.TrimSpace(m.defaultIf)
	return iface != "" && !strings.HasPrefix(strings.ToLower(iface), "utun")
}

func (m *darwinRouteManager) hasUsableCachedIPv6Uplink() bool {
	if m == nil {
		return false
	}
	iface := strings.TrimSpace(m.defaultIf6)
	return iface != "" && !strings.HasPrefix(strings.ToLower(iface), "utun")
}

func isDarwinRouteNotInTableText(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	return strings.Contains(text, "not in table") || strings.Contains(text, "writing to routing socket")
}

const routeResolveTimeout = 3 * time.Second

func newLinuxRouteManager(tunName string) (*linuxRouteManager, error) {
	manager := &linuxRouteManager{
		tunName:     tunName,
		bypass:      make(map[string]struct{}),
		nodeBypass:  make(map[string]struct{}),
		extraBypass: make(map[string]struct{}),
	}
	if err := manager.refreshDefaultRoute(false); err != nil {
		return nil, err
	}
	return manager, nil
}

func detectLinuxDefaultRoute() (spec, via, dev string, err error) {
	type routeProbe struct {
		name string
		args []string
	}
	probes := []routeProbe{
		{name: "ip", args: []string{"-4", "route", "show", "default"}},
		{name: "ip", args: []string{"route", "show", "default"}},
		{name: "ip", args: []string{"-4", "route", "show", "table", "main", "default"}},
		{name: "ip", args: []string{"route", "show", "table", "main", "default"}},
		{name: "ip", args: []string{"route", "show", "table", "all", "default"}},
		{name: "route", args: []string{"-n"}},
	}

	var errs []string
	for _, probe := range probes {
		out, runErr := runCommand(probe.name, probe.args...)
		if runErr != nil {
			errs = append(errs, fmt.Sprintf("%s %s: %v", probe.name, strings.Join(probe.args, " "), runErr))
			continue
		}
		if spec, via, dev, ok := parseLinuxDefaultRouteOutput(out); ok {
			return spec, via, dev, nil
		}
		errs = append(errs, fmt.Sprintf("%s %s: no default route in output", probe.name, strings.Join(probe.args, " ")))
	}

	return "", "", "", fmt.Errorf("cannot parse default route: %q", strings.Join(errs, " | "))
}

func (m *linuxRouteManager) ActivateForNode(server string) error {
	if err := m.refreshDefaultRoute(false); err != nil {
		return err
	}
	if err := m.UpdateNode(server); err != nil {
		return err
	}

	// Linux/OpenWrt: prefer split default routes instead of replacing system default.
	// This avoids losing the real default route when route tool behavior is unstable.
	if _, _, currentDev, err := detectLinuxDefaultRoute(); err == nil {
		if strings.TrimSpace(currentDev) == strings.TrimSpace(m.tunName) {
			// Best effort restore before applying split routes.
			_ = ipRouteReplaceDefault(strings.Fields(m.defaultV4Spec))
		}
	}
	if err := m.ensureSplitDefaultRoutes(); err != nil {
		return err
	}
	if err := m.verifyServerBypass(server); err != nil {
		_ = ipRouteDeleteSpec([]string{"0.0.0.0/1", "dev", m.tunName})
		_ = ipRouteDeleteSpec([]string{"128.0.0.0/1", "dev", m.tunName})
		return err
	}
	return nil
}

func (m *linuxRouteManager) UpdateNode(server string) error {
	if err := m.refreshDefaultRoute(false); err != nil {
		return err
	}
	target, err := resolveServerIPv4Set(server)
	if err != nil {
		return err
	}

	for ip := range target {
		if err := m.addBypass(ip); err != nil {
			return err
		}
		m.bypass[ip] = struct{}{}
		m.nodeBypass[ip] = struct{}{}
	}

	for ip := range m.nodeBypass {
		if _, exists := target[ip]; exists {
			continue
		}
		delete(m.nodeBypass, ip)
		if _, keep := m.extraBypass[ip]; keep {
			continue
		}
		m.removeBypass(ip)
	}
	return nil
}

func (m *linuxRouteManager) addBypass(ip string) error {
	tryAdd := func() error {
		via := strings.TrimSpace(m.defaultV4Via)
		if via == "" {
			if detectedVia, err := detectLinuxIPv4GatewayForDev(m.defaultV4Dev); err == nil && detectedVia != "" {
				via = detectedVia
				m.defaultV4Via = detectedVia
				m.defaultV4Spec = buildLinuxDefaultRouteSpec(m.defaultV4Via, m.defaultV4Dev)
			}
		}
		spec := []string{ip + "/32"}
		if via != "" {
			spec = append(spec, "via", via)
		}
		spec = append(spec, "dev", m.defaultV4Dev)
		if err := ipRouteReplaceSpec(spec); err != nil {
			return fmt.Errorf("add bypass route for server %s failed: %w", ip, err)
		}
		if err := m.verifyBypassRoute(ip); err != nil {
			return fmt.Errorf("verify bypass route for server %s failed: %w", ip, err)
		}
		return nil
	}
	if err := tryAdd(); err != nil {
		if refreshErr := m.refreshDefaultRoute(true); refreshErr == nil {
			if retryErr := tryAdd(); retryErr == nil {
				return nil
			} else {
				return retryErr
			}
		}
		return err
	}
	return nil
}

func (m *linuxRouteManager) verifyBypassRoute(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("empty target ip")
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		out, err := runCommand("ip", "-4", "route", "get", ip)
		if err != nil {
			lastErr = err
		} else {
			_, dev, _ := parseLinuxRouteGetOutput(out)
			dev = strings.TrimSpace(dev)
			if dev == "" {
				lastErr = fmt.Errorf("cannot parse route device from: %q", out)
			} else if dev == strings.TrimSpace(m.tunName) || isLikelyTunInterfaceName(dev) {
				lastErr = fmt.Errorf("route device still points to tun-like interface: %s", dev)
			} else {
				return nil
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	return lastErr
}

func (m *linuxRouteManager) refreshDefaultRoute(repairMode bool) error {
	spec, via, dev, err := detectLinuxDefaultRoute()
	if err != nil {
		if repairMode {
			logrus.Warnf("[Client] linux route refresh detect failed (repair mode): %v", err)
		}
		return err
	}
	spec, via = sanitizeLinuxRouteSpecIPv4(spec, via)

	// On OpenWrt prefer explicit WAN route spec when available, especially for repair mode
	// and when auto-detected route appears tun-like or lacks a usable IPv4 gateway.
	if owrtSpec, owrtErr := detectOpenWrtWANDefaultRouteSpec(); owrtErr == nil && strings.TrimSpace(owrtSpec) != "" {
		owrtVia, owrtDev := parseRouteViaDev(owrtSpec)
		owrtVia = strings.TrimSpace(strings.Trim(owrtVia, "[]"))
		owrtDev = strings.TrimSpace(owrtDev)
		if owrtDev != "" && !isLikelyTunInterfaceName(owrtDev) {
			useOpenWrt := false
			switch {
			case repairMode:
				useOpenWrt = true
			case dev == "" || isLikelyTunInterfaceName(dev):
				useOpenWrt = true
			case via == "" && owrtVia != "":
				useOpenWrt = true
			}
			if useOpenWrt {
				spec = owrtSpec
				via = owrtVia
				dev = owrtDev
				nextSpec := buildLinuxDefaultRouteSpec(via, dev)
				prevSpec := strings.TrimSpace(m.defaultV4Spec)
				if nextSpec != "" && nextSpec != prevSpec {
					levelLog := logrus.Warnf
					if !repairMode {
						levelLog = logrus.Infof
					}
					levelLog("[Client] linux route manager uses OpenWrt WAN default route: %s", nextSpec)
				}
			}
		}
	}

	if dev == "" {
		return fmt.Errorf("cannot parse default route device from spec: %q", spec)
	}
	if isLikelyTunInterfaceName(dev) {
		return fmt.Errorf("default route currently points to %s; please repair network/disable other proxy first", dev)
	}
	spec = buildLinuxDefaultRouteSpec(via, dev)
	m.defaultV4Spec = spec
	m.defaultV4Via = via
	m.defaultV4Dev = dev
	return nil
}

func (m *linuxRouteManager) verifyServerBypass(server string) error {
	targetSet, err := resolveServerIPv4Set(server)
	if err != nil {
		return nil
	}
	for ip := range targetSet {
		out, routeErr := runCommand("ip", "-4", "route", "get", ip)
		if routeErr != nil {
			return fmt.Errorf("verify server bypass route %s failed: %w", ip, routeErr)
		}
		_, dev, _ := parseLinuxRouteGetOutput(out)
		dev = strings.TrimSpace(dev)
		if dev == "" {
			continue
		}
		if dev == strings.TrimSpace(m.tunName) || isLikelyTunInterfaceName(dev) {
			return fmt.Errorf("server route still points to tun-like interface (%s) after TUN enable", dev)
		}
	}
	return nil
}

func (m *linuxRouteManager) EnsureBypass(target string) error {
	targetIPs, err := resolveTargetIPv4Set(target)
	if err != nil {
		return err
	}
	for ip := range targetIPs {
		if _, exists := m.bypass[ip]; exists {
			m.extraBypass[ip] = struct{}{}
			continue
		}
		if err := m.addBypass(ip); err != nil {
			return err
		}
		m.bypass[ip] = struct{}{}
		m.extraBypass[ip] = struct{}{}
	}
	return nil
}

func (m *linuxRouteManager) Close() error {
	for ip := range m.bypass {
		m.removeBypass(ip)
	}
	m.bypass = map[string]struct{}{}
	m.nodeBypass = map[string]struct{}{}
	m.extraBypass = map[string]struct{}{}

	_ = ipRouteDeleteSpec([]string{"0.0.0.0/1", "dev", m.tunName})
	_ = ipRouteDeleteSpec([]string{"128.0.0.0/1", "dev", m.tunName})
	_, _ = runCommand("ip", "-4", "route", "del", "0.0.0.0/1")
	_, _ = runCommand("ip", "-4", "route", "del", "128.0.0.0/1")

	needRestore := false
	if _, _, dev, err := detectLinuxDefaultRoute(); err != nil {
		needRestore = true
	} else if strings.TrimSpace(dev) == "" || strings.TrimSpace(dev) == strings.TrimSpace(m.tunName) {
		needRestore = true
	}
	if !needRestore {
		return nil
	}

	if err := ipRouteReplaceDefault(strings.Fields(m.defaultV4Spec)); err != nil {
		recoverErr := m.recoverDefaultRouteFallback(err)
		if recoverErr != nil {
			return fmt.Errorf("restore default route failed: %w; fallback failed: %v", err, recoverErr)
		}
		logrus.Warnf("[Client] restore default route via cached spec failed, fallback recovered: %v", err)
	}
	return nil
}

func (m *linuxRouteManager) removeBypass(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	_, _ = runCommand("ip", "-4", "route", "del", ip+"/32")
	delete(m.bypass, ip)
}

func (m *linuxRouteManager) ensureSplitDefaultRoutes() error {
	specA := []string{"0.0.0.0/1", "dev", m.tunName}
	specB := []string{"128.0.0.0/1", "dev", m.tunName}

	if err := ipRouteReplaceSpec(specA); err != nil {
		return fmt.Errorf("add split route 0.0.0.0/1 via %s failed: %w", m.tunName, err)
	}
	if err := ipRouteReplaceSpec(specB); err != nil {
		_ = ipRouteDeleteSpec(specA)
		return fmt.Errorf("add split route 128.0.0.0/1 via %s failed: %w", m.tunName, err)
	}
	return nil
}

func (m *linuxRouteManager) recoverDefaultRouteFallback(primaryErr error) error {
	var errs []string
	if primaryErr != nil {
		errs = append(errs, primaryErr.Error())
	}

	if spec, err := detectOpenWrtWANDefaultRouteSpec(); err == nil && strings.TrimSpace(spec) != "" {
		if repErr := ipRouteReplaceDefault(strings.Fields(spec)); repErr == nil {
			return nil
		} else {
			errs = append(errs, "openwrt-wan="+repErr.Error())
		}
	}

	if spec, _, dev, err := detectLinuxDefaultRoute(); err == nil {
		if dev != "" && !isLikelyTunInterfaceName(dev) {
			if repErr := ipRouteReplaceDefault(strings.Fields(spec)); repErr == nil {
				return nil
			} else {
				errs = append(errs, "linux-detect="+repErr.Error())
			}
		}
	}

	if dev := strings.TrimSpace(m.defaultV4Dev); dev != "" && !isLikelyTunInterfaceName(dev) {
		spec := buildLinuxDefaultRouteSpec(strings.TrimSpace(m.defaultV4Via), dev)
		if repErr := ipRouteReplaceDefault(strings.Fields(spec)); repErr == nil {
			return nil
		} else {
			errs = append(errs, "cached-dev="+repErr.Error())
		}
	}

	if len(errs) == 0 {
		return fmt.Errorf("no fallback route candidate")
	}
	return errors.New(strings.Join(errs, " | "))
}

func newDarwinRouteManager(tunName string) (*darwinRouteManager, error) {
	m := &darwinRouteManager{
		tunName: tunName,
		bypass:  make(map[string]struct{}),
		bypass6: make(map[string]struct{}),
	}
	if err := m.refreshDefaultRoute(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *darwinRouteManager) ActivateForNode(server string) error {
	if err := m.refreshDefaultRoute(); err != nil {
		return err
	}
	if err := m.UpdateNode(server); err != nil {
		return err
	}
	if err := m.replaceSplitDefaultRoutes(); err != nil {
		return err
	}
	return nil
}

func (m *darwinRouteManager) refreshDefaultRoute() error {
	output, err := runCommand("route", "-n", "get", "default")
	if err != nil {
		if m.hasUsableCachedIPv4Uplink() && isDarwinRouteNotInTableText(err.Error()) {
			return nil
		}
		return fmt.Errorf("read default route failed: %w", err)
	}
	gateway, iface := parseDarwinRouteGetOutput(output)
	if iface == "" {
		if m.hasUsableCachedIPv4Uplink() && isDarwinRouteNotInTableText(output) {
			return nil
		}
		return fmt.Errorf("cannot parse default interface from route output: %q", output)
	}
	if strings.HasPrefix(strings.ToLower(iface), "utun") {
		// Never overwrite cached physical uplink with utun route.
		if m.hasUsableCachedIPv4Uplink() {
			return nil
		}
		if iface == m.tunName {
			return fmt.Errorf("default route currently points to %s and no physical uplink cached yet", iface)
		}
		return fmt.Errorf("default route currently points to %s; please disable other VPN/proxy first", iface)
	}
	m.defaultGateway = gateway
	m.defaultIf = iface

	// IPv6 default route may be absent on some networks. Keep it optional.
	m.defaultGateway6 = ""
	m.defaultIf6 = ""
	if output6, err := runCommand("route", "-n", "get", "-inet6", "default"); err == nil {
		gateway6, iface6 := parseDarwinRouteGetOutput(output6)
		if iface6 == "" {
			return nil
		}
		if strings.HasPrefix(strings.ToLower(iface6), "utun") {
			// Keep cached IPv6 uplink if present, otherwise leave IPv6 uplink empty (optional).
			if m.hasUsableCachedIPv6Uplink() {
				return nil
			}
			return nil
		}
		m.defaultGateway6 = gateway6
		m.defaultIf6 = iface6
	}
	return nil
}

func (m *darwinRouteManager) replaceSplitDefaultRoutes() error {
	_, _ = runCommand("route", "-n", "delete", "-net", "0.0.0.0/1")
	_, _ = runCommand("route", "-n", "delete", "-net", "128.0.0.0/1")

	if _, err := runCommand("route", "-n", "add", "-net", "0.0.0.0/1", "-interface", m.tunName); err != nil {
		return fmt.Errorf("add split route 0.0.0.0/1 failed: %w", err)
	}
	if _, err := runCommand("route", "-n", "add", "-net", "128.0.0.0/1", "-interface", m.tunName); err != nil {
		return fmt.Errorf("add split route 128.0.0.0/1 failed: %w", err)
	}

	// Best effort IPv6 full-route takeover.
	// Keep server bypass routes separately to avoid routing control connection back into TUN.
	_, _ = runCommand("route", "-n", "delete", "-inet6", "::/1")
	_, _ = runCommand("route", "-n", "delete", "-inet6", "8000::/1")
	if m.defaultGateway6 != "" || m.defaultIf6 != "" {
		if _, err := runCommand("route", "-n", "add", "-inet6", "::/1", "-interface", m.tunName); err != nil {
			return fmt.Errorf("add split route ::/1 failed: %w", err)
		}
		if _, err := runCommand("route", "-n", "add", "-inet6", "8000::/1", "-interface", m.tunName); err != nil {
			return fmt.Errorf("add split route 8000::/1 failed: %w", err)
		}
	}
	return nil
}

func (m *darwinRouteManager) UpdateNode(server string) error {
	target4, target6, err := resolveServerIPSets(server)
	if err != nil {
		return err
	}

	for ip := range target4 {
		if err := m.addBypass(ip); err != nil {
			return err
		}
		m.bypass[ip] = struct{}{}
	}

	for ip := range m.bypass {
		if _, exists := target4[ip]; exists {
			continue
		}
		_, _ = runCommand("route", "-n", "delete", "-host", ip)
		delete(m.bypass, ip)
	}

	if m.defaultGateway6 != "" || m.defaultIf6 != "" {
		for ip := range target6 {
			if err := m.addBypass6(ip); err != nil {
				return err
			}
			m.bypass6[ip] = struct{}{}
		}

		for ip := range m.bypass6 {
			if _, exists := target6[ip]; exists {
				continue
			}
			_, _ = runCommand("route", "-n", "delete", "-inet6", "-host", ip)
			delete(m.bypass6, ip)
		}
	}
	return nil
}

func (m *darwinRouteManager) addBypass(ip string) error {
	_, _ = runCommand("route", "-n", "delete", "-host", ip)
	var err error
	switch {
	case m.defaultGateway != "":
		_, err = runCommand("route", "-n", "add", "-host", ip, m.defaultGateway)
	case m.defaultIf != "":
		_, err = runCommand("route", "-n", "add", "-host", ip, "-interface", m.defaultIf)
	default:
		return fmt.Errorf("add bypass route for server %s failed: no default gateway/interface available", ip)
	}
	if err != nil {
		return fmt.Errorf("add bypass route for server %s failed: %w", ip, err)
	}
	return nil
}

func (m *darwinRouteManager) addBypass6(ip string) error {
	_, _ = runCommand("route", "-n", "delete", "-inet6", "-host", ip)
	var err error
	switch {
	case m.defaultGateway6 != "":
		_, err = runCommand("route", "-n", "add", "-inet6", "-host", ip, m.defaultGateway6)
	case m.defaultIf6 != "":
		_, err = runCommand("route", "-n", "add", "-inet6", "-host", ip, "-interface", m.defaultIf6)
	default:
		return fmt.Errorf("add IPv6 bypass route for server %s failed: no default gateway/interface available", ip)
	}
	if err != nil {
		return fmt.Errorf("add IPv6 bypass route for server %s failed: %w", ip, err)
	}
	return nil
}

func (m *darwinRouteManager) EnsureBypass(target string) error {
	if err := m.refreshDefaultRoute(); err != nil {
		return err
	}
	target4, target6, err := resolveTargetIPSets(target)
	if err != nil {
		return err
	}
	for ip := range target4 {
		if _, exists := m.bypass[ip]; exists {
			continue
		}
		if err := m.addBypass(ip); err != nil {
			return err
		}
		m.bypass[ip] = struct{}{}
	}
	if m.defaultGateway6 != "" || m.defaultIf6 != "" {
		for ip := range target6 {
			if _, exists := m.bypass6[ip]; exists {
				continue
			}
			if err := m.addBypass6(ip); err != nil {
				return err
			}
			m.bypass6[ip] = struct{}{}
		}
	}
	return nil
}

func (m *darwinRouteManager) Close() error {
	for ip := range m.bypass {
		_, _ = runCommand("route", "-n", "delete", "-host", ip)
	}
	m.bypass = map[string]struct{}{}
	for ip := range m.bypass6 {
		_, _ = runCommand("route", "-n", "delete", "-inet6", "-host", ip)
	}
	m.bypass6 = map[string]struct{}{}

	_, _ = runCommand("route", "-n", "delete", "-net", "0.0.0.0/1")
	_, _ = runCommand("route", "-n", "delete", "-net", "128.0.0.0/1")
	_, _ = runCommand("route", "-n", "delete", "-inet6", "::/1")
	_, _ = runCommand("route", "-n", "delete", "-inet6", "8000::/1")
	return nil
}

func parseRouteViaDev(spec string) (via, dev string) {
	fields := strings.Fields(spec)
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "via":
			via = fields[i+1]
		case "dev":
			dev = fields[i+1]
		}
	}
	return
}

func parseLinuxDefaultRouteOutput(output string) (spec, via, dev string, ok bool) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", "", "", false
	}
	candidates := make([]linuxDefaultRouteCandidate, 0, 4)
	lines := strings.Split(trimmed, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "default ") {
			spec = strings.TrimSpace(strings.TrimPrefix(line, "default"))
			via, dev = parseRouteViaDev(spec)
			if dev == "" {
				continue
			}
			via = strings.TrimSpace(strings.Trim(via, "[]"))
			if via != "" {
				parsed := net.ParseIP(via)
				if parsed == nil || parsed.To4() == nil {
					// IPv4 parser: keep candidate but drop non-IPv4 gateway (e.g. fe80::1).
					via = ""
				}
			}
			if strings.EqualFold(dev, "lo") {
				continue
			}
			spec, via = sanitizeLinuxRouteSpecIPv4(spec, via)
			spec = buildLinuxDefaultRouteSpec(via, dev)
			metric := 0
			fields := strings.Fields(line)
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "metric" {
					if m, err := strconv.Atoi(fields[i+1]); err == nil {
						metric = m
					}
					break
				}
			}
			candidates = append(candidates, linuxDefaultRouteCandidate{
				spec:   spec,
				via:    via,
				dev:    dev,
				metric: metric,
			})
			continue
		}

		// BusyBox route -n output:
		// Destination Gateway Genmask Flags Metric Ref Use Iface
		// 0.0.0.0     192.168.1.1 0.0.0.0 UG    ...       eth0
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != "0.0.0.0" {
			continue
		}
		gateway := strings.TrimSpace(fields[1])
		dev = strings.TrimSpace(fields[len(fields)-1])
		if dev == "" || strings.EqualFold(dev, "iface") {
			continue
		}
		if strings.EqualFold(dev, "lo") {
			continue
		}
		if gateway != "" && gateway != "0.0.0.0" && gateway != "*" {
			parsed := net.ParseIP(strings.Trim(gateway, "[]"))
			if parsed != nil && parsed.To4() != nil {
				via = gateway
				spec = "via " + via + " dev " + dev
			} else {
				via = ""
				spec = "dev " + dev
			}
		} else {
			via = ""
			spec = "dev " + dev
		}
		spec, via = sanitizeLinuxRouteSpecIPv4(spec, via)
		spec = buildLinuxDefaultRouteSpec(via, dev)
		metric := 0
		if m, err := strconv.Atoi(fields[4]); err == nil {
			metric = m
		}
		candidates = append(candidates, linuxDefaultRouteCandidate{
			spec:   spec,
			via:    via,
			dev:    dev,
			metric: metric,
		})
	}
	if len(candidates) == 0 {
		return "", "", "", false
	}
	best := -1
	for i, c := range candidates {
		if strings.TrimSpace(c.dev) == "" || isLikelyTunInterfaceName(c.dev) {
			continue
		}
		if best == -1 || c.metric < candidates[best].metric {
			best = i
		}
	}
	if best == -1 {
		best = 0
	}
	choice := candidates[best]
	return choice.spec, choice.via, choice.dev, true
}

func parseDarwinRouteGetOutput(output string) (gateway, iface string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "gateway:"):
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		case strings.HasPrefix(line, "interface:"):
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	return gateway, iface
}

func resolveTargetHost(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty target address")
	}

	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return "", fmt.Errorf("invalid target address: %q", target)
	}
	return host, nil
}

func resolveTargetIPSets(target string) (map[string]struct{}, map[string]struct{}, error) {
	host, err := resolveTargetHost(target)
	if err != nil {
		return nil, nil, err
	}

	ipv4Set := map[string]struct{}{}
	ipv6Set := map[string]struct{}{}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ipv4Set[ip4.String()] = struct{}{}
			return ipv4Set, ipv6Set, nil
		}
		ipv6Set[ip.String()] = struct{}{}
		return ipv4Set, ipv6Set, nil
	}

	ips, err := lookupIPsWithTimeout(host, routeResolveTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve target host %s failed: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			ipv4Set[ip4.String()] = struct{}{}
			continue
		}
		ipv6Set[ip.String()] = struct{}{}
	}
	if len(ipv4Set) == 0 && len(ipv6Set) == 0 {
		return nil, nil, fmt.Errorf("target host %s has no resolved IP address", host)
	}
	return ipv4Set, ipv6Set, nil
}

func resolveTargetIPv4Set(target string) (map[string]struct{}, error) {
	ipv4Set, _, err := resolveTargetIPSets(target)
	if err != nil {
		return nil, err
	}
	if len(ipv4Set) == 0 {
		// Linux auto_route currently manages IPv4 routes only.
		// For IPv6-only targets, skip IPv4 bypass without failing startup/runtime.
		return map[string]struct{}{}, nil
	}
	return ipv4Set, nil
}

func resolveServerIPSets(server string) (map[string]struct{}, map[string]struct{}, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid server address for tun route update: %w", err)
	}
	host = strings.Trim(host, "[]")

	ipv4Set := map[string]struct{}{}
	ipv6Set := map[string]struct{}{}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ipv4Set[ip4.String()] = struct{}{}
			return ipv4Set, ipv6Set, nil
		}
		ipv6Set[ip.String()] = struct{}{}
		return ipv4Set, ipv6Set, nil
	}

	ips, err := lookupIPsWithTimeout(host, routeResolveTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve server host %s failed: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			ipv4Set[ip4.String()] = struct{}{}
			continue
		}
		ipv6Set[ip.String()] = struct{}{}
	}
	if len(ipv4Set) == 0 && len(ipv6Set) == 0 {
		return nil, nil, fmt.Errorf("server host %s has no resolved IP address", host)
	}
	return ipv4Set, ipv6Set, nil
}

func resolveServerIPv4Set(server string) (map[string]struct{}, error) {
	ipv4Set, _, err := resolveServerIPSets(server)
	if err != nil {
		return nil, err
	}
	if len(ipv4Set) == 0 {
		// Linux auto_route currently manages IPv4 routes only.
		// For IPv6-only upstream servers, do not fail TUN startup.
		return map[string]struct{}{}, nil
	}
	return ipv4Set, nil
}

func runCommand(name string, args ...string) (string, error) {
	const cmdTimeout = 15 * time.Second
	if wait := runCommandBackoffWait(); wait > 0 {
		return "", fmt.Errorf("%s %s: delayed by fd-pressure backoff (%s)", name, strings.Join(args, " "), wait.Round(100*time.Millisecond))
	}
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	select {
	case runCommandSlots <- struct{}{}:
	case <-ctx.Done():
		return "", fmt.Errorf("%s %s: timeout waiting command slot: %w", name, strings.Join(args, " "), ctx.Err())
	}
	defer func() {
		<-runCommandSlots
	}()

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if ctx.Err() == context.DeadlineExceeded {
		if text == "" {
			return "", fmt.Errorf("%s %s: timeout after %s", name, strings.Join(args, " "), cmdTimeout)
		}
		return "", fmt.Errorf("%s %s: timeout after %s: %s", name, strings.Join(args, " "), cmdTimeout, text)
	}
	if err != nil {
		if isTooManyOpenFilesError(text, err) {
			runCommandEnterBackoff(1500 * time.Millisecond)
		}
		if text == "" {
			return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, text)
	}
	return text, nil
}

func runCommandBackoffWait() time.Duration {
	runCommandPressureMu.Lock()
	defer runCommandPressureMu.Unlock()
	if runCommandBlockedUntil.IsZero() {
		return 0
	}
	wait := time.Until(runCommandBlockedUntil)
	if wait <= 0 {
		runCommandBlockedUntil = time.Time{}
		return 0
	}
	return wait
}

func runCommandEnterBackoff(d time.Duration) {
	if d <= 0 {
		d = 1200 * time.Millisecond
	}
	now := time.Now()
	until := now.Add(d)
	runCommandPressureMu.Lock()
	if until.After(runCommandBlockedUntil) {
		runCommandBlockedUntil = until
	}
	runCommandPressureMu.Unlock()
}

func isTooManyOpenFilesError(output string, err error) bool {
	msg := strings.ToLower(strings.TrimSpace(output))
	if msg == "" && err != nil {
		msg = strings.ToLower(err.Error())
	} else if err != nil {
		msg = msg + " " + strings.ToLower(err.Error())
	}
	return strings.Contains(msg, "too many open files")
}

func sanitizeLinuxRouteSpecIPv4(spec, via string) (cleanSpec, cleanVia string) {
	spec = strings.TrimSpace(spec)
	via = strings.TrimSpace(strings.Trim(via, "[]"))
	if via == "" {
		return spec, ""
	}
	ip := net.ParseIP(via)
	if ip != nil && ip.To4() != nil {
		return spec, via
	}
	// For IPv4 route operations, drop non-IPv4 gateway tokens such as "via fe80::1".
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return spec, ""
	}
	out := make([]string, 0, len(fields))
	skipNext := false
	for _, field := range fields {
		if skipNext {
			skipNext = false
			continue
		}
		if field == "via" {
			skipNext = true
			continue
		}
		out = append(out, field)
	}
	return strings.TrimSpace(strings.Join(out, " ")), ""
}

func buildLinuxDefaultRouteSpec(via, dev string) string {
	dev = strings.TrimSpace(dev)
	via = strings.TrimSpace(strings.Trim(via, "[]"))
	if dev == "" {
		return ""
	}
	if via == "" {
		return "dev " + dev
	}
	ip := net.ParseIP(via)
	if ip == nil || ip.To4() == nil {
		return "dev " + dev
	}
	return "via " + via + " dev " + dev
}

func parseLinuxDefaultGatewayFromOutput(output string) string {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "default") {
			continue
		}
		spec := strings.TrimSpace(strings.TrimPrefix(line, "default"))
		via, _ := parseRouteViaDev(spec)
		via = strings.TrimSpace(strings.Trim(via, "[]"))
		if via == "" {
			continue
		}
		parsed := net.ParseIP(via)
		if parsed != nil && parsed.To4() != nil {
			return parsed.String()
		}
	}
	return ""
}

func detectLinuxIPv4GatewayForDev(dev string) (string, error) {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return "", fmt.Errorf("empty device")
	}
	probes := [][]string{
		{"-4", "route", "show", "default", "dev", dev},
		{"-4", "route", "show", "table", "main", "default", "dev", dev},
		{"route", "show", "default", "dev", dev},
		{"-4", "route", "show", "default"},
		{"-4", "route", "show", "table", "main", "default"},
	}
	errs := make([]string, 0, len(probes))
	for _, args := range probes {
		out, err := runCommand("ip", args...)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if gateway := parseLinuxDefaultGatewayFromOutput(out); gateway != "" {
			return gateway, nil
		}
	}
	if len(errs) == 0 {
		return "", fmt.Errorf("no ipv4 gateway found for dev %s", dev)
	}
	return "", fmt.Errorf("no ipv4 gateway found for dev %s (%s)", dev, strings.Join(errs, " | "))
}

func isRouteAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "exists")
}

func isLikelyTunInterfaceName(name string) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return false
	}
	return strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "utun") ||
		strings.HasPrefix(name, "anytls") ||
		strings.HasPrefix(name, "wg")
}

type openWrtInterfaceStatus struct {
	L3Device string `json:"l3_device"`
	Route    []struct {
		Target  string `json:"target"`
		Mask    int    `json:"mask"`
		Nexthop string `json:"nexthop"`
	} `json:"route"`
}

func parseOpenWrtWANDefaultRouteSpec(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var status openWrtInterfaceStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		return ""
	}
	dev := strings.TrimSpace(status.L3Device)
	if dev == "" || isLikelyTunInterfaceName(dev) {
		return ""
	}
	for _, route := range status.Route {
		target := strings.TrimSpace(route.Target)
		if target != "0.0.0.0" || route.Mask != 0 {
			continue
		}
		gw := strings.TrimSpace(strings.Trim(route.Nexthop, "[]"))
		if gw != "" {
			ip := net.ParseIP(gw)
			if ip != nil && ip.To4() != nil {
				return buildLinuxDefaultRouteSpec(gw, dev)
			}
		}
		return buildLinuxDefaultRouteSpec("", dev)
	}
	return buildLinuxDefaultRouteSpec("", dev)
}

func detectOpenWrtWANDefaultRouteSpec() (string, error) {
	out, err := runCommand("ubus", "call", "network.interface.wan", "status")
	if err != nil {
		return "", err
	}
	spec := parseOpenWrtWANDefaultRouteSpec(out)
	if strings.TrimSpace(spec) == "" {
		return "", fmt.Errorf("no usable WAN default route in ubus output")
	}
	return spec, nil
}

func isIPReplaceUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "replace") && (strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "unknown") ||
		strings.Contains(msg, "invalid") ||
		strings.Contains(msg, "garbage"))
}

func ipAddrReplace(cidr, dev string) error {
	if _, err := runCommand("ip", "addr", "replace", cidr, "dev", dev); err != nil {
		if !isIPReplaceUnsupportedError(err) {
			return err
		}
		_, _ = runCommand("ip", "addr", "del", cidr, "dev", dev)
		if _, addErr := runCommand("ip", "addr", "add", cidr, "dev", dev); addErr != nil {
			return fmt.Errorf("replace unsupported, fallback add failed: %w", addErr)
		}
	}
	return nil
}

func ipRouteReplaceSpec(spec []string) error {
	replaceArgs := append([]string{"-4", "route", "replace"}, spec...)
	if _, err := runCommand("ip", replaceArgs...); err != nil {
		if !isIPReplaceUnsupportedError(err) {
			return err
		}
		addArgs := append([]string{"-4", "route", "add"}, spec...)
		if _, addErr := runCommand("ip", addArgs...); addErr != nil {
			if !isRouteAlreadyExistsError(addErr) {
				return fmt.Errorf("replace unsupported, fallback add failed: %w", addErr)
			}
			delArgs := append([]string{"-4", "route", "del"}, spec...)
			_, _ = runCommand("ip", delArgs...)
			if _, addRetryErr := runCommand("ip", addArgs...); addRetryErr != nil {
				return fmt.Errorf("replace unsupported, fallback del+add failed: %w", addRetryErr)
			}
		}
	}
	return nil
}

func isRouteNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "not in table") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "network unreachable")
}

func ipRouteDeleteSpec(spec []string) error {
	delArgs := append([]string{"-4", "route", "del"}, spec...)
	if _, err := runCommand("ip", delArgs...); err != nil {
		if isRouteNotFoundError(err) {
			return nil
		}
		return err
	}
	return nil
}

func ipRouteReplaceDefault(spec []string) error {
	fullSpec := append([]string{"default"}, spec...)
	if err := ipRouteReplaceSpec(fullSpec); err != nil {
		addArgs := append([]string{"-4", "route", "add", "default"}, spec...)
		if _, addErr := runCommand("ip", addArgs...); addErr != nil {
			if !isRouteAlreadyExistsError(addErr) {
				return fmt.Errorf("fallback default route add failed: %w", addErr)
			}
			// Some busybox variants cannot parse "route del default <spec>", keep it simple.
			_, _ = runCommand("ip", "-4", "route", "del", "default")
			if _, addRetryErr := runCommand("ip", addArgs...); addRetryErr != nil {
				return fmt.Errorf("fallback default route del+add failed: %w", addRetryErr)
			}
		}
	}
	return nil
}

func lookupIPsWithTimeout(host string, timeout time.Duration) ([]net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	if timeout <= 0 {
		timeout = routeResolveTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

func isTunResourceBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "resource busy") || strings.Contains(msg, "device or resource busy")
}

func disableDarwinSystemProxies() (int, error) {
	output, err := runCommand("networksetup", "-listallnetworkservices")
	if err != nil {
		return 0, err
	}
	services := parseDarwinNetworkServices(output)
	if len(services) == 0 {
		return 0, nil
	}
	actions := []string{
		"-setwebproxystate",
		"-setsecurewebproxystate",
		"-setsocksfirewallproxystate",
		"-setautoproxystate",
		"-setproxyautodiscovery",
	}

	var ops int
	var errs []string
	for _, service := range services {
		for _, action := range actions {
			_, e := runCommand("networksetup", action, service, "off")
			if e != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): %v", service, action, e))
				continue
			}
			ops++
		}
	}
	if len(errs) > 0 {
		return ops, errors.New(strings.Join(errs, "; "))
	}
	return ops, nil
}

func parseDarwinNetworkServices(output string) []string {
	lines := strings.Split(output, "\n")
	services := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "An asterisk") {
			continue
		}
		// Disabled service entries are prefixed with '*', skip them.
		if strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}

func stopKnownDarwinProxyProcesses(excludePID int) (int, error) {
	patterns := []string{
		"[/]Applications/Surge.app/Contents/MacOS/Surge",
		"[c]lashx",
		"[c]lashx.meta",
		"[c]lash-verge",
		"[m]ihomo",
		"[s]ing-box",
		"[v]2ray",
		"[x]ray",
		"[s]tash",
	}
	targets := make(map[int]struct{})
	var errs []string
	for _, pattern := range patterns {
		pids, err := findPIDsByPattern(pattern)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", pattern, err))
			continue
		}
		for _, pid := range pids {
			if pid <= 1 || pid == excludePID {
				continue
			}
			targets[pid] = struct{}{}
		}
	}
	if len(targets) == 0 {
		if len(errs) > 0 {
			return 0, errors.New(strings.Join(errs, "; "))
		}
		return 0, nil
	}

	killed := 0
	targetList := make([]int, 0, len(targets))
	for pid := range targets {
		targetList = append(targetList, pid)
	}
	for _, pid := range targetList {
		if err := sendKillSignal(pid, "TERM"); err != nil {
			errs = append(errs, fmt.Sprintf("SIGTERM %d: %v", pid, err))
			continue
		}
		killed++
	}
	time.Sleep(600 * time.Millisecond)
	for _, pid := range targetList {
		if !isProcessAlive(pid) {
			continue
		}
		if err := sendKillSignal(pid, "KILL"); err != nil {
			errs = append(errs, fmt.Sprintf("SIGKILL %d: %v", pid, err))
		}
	}
	if len(errs) > 0 {
		return killed, errors.New(strings.Join(errs, "; "))
	}
	return killed, nil
}

func findPIDsByPattern(pattern string) ([]int, error) {
	cmd := exec.Command("pgrep", "-f", pattern)
	output, err := cmd.Output()
	if err != nil {
		// exit code 1 means no process matched
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	return parsePIDs(string(output)), nil
}

func parsePIDs(raw string) []int {
	lines := strings.Split(raw, "\n")
	out := make([]int, 0, len(lines))
	seen := map[int]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil || pid <= 1 {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		out = append(out, pid)
	}
	return out
}

func isProcessAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	cmd := exec.Command("kill", "-0", strconv.Itoa(pid))
	if err := cmd.Run(); err == nil {
		return true
	}
	return false
}

func sendKillSignal(pid int, signal string) error {
	if pid <= 1 {
		return nil
	}
	signal = strings.TrimSpace(strings.ToUpper(signal))
	if signal == "" {
		signal = "TERM"
	}
	cmd := exec.Command("kill", "-"+signal, strconv.Itoa(pid))
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.ToLower(strings.TrimSpace(string(out)))
	if strings.Contains(msg, "no such process") {
		return nil
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 && strings.Contains(msg, "no such process") {
		return nil
	}
	if msg != "" {
		return fmt.Errorf("%w (%s)", err, msg)
	}
	return err
}
