package main

import (
	"anytls/proxy"
	"anytls/util"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	tunBypassRecoverMu    sync.RWMutex
	tunBypassRecoverHook  func(server string) bool
	tunBypassActiveHook   func() bool
	tunNoRouteWarnLogger  routeWarnLogger
	tunTimeoutWarnLogger  routeWarnLogger
	tunFallbackWarnLogger routeWarnLogger
	tunLoopWarnLogger     routeWarnLogger
	inboundDropWarnLogger routeWarnLogger
	inboundFDWarnLogger   routeWarnLogger

	inboundLimitCurrent      int64
	inboundSoftLimitCurrent  int64
	inboundSlotWaitMSCurrent int64
	inboundEMFILECooldownMS  int64
	inboundPressureLevel     int64
	inboundPressureScoreX100 int64
	inboundActiveCurrent     int64
	inboundActivePeak        int64

	inboundAcceptedTotal        uint64
	inboundDroppedTotal         uint64
	inboundDroppedPressureTotal uint64
	inboundAcceptErrorTotal     uint64
	inboundAcceptEMFILETotal    uint64

	failoverProbeIntervalMSCurrent int64
	failoverProbeScaleCurrent      int64
)

func setTunBypassRecoverHook(hook func(server string) bool) {
	tunBypassRecoverMu.Lock()
	defer tunBypassRecoverMu.Unlock()
	tunBypassRecoverHook = hook
}

func setTunBypassActiveHook(hook func() bool) {
	tunBypassRecoverMu.Lock()
	defer tunBypassRecoverMu.Unlock()
	tunBypassActiveHook = hook
}

func tryRecoverTunBypass(server string) bool {
	tunBypassRecoverMu.RLock()
	hook := tunBypassRecoverHook
	tunBypassRecoverMu.RUnlock()
	if hook == nil {
		return false
	}
	return hook(server)
}

func isTunBypassRecoveryActive() bool {
	tunBypassRecoverMu.RLock()
	hook := tunBypassActiveHook
	tunBypassRecoverMu.RUnlock()
	if hook == nil {
		return false
	}
	return hook()
}

func main() {
	initClientLogCapture()

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)
	raiseClientNoFileLimit()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cleanupForceInterrupt := installForceInterruptHandler(stop)
	defer cleanupForceInterrupt()

	if len(os.Args) == 2 && isVersionArg(os.Args[1]) {
		fmt.Println(util.BuildInfo())
		return
	}
	if len(os.Args) == 1 {
		if err := runClientMenu(ctx); err != nil {
			logrus.Fatalln(err)
		}
		return
	}
	if handled, err := runPositionalMode(ctx, os.Args[1:]); handled {
		if err != nil {
			logrus.Fatalln(err)
		}
		return
	}

	mode := flag.String("mode", "run", "Run mode: run | api | cli")
	listen := flag.String("l", "127.0.0.1:1080", "socks5 listen port")
	serverAddr := flag.String("s", "", "Server address or anytls:// link")
	sni := flag.String("sni", "", "Server Name Indication")
	password := flag.String("p", "", "Password")
	egressIP := flag.String("egress-ip", "", "Server egress source IP")
	egressRule := flag.String("egress-rule", "", "Server egress rule")
	minIdleSession := flag.Int("m", 5, "Reserved min idle session")

	configPath := flag.String("config", "", "Client config file path (JSON)")
	controlAddr := flag.String("control", "", "Control address")
	controlCmd := flag.String("cmd", "", "Control command: status | list | current | switch | import | create | update | delete | backups | rollback | diagnose | stop")
	nodeName := flag.String("node", "", "Node name for startup override or switch command")
	nodeURI := flag.String("uri", "", "Node URI for import command")
	backupName := flag.String("backup", "", "Backup filename for rollback command")
	flag.Parse()

	logrus.Infoln("[Client]", util.BuildInfo())

	if *mode == "api" {
		cfgPath := *configPath
		if cfgPath == "" {
			if p, err := defaultClientConfigPath(); err == nil {
				cfgPath = p
			}
		}
		if cfgPath == "" {
			logrus.Fatalln("api mode requires -config (or valid default config dir)")
		}
		runWithAPI(ctx, cfgPath, *listen, *minIdleSession, *controlAddr, *nodeName)
		return
	}
	if *mode == "cli" {
		cfgPath := *configPath
		if cfgPath == "" {
			if p, err := defaultClientConfigPath(); err == nil {
				cfgPath = p
			}
		}
		if err := runCLI(cfgPath, *controlAddr, *controlCmd, *nodeName, *nodeURI, *backupName, clientNodeConfig{
			Server:     *serverAddr,
			Password:   *password,
			SNI:        *sni,
			EgressIP:   *egressIP,
			EgressRule: *egressRule,
		}); err != nil {
			logrus.Fatalln(err)
		}
		return
	}

	if *configPath != "" {
		runWithConfig(ctx, *configPath, listen, minIdleSession, controlAddr, controlCmd, nodeName, nodeURI)
		return
	}
	if *controlCmd != "" {
		logrus.Fatalln("-cmd requires -config")
	}

	runWithSingleNode(ctx, listen, serverAddr, sni, password, egressIP, egressRule, minIdleSession)
}

func isVersionArg(arg string) bool {
	switch strings.TrimSpace(strings.ToLower(arg)) {
	case "version", "-v", "--version", "-version":
		return true
	default:
		return false
	}
}

func installForceInterruptHandler(cancel context.CancelFunc) func() {
	sigCh := make(chan os.Signal, 2)
	done := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer close(done)
		first := <-sigCh
		logrus.Warnf("[Client] received signal %s, shutting down...", first.String())
		cancel()

		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case second := <-sigCh:
			logrus.Warnf("[Client] received second signal %s, force exiting", second.String())
			os.Exit(130)
		case <-timer.C:
		}
	}()
	return func() {
		signal.Stop(sigCh)
		select {
		case <-done:
		default:
		}
	}
}

func runWithConfig(ctx context.Context, configPath string, listen *string, minIdleSession *int, controlAddr, controlCmd, nodeName, nodeURI *string) {
	cfg, err := loadClientConfig(configPath)
	if err != nil {
		logrus.Fatalln("load config:", err)
	}

	if *listen == "127.0.0.1:1080" && cfg.Listen != "" {
		*listen = cfg.Listen
	}
	if *minIdleSession == 5 && cfg.MinIdleSession > 0 {
		*minIdleSession = cfg.MinIdleSession
	}

	effectiveControl := cfg.Control
	if *controlAddr != "" {
		effectiveControl = *controlAddr
	}
	if effectiveControl == "" {
		effectiveControl = defaultControlAddr
	}

	if *controlCmd != "" {
		switch strings.ToLower(strings.TrimSpace(*controlCmd)) {
		case "import", "add":
			name, err := upsertNodeFromURI(cfg, *nodeName, *nodeURI)
			if err != nil {
				logrus.Fatalln("import node:", err)
			}
			if err := saveClientConfig(configPath, cfg); err != nil {
				logrus.Fatalln("save config:", err)
			}
			logrus.Infoln("imported node:", name)
			return
		}
		if err := runControlCommand(effectiveControl, *controlCmd, *nodeName); err != nil {
			logrus.Fatalln(err)
		}
		return
	}

	selected := strings.TrimSpace(*nodeName)
	if selected == "" {
		selected, err = selectNodeWithArrows(cfg.Nodes, cfg.DefaultNode)
		if err != nil {
			logrus.Fatalln("select node:", err)
		}
	} else {
		if _, ok := findNodeByName(cfg.Nodes, selected); !ok {
			logrus.Fatalln("node not found:", selected)
		}
	}

	if cfg.DefaultNode != selected {
		cfg.DefaultNode = selected
		if err := saveClientConfig(configPath, cfg); err != nil {
			logrus.Warnln("save default node:", err)
		}
	}

	manager, err := newRuntimeClientManager(ctx, cfg.Nodes, selected, *minIdleSession)
	if err != nil {
		logrus.Fatalln("build client runtime:", err)
	}
	defer manager.Close()
	routingEngine, err := buildRoutingEngineWithContext(ctx, cfg.Routing, configPath)
	if err != nil {
		logrus.Fatalln("build routing rules:", err)
	}
	var mitm *mitmRuntime
	if cfg.MITM != nil && cfg.MITM.Enabled {
		mitm, err = startMITMRuntime(ctx, *cfg.MITM, *listen, routingEngine)
		if err != nil {
			logrus.Warnln("start mitm runtime:", err)
			logrus.Warnln("[Client] MITM 启动失败，已跳过 MITM；请检查 CA 文件权限或在 Web 面板重新初始化证书")
		} else {
			defer mitm.Close()
			logrus.Infoln("[Client] mitm", mitm.ListenAddr(), "hosts=", mitm.HostCount(), "url_reject=", mitm.URLRejectCount())
		}
	}

	var cfgLock sync.Mutex

	if err := startControlServer(ctx, effectiveControl, manager, func(name string) error {
		cfgLock.Lock()
		defer cfgLock.Unlock()
		cfg.DefaultNode = name
		return saveClientConfig(configPath, cfg)
	}); err != nil {
		logrus.Fatalln("start control server:", err)
	}
	if cfg.Failover != nil && cfg.Failover.Enabled {
		manager.SetAutoSwitchHook(func(from, to string) error {
			// Auto failover should only affect current runtime node.
			// Keep default_node as user-selected startup preference.
			return nil
		})
		manager.StartAutoFailover(*cfg.Failover)
		logrus.Infoln("[Client] failover enabled")
	}

	logrus.Infoln("[Client] config", configPath)
	logrus.Infoln("[Client] socks5/http", *listen, "=>", manager.CurrentNodeName())
	logrus.Infoln("[Client] control", effectiveControl)
	runClientListener(ctx, *listen, newRoutingInbound(manager, routingEngine, mitm))
}

func runWithSingleNode(ctx context.Context, listen, serverAddr, sni, password, egressIP, egressRule *string, minIdleSession *int) {
	if serverURL, err := url.Parse(*serverAddr); err == nil {
		if serverURL.Scheme == "anytls" {
			*serverAddr = serverURL.Host
			if serverURL.User != nil {
				*password = serverURL.User.Username()
			}
			query := serverURL.Query()
			*sni = query.Get("sni")
			if queryEgressIP := query.Get("egress-ip"); queryEgressIP != "" {
				*egressIP = queryEgressIP
			}
			if queryEgressRule := query.Get("egress-rule"); queryEgressRule != "" {
				*egressRule = queryEgressRule
			}
		}
	}

	if *serverAddr == "" {
		logrus.Fatalln("please set -s server address")
	}
	if *password == "" {
		logrus.Fatalln("please set -p password")
	}
	if _, _, err := net.SplitHostPort(*serverAddr); err != nil {
		logrus.Fatalln("error server address:", *serverAddr, err)
	}
	if *egressIP != "" {
		ip := net.ParseIP(*egressIP)
		if ip == nil {
			logrus.Fatalln("error egress ip:", *egressIP)
		}
		*egressIP = ip.String()
	}

	client, err := buildClientFromNode(ctx, clientNodeConfig{
		Name:       "single",
		Server:     *serverAddr,
		Password:   *password,
		SNI:        *sni,
		EgressIP:   *egressIP,
		EgressRule: *egressRule,
	}, *minIdleSession)
	if err != nil {
		logrus.Fatalln(err)
	}

	logrus.Infoln("[Client] socks5/http", *listen, "=>", *serverAddr)
	if *egressIP != "" {
		logrus.Infoln("[Client] server egress ip", *egressIP)
	}

	runClientListener(ctx, *listen, client)
}

func buildClientFromNode(ctx context.Context, node clientNodeConfig, minIdleSession int) (*myClient, error) {
	if spec, ok, err := parseSOCKSBridgeNodeURI(node.URI); ok {
		if err != nil {
			return nil, fmt.Errorf("invalid socks bridge uri: %w", err)
		}
		label := strings.TrimSpace(node.Name)
		if label == "" {
			label = node.Server
		}
		return NewSOCKSBridgeClient(label, spec, nil), nil
	} else if err != nil {
		return nil, fmt.Errorf("invalid socks bridge uri: %w", err)
	}

	if nativeSpec, ok, err := parseNativeProxyNodeURI(node.URI); ok {
		if err != nil {
			return nil, fmt.Errorf("invalid native proxy uri: %w", err)
		}
		coreSpec, err := buildExternalCoreSpecFromNativeNode(strings.TrimSpace(node.Name), nativeSpec)
		if err != nil {
			return nil, fmt.Errorf("build native external core failed: %w", err)
		}
		coreProc, err := startExternalCoreIfNeeded(ctx, strings.TrimSpace(node.Name), coreSpec)
		if err != nil {
			return nil, err
		}
		label := strings.TrimSpace(node.Name)
		if label == "" {
			label = node.Server
		}
		return NewSOCKSBridgeClient(label, coreSpec.SOCKS, coreProc.Close), nil
	} else if err != nil {
		return nil, fmt.Errorf("invalid native proxy uri: %w", err)
	}

	if coreSpec, ok, err := parseExternalCoreNodeURI(node.URI); ok {
		if err != nil {
			return nil, fmt.Errorf("invalid external core uri: %w", err)
		}
		coreProc, err := startExternalCoreIfNeeded(ctx, strings.TrimSpace(node.Name), coreSpec)
		if err != nil {
			return nil, err
		}
		label := strings.TrimSpace(node.Name)
		if label == "" {
			label = node.Server
		}
		return NewSOCKSBridgeClient(label, coreSpec.SOCKS, coreProc.Close), nil
	} else if err != nil {
		return nil, fmt.Errorf("invalid external core uri: %w", err)
	}

	if _, _, err := net.SplitHostPort(node.Server); err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         node.SNI,
		InsecureSkipVerify: true,
	}
	if tlsConfig.ServerName == "" {
		// disable SNI
		tlsConfig.ServerName = "127.0.0.1"
	}

	path := strings.TrimSpace(os.Getenv("TLS_KEY_LOG"))
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err == nil {
			tlsConfig.KeyLogWriter = f
		}
	}

	label := strings.TrimSpace(node.Name)
	if label == "" {
		label = node.Server
	} else {
		label = fmt.Sprintf("%s (%s)", label, node.Server)
	}

	return NewMyClient(ctx, func(ctx context.Context) (net.Conn, error) {
		dialUpstream := func() (net.Conn, error) {
			return proxy.SystemDialer.DialContext(ctx, "tcp", node.Server)
		}

		conn, err := dialUpstream()
		if err != nil {
			// Linux/OpenWrt may transiently lose bypass host route while TUN is active.
			// Try one-shot bypass repair and re-dial for route-unreachable/timeout errors.
			if isTunBypassRecoveryActive() && (isLikelyNoRouteError(err) || isLikelyDialTimeoutError(err)) {
				if isLikelyNoRouteError(err) {
					tunNoRouteWarnLogger.log(
						"[Client] upstream dial route unreachable, trying auto bypass repair",
						fmt.Errorf("%s: %w", node.Server, err),
					)
				} else {
					tunTimeoutWarnLogger.log(
						"[Client] upstream dial timeout, trying auto bypass repair",
						fmt.Errorf("%s: %w", node.Server, err),
					)
				}
				if tryRecoverTunBypass(node.Server) {
					conn, err = dialUpstream()
				}
			}
			if err != nil && runtime.GOOS == "linux" && isTunBypassRecoveryActive() &&
				(isLikelyNoRouteError(err) || isLikelyDialTimeoutError(err)) {
				fallbackConn, fallbackErr := dialUpstreamByLinuxPhysicalRoute(ctx, node.Server)
				if fallbackErr == nil {
					conn = fallbackConn
					err = nil
				} else {
					tunFallbackWarnLogger.log(
						"[Client] upstream physical-route fallback dial failed",
						fmt.Errorf("%s: %v", node.Server, fallbackErr),
					)
				}
			}
		}
		if err != nil {
			return nil, err
		}
		if isLikelyTunLoopAddr(conn.LocalAddr()) && isTunBypassRecoveryActive() {
			source := conn.LocalAddr()
			_ = conn.Close()
			tunLoopWarnLogger.log(
				"[Client] detected upstream route loop, trying auto bypass repair",
				fmt.Errorf("%s source=%s", node.Server, source),
			)
			if tryRecoverTunBypass(node.Server) {
				conn, err = dialUpstream()
				if err == nil && isLikelyTunLoopAddr(conn.LocalAddr()) {
					source = conn.LocalAddr()
					_ = conn.Close()
					err = fmt.Errorf("upstream route loop still exists after auto bypass repair (source=%s)", source)
				}
				if err != nil && runtime.GOOS == "linux" {
					fallbackConn, fallbackErr := dialUpstreamByLinuxPhysicalRoute(ctx, node.Server)
					if fallbackErr == nil {
						conn = fallbackConn
						err = nil
					} else {
						tunFallbackWarnLogger.log(
							"[Client] upstream physical-route fallback dial failed after loop repair",
							fmt.Errorf("%s: %v", node.Server, fallbackErr),
						)
					}
				}
				if err != nil {
					return nil, fmt.Errorf("%w; please check TUN bypass route for %s", err, node.Server)
				}
			} else {
				if runtime.GOOS == "linux" {
					fallbackConn, fallbackErr := dialUpstreamByLinuxPhysicalRoute(ctx, node.Server)
					if fallbackErr == nil {
						conn = fallbackConn
						goto tlsHandshake
					}
					tunFallbackWarnLogger.log(
						"[Client] upstream physical-route fallback dial failed without loop repair",
						fmt.Errorf("%s: %v", node.Server, fallbackErr),
					)
				}
				return nil, fmt.Errorf("upstream route loop detected (source=%s), please check TUN bypass route for %s", source, node.Server)
			}
		}

	tlsHandshake:
		tlsConn := tls.Client(conn, tlsConfig)
		handshakeCtx := ctx
		cancel := func() {}
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			handshakeCtx, cancel = context.WithTimeout(ctx, 8*time.Second)
		}
		defer cancel()
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}, minIdleSession, node.EgressIP, node.EgressRule, node.Password, label), nil
}

func isLikelyTunLoopAddr(addr net.Addr) bool {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return false
	}
	ip4 := tcpAddr.IP.To4()
	if ip4 == nil {
		return false
	}
	// 198.18.0.0/15 is commonly used by local TUN stacks.
	return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func isLikelyNoRouteError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "network unreachable")
}

func isLikelyDialTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "timeout")
}

func isLikelyTunLoopIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func resolveIPv4ForServerHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
		return "", fmt.Errorf("server host %s has no IPv4 address", host)
	}
	ips, err := lookupIPsWithTimeout(host, 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("resolve %s failed: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return "", fmt.Errorf("resolve %s failed: no IPv4 address", host)
}

func dialUpstreamByLinuxPhysicalRoute(ctx context.Context, server string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}
	host = strings.Trim(host, "[]")
	targetIPv4, err := resolveIPv4ForServerHost(host)
	if err != nil {
		return nil, err
	}
	out, err := runCommand("ip", "-4", "route", "get", targetIPv4)
	if err != nil {
		return nil, fmt.Errorf("ip route get %s failed: %w", targetIPv4, err)
	}
	_, dev, src := parseLinuxRouteGetOutput(out)
	if strings.TrimSpace(dev) == "" {
		return nil, fmt.Errorf("cannot parse route device from: %q", out)
	}
	if isLikelyTunInterfaceName(dev) {
		wanDev := ""
		wanSrc := ""
		if owrtSpec, owrtErr := detectOpenWrtWANDefaultRouteSpec(); owrtErr == nil {
			_, wanDev = parseRouteViaDev(owrtSpec)
			wanDev = strings.TrimSpace(wanDev)
		}
		if (wanDev == "" || isLikelyTunInterfaceName(wanDev)) && runtime.GOOS == "linux" {
			if _, _, fallbackDev, routeErr := detectLinuxDefaultRoute(); routeErr == nil {
				fallbackDev = strings.TrimSpace(fallbackDev)
				if fallbackDev != "" && !isLikelyTunInterfaceName(fallbackDev) {
					wanDev = fallbackDev
				}
			}
		}
		if wanDev != "" && !isLikelyTunInterfaceName(wanDev) {
			if parsedSrc := net.ParseIP(strings.TrimSpace(src)); parsedSrc != nil && parsedSrc.To4() != nil && !isLikelyTunLoopIP(parsedSrc) {
				wanSrc = parsedSrc.String()
			} else if detectedSrc, srcErr := detectLinuxIPv4SourceForDev(wanDev); srcErr == nil {
				wanSrc = detectedSrc
			}
			conn, bindErr := dialUpstreamByLinuxBoundDevice(ctx, server, wanDev, wanSrc)
			if bindErr == nil {
				return conn, nil
			}
			return nil, fmt.Errorf("route device still points to tun-like interface: %s (wan-bind fallback failed: %v)", dev, bindErr)
		}
		return nil, fmt.Errorf("route device still points to tun-like interface: %s", dev)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if parsedSrc := net.ParseIP(strings.TrimSpace(src)); parsedSrc != nil && !isLikelyTunLoopIP(parsedSrc) {
		if ip4 := parsedSrc.To4(); ip4 != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip4}
		}
	}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	if isLikelyTunLoopAddr(conn.LocalAddr()) {
		source := conn.LocalAddr()
		_ = conn.Close()
		return nil, fmt.Errorf("fallback dial still on tun source=%s", source)
	}
	return conn, nil
}

func detectLinuxIPv4SourceForDev(dev string) (string, error) {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return "", fmt.Errorf("empty device")
	}
	out, err := runCommand("ip", "-4", "addr", "show", "dev", dev)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "inet ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr := strings.TrimSpace(fields[1])
		if addr == "" {
			continue
		}
		ip := strings.TrimSpace(strings.Split(addr, "/")[0])
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil && !isLikelyTunLoopIP(parsed) {
			return parsed.String(), nil
		}
	}
	return "", fmt.Errorf("no usable ipv4 source on dev %s", dev)
}

func dialUpstreamByLinuxBoundDevice(ctx context.Context, server, dev, src string) (net.Conn, error) {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return nil, fmt.Errorf("empty bind device")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if parsedSrc := net.ParseIP(strings.TrimSpace(src)); parsedSrc != nil && !isLikelyTunLoopIP(parsedSrc) {
		if ip4 := parsedSrc.To4(); ip4 != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip4}
		}
	}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		controlErr := c.Control(func(fd uintptr) {
			sockErr = setSocketBindToDevice(fd, dev)
		})
		if controlErr != nil {
			return controlErr
		}
		return sockErr
	}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	if isLikelyTunLoopAddr(conn.LocalAddr()) {
		source := conn.LocalAddr()
		_ = conn.Close()
		return nil, fmt.Errorf("bind-device dial still on tun source=%s", source)
	}
	return conn, nil
}

func runClientListener(ctx context.Context, listen string, handler inboundHandler) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		logrus.Fatalln("listen socks5 tcp:", err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	connLimit := inboundConnLimit()
	slotWait := inboundSlotWaitTimeout()
	connSlots := make(chan struct{}, connLimit)
	resetInboundRuntimeStats(connLimit, slotWait)
	logrus.Infof("[Client] inbound connection cap: %d wait=%s (%s)", connLimit, slotWait, fdUsageSummary())
	pressureCtl := newInboundPressureController()

	acceptErrStreak := 0
	acceptEMFILECooldownUntil := time.Time{}
	for {
		if d := time.Until(acceptEMFILECooldownUntil); d > 0 {
			atomic.StoreInt64(&inboundEMFILECooldownMS, d.Milliseconds())
			timer := time.NewTimer(d)
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
			}
		} else {
			atomic.StoreInt64(&inboundEMFILECooldownMS, 0)
		}

		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			recordInboundAcceptError(err)
			// Do not terminate whole client on transient accept errors.
			// On OpenWrt/low-memory environments, short spikes (EMFILE/ENOBUFS/etc.)
			// can happen and should be retried with backoff.
			acceptErrStreak++
			backoff := time.Duration(acceptErrStreak) * 200 * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			logrus.Warnf("[Client] accept failed (streak=%d), retrying in %s: %v", acceptErrStreak, backoff, err)
			if isTooManyOpenFilesErr(err) {
				emfileCooldown := time.Duration(acceptErrStreak) * 300 * time.Millisecond
				if emfileCooldown < 800*time.Millisecond {
					emfileCooldown = 800 * time.Millisecond
				}
				if emfileCooldown > 5*time.Second {
					emfileCooldown = 5 * time.Second
				}
				until := time.Now().Add(emfileCooldown)
				if until.After(acceptEMFILECooldownUntil) {
					acceptEMFILECooldownUntil = until
				}
				atomic.StoreInt64(&inboundEMFILECooldownMS, emfileCooldown.Milliseconds())
				inboundFDWarnLogger.log("[Client] fd pressure detected", fmt.Errorf("%s cooldown=%s", fdUsageSummary(), emfileCooldown))
			}
			pressureCtl.onAcceptError(err)
			time.Sleep(backoff)
			continue
		}
		acceptErrStreak = 0
		acceptEMFILECooldownUntil = time.Time{}
		atomic.StoreInt64(&inboundEMFILECooldownMS, 0)
		atomic.AddUint64(&inboundAcceptedTotal, 1)
		if handler == nil {
			c.Close()
			continue
		}

		activeNow := len(connSlots)
		softLimit, pressureWaitCap, pressureReason, pressureLevel, pressureScore := pressureCtl.compute(connLimit)
		atomic.StoreInt64(&inboundSoftLimitCurrent, int64(softLimit))
		atomic.StoreInt64(&inboundPressureLevel, int64(pressureLevel))
		atomic.StoreInt64(&inboundPressureScoreX100, int64(pressureScore*100))
		if activeNow >= softLimit {
			// Only fast-drop when soft limit is pressure-lowered.
			// When soft==hard, allow waiting for a slot to reduce burst drop.
			pressureDrop := softLimit < connLimit
			if pressureDrop {
				atomic.AddUint64(&inboundDroppedTotal, 1)
				atomic.AddUint64(&inboundDroppedPressureTotal, 1)
				pressureCtl.onPressureDrop()
				inboundDropWarnLogger.log(
					"[Client] inbound connection dropped (pressure)",
					fmt.Errorf("active=%d soft_limit=%d hard_limit=%d %s", activeNow, softLimit, connLimit, pressureReason),
				)
				_ = c.Close()
				continue
			}
		}

		waitForInboundSlot := slotWait
		if pressureWaitCap > 0 && waitForInboundSlot > pressureWaitCap {
			waitForInboundSlot = pressureWaitCap
		}
		acquired := false
		select {
		case connSlots <- struct{}{}:
			acquired = true
		default:
			timer := time.NewTimer(waitForInboundSlot)
			select {
			case connSlots <- struct{}{}:
				acquired = true
			case <-timer.C:
			case <-ctx.Done():
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if !acquired {
			atomic.AddUint64(&inboundDroppedTotal, 1)
			pressureCtl.onPressureDrop()
			// Throttle this warning to avoid log storms under burst traffic.
			inboundDropWarnLogger.log("[Client] inbound connection dropped", fmt.Errorf("active=%d limit=%d %s", len(connSlots), connLimit, fdUsageSummary()))
			_ = c.Close()
			continue
		}
		recordInboundAcquire()
		trackInboundConn(c)
		go func(conn net.Conn) {
			defer func() {
				untrackInboundConn(conn)
				<-connSlots
				recordInboundRelease()
			}()
			handleTcpConnection(ctx, conn, handler)
		}(c)
	}
}

func resetInboundRuntimeStats(limit int, slotWait time.Duration) {
	atomic.StoreInt64(&inboundLimitCurrent, int64(limit))
	atomic.StoreInt64(&inboundSoftLimitCurrent, int64(limit))
	atomic.StoreInt64(&inboundSlotWaitMSCurrent, slotWait.Milliseconds())
	atomic.StoreInt64(&inboundEMFILECooldownMS, 0)
	atomic.StoreInt64(&inboundPressureLevel, 0)
	atomic.StoreInt64(&inboundPressureScoreX100, 0)
	atomic.StoreInt64(&inboundActiveCurrent, 0)
	atomic.StoreInt64(&inboundActivePeak, 0)
	atomic.StoreUint64(&inboundAcceptedTotal, 0)
	atomic.StoreUint64(&inboundDroppedTotal, 0)
	atomic.StoreUint64(&inboundDroppedPressureTotal, 0)
	atomic.StoreUint64(&inboundAcceptErrorTotal, 0)
	atomic.StoreUint64(&inboundAcceptEMFILETotal, 0)
}

func recordInboundAcceptError(err error) {
	atomic.AddUint64(&inboundAcceptErrorTotal, 1)
	if isTooManyOpenFilesErr(err) {
		atomic.AddUint64(&inboundAcceptEMFILETotal, 1)
	}
}

func recordInboundAcquire() {
	active := atomic.AddInt64(&inboundActiveCurrent, 1)
	for {
		peak := atomic.LoadInt64(&inboundActivePeak)
		if active <= peak {
			return
		}
		if atomic.CompareAndSwapInt64(&inboundActivePeak, peak, active) {
			return
		}
	}
}

func recordInboundRelease() {
	atomic.AddInt64(&inboundActiveCurrent, -1)
}

func inboundRuntimeStatsSnapshot() map[string]any {
	fdOpen := currentOpenFDCount()
	fdLimit := currentNoFileLimit()
	out := map[string]any{
		"limit":                  atomic.LoadInt64(&inboundLimitCurrent),
		"soft_limit":             atomic.LoadInt64(&inboundSoftLimitCurrent),
		"slot_wait_ms":           atomic.LoadInt64(&inboundSlotWaitMSCurrent),
		"emfile_cooldown_ms":     atomic.LoadInt64(&inboundEMFILECooldownMS),
		"pressure_level":         atomic.LoadInt64(&inboundPressureLevel),
		"pressure_score_x100":    atomic.LoadInt64(&inboundPressureScoreX100),
		"active":                 atomic.LoadInt64(&inboundActiveCurrent),
		"peak":                   atomic.LoadInt64(&inboundActivePeak),
		"accepted_total":         atomic.LoadUint64(&inboundAcceptedTotal),
		"dropped_total":          atomic.LoadUint64(&inboundDroppedTotal),
		"dropped_pressure_total": atomic.LoadUint64(&inboundDroppedPressureTotal),
		"accept_error_total":     atomic.LoadUint64(&inboundAcceptErrorTotal),
		"accept_emfile_total":    atomic.LoadUint64(&inboundAcceptEMFILETotal),
		"fd_usage":               fdUsageSummary(),
		"fd_open":                fdOpen,
		"fd_limit":               fdLimit,
	}
	if fdOpen < 0 {
		out["fd_open"] = nil
	}
	if fdLimit == 0 {
		out["fd_limit"] = nil
	}
	return out
}

func inboundConnLimit() int {
	const (
		minLimit                 = 128
		maxLimit                 = 8192
		defaultLimitLinuxOpenWrt = 256
		defaultLimitOther        = 1024
	)
	raw := strings.TrimSpace(os.Getenv("ANYTLS_INBOUND_MAX_CONN"))
	if raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= minLimit && n <= 32768 {
			return n
		}
	}
	if nofile := currentNoFileLimit(); nofile > 0 {
		// Keep reserved headroom for DNS/TUN/routing commands and misc goroutines.
		reserveDivisor := inboundFDReserveDivisor()
		reserveFloor := inboundFDReserveFloor()
		fdPerConn := inboundFDPerConnBudget()
		reserve := nofile / reserveDivisor
		if reserve < reserveFloor {
			reserve = reserveFloor
		}
		if nofile <= reserve+uint64(minLimit) {
			return minLimit
		}
		usable := nofile - reserve
		// Roughly 1 inbound request can consume >1 FD (inbound+upstream+epoll etc),
		// so keep the cap conservative to avoid EMFILE cascades.
		limit := int(usable / fdPerConn)
		if limit < minLimit {
			limit = minLimit
		}
		if limit > maxLimit {
			limit = maxLimit
		}
		return limit
	}
	if runtime.GOOS == "linux" && isOpenWrtRuntime() {
		return defaultLimitLinuxOpenWrt
	}
	return defaultLimitOther
}

func inboundFDPerConnBudget() uint64 {
	// On OpenWrt we default to a stricter budget to reduce EMFILE bursts.
	defaultBudget := 2
	if runtime.GOOS == "linux" && isOpenWrtRuntime() {
		defaultBudget = 3
	}
	if raw := strings.TrimSpace(os.Getenv("ANYTLS_INBOUND_FD_PER_CONN")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 8 {
			return uint64(n)
		}
	}
	return uint64(defaultBudget)
}

func inboundFDReserveDivisor() uint64 {
	if runtime.GOOS == "linux" && isOpenWrtRuntime() {
		return 3
	}
	return 4
}

func inboundFDReserveFloor() uint64 {
	if runtime.GOOS == "linux" && isOpenWrtRuntime() {
		return 192
	}
	return 128
}

func inboundSlotWaitTimeout() time.Duration {
	const (
		minMs = 100
		maxMs = 10000
	)
	if raw := strings.TrimSpace(os.Getenv("ANYTLS_INBOUND_SLOT_WAIT_MS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			if n < minMs {
				n = minMs
			}
			if n > maxMs {
				n = maxMs
			}
			return time.Duration(n) * time.Millisecond
		}
	}
	if runtime.GOOS == "linux" && isOpenWrtRuntime() {
		return 1500 * time.Millisecond
	}
	return 800 * time.Millisecond
}

func inboundAdaptiveSoftLimit(connLimit int) (int, time.Duration, string) {
	fdOpen := currentOpenFDCount()
	fdLimit := currentNoFileLimit()
	if fdOpen <= 0 || fdLimit == 0 {
		return connLimit, 0, fdUsageSummary()
	}

	fdPct := float64(fdOpen) * 100 / float64(fdLimit)
	switch {
	case fdPct >= 97:
		soft := connLimit / 4
		if soft < 64 {
			soft = 64
		}
		if soft > connLimit {
			soft = connLimit
		}
		return soft, 120 * time.Millisecond, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	case fdPct >= 94:
		soft := connLimit / 2
		if soft < 128 {
			soft = 128
		}
		if soft > connLimit {
			soft = connLimit
		}
		return soft, 250 * time.Millisecond, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	case fdPct >= 90:
		soft := (connLimit * 3) / 4
		if soft < 192 {
			soft = 192
		}
		if soft > connLimit {
			soft = connLimit
		}
		return soft, 400 * time.Millisecond, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	default:
		return connLimit, 0, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	}
}

type inboundPressureController struct {
	lastAt time.Time
	score  float64
}

func newInboundPressureController() *inboundPressureController {
	return &inboundPressureController{
		lastAt: time.Now(),
		score:  0,
	}
}

func (c *inboundPressureController) decay() {
	now := time.Now()
	if c.lastAt.IsZero() {
		c.lastAt = now
		return
	}
	elapsed := now.Sub(c.lastAt).Seconds()
	if elapsed <= 0 {
		return
	}
	// Recover aggressively once pressure eases, to avoid long over-throttling.
	c.score -= elapsed * 1.5
	if c.score < 0 {
		c.score = 0
	}
	c.lastAt = now
}

func (c *inboundPressureController) onAcceptError(err error) {
	c.decay()
	if isTooManyOpenFilesErr(err) {
		c.score += 3.0
		return
	}
	c.score += 0.4
}

func (c *inboundPressureController) onPressureDrop() {
	c.decay()
	// Keep drop feedback lightweight; FD level is the primary limiter.
	c.score += 0.15
}

func (c *inboundPressureController) compute(connLimit int) (int, time.Duration, string, int, float64) {
	c.decay()

	soft, waitCap, baseReason := inboundAdaptiveSoftLimit(connLimit)
	fdOpen := currentOpenFDCount()
	fdLimit := currentNoFileLimit()

	fdLevel := 0
	if fdOpen > 0 && fdLimit > 0 {
		fdPct := float64(fdOpen) * 100 / float64(fdLimit)
		switch {
		case fdPct >= 97:
			fdLevel = 3
		case fdPct >= 94:
			fdLevel = 2
		case fdPct >= 90:
			fdLevel = 1
		}
	}
	if c.score < 0 {
		c.score = 0
	}

	scoreLevel := 0
	switch {
	case c.score >= 25:
		scoreLevel = 3
	case c.score >= 10:
		scoreLevel = 2
	case c.score >= 3:
		scoreLevel = 1
	}
	level := fdLevel
	// Avoid score-only escalation when FD usage is not high.
	if fdLevel >= 2 && scoreLevel > level {
		level = scoreLevel
	}
	if atomic.LoadInt64(&inboundEMFILECooldownMS) > 0 && level < 3 {
		level = 3
	}
	if level <= 0 {
		return soft, waitCap, fmt.Sprintf("%s score=%.2f level=0", baseReason, c.score), 0, c.score
	}

	switch level {
	case 1:
		altSoft := (connLimit * 85) / 100
		if altSoft < 192 {
			altSoft = 192
		}
		if altSoft < soft {
			soft = altSoft
		}
		if waitCap == 0 || waitCap > 500*time.Millisecond {
			waitCap = 500 * time.Millisecond
		}
	case 2:
		altSoft := (connLimit * 65) / 100
		if altSoft < 128 {
			altSoft = 128
		}
		if altSoft < soft {
			soft = altSoft
		}
		if waitCap == 0 || waitCap > 300*time.Millisecond {
			waitCap = 300 * time.Millisecond
		}
	default:
		altSoft := (connLimit * 45) / 100
		if altSoft < 64 {
			altSoft = 64
		}
		if altSoft < soft {
			soft = altSoft
		}
		if waitCap == 0 || waitCap > 150*time.Millisecond {
			waitCap = 150 * time.Millisecond
		}
	}
	if soft > connLimit {
		soft = connLimit
	}
	if soft < 64 {
		soft = 64
	}
	reason := fmt.Sprintf("%s score=%.2f level=%d", baseReason, c.score, level)
	return soft, waitCap, reason, level, c.score
}

func isTooManyOpenFilesErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "too many open files")
}

func currentOpenFDCount() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func fdUsageSummary() string {
	limit := currentNoFileLimit()
	open := currentOpenFDCount()
	if limit == 0 || open < 0 {
		if limit > 0 {
			return fmt.Sprintf("nofile=%d", limit)
		}
		return "nofile=unknown"
	}
	pct := float64(open) * 100 / float64(limit)
	return fmt.Sprintf("fd=%d/%d(%.0f%%)", open, limit, pct)
}

func failoverRuntimeStatsSnapshot() map[string]any {
	intervalMS := atomic.LoadInt64(&failoverProbeIntervalMSCurrent)
	scale := atomic.LoadInt64(&failoverProbeScaleCurrent)
	out := map[string]any{}
	if intervalMS > 0 {
		out["probe_interval_ms"] = intervalMS
	}
	if scale > 0 {
		out["probe_interval_scale"] = scale
	}
	return out
}
