package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
)

type apiState struct {
	lock                   sync.Mutex
	authMu                 sync.RWMutex
	taskMu                 sync.Mutex
	routeSelfHealMu        sync.Mutex
	loopRepairMu           sync.Mutex
	nodeBypassCircuitMu    sync.Mutex
	ctx                    context.Context
	stopAll                context.CancelFunc
	startedAt              time.Time
	configPath             string
	activeControl          string
	activeListen           string
	cfg                    *clientProfileConfig
	manager                *runtimeClientManager
	tun                    *tunRuntime
	mitm                   *mitmRuntime
	routing                *routingEngine
	authGuard              *authAttemptGuard
	subStatus              map[string]*subscriptionRuntimeStatus
	subCancel              context.CancelFunc
	routingProviderStatus  map[string]*routingProviderRuntimeStatus
	routingGeoIPStatus     *routingProviderRuntimeStatus
	routingCancel          context.CancelFunc
	routingHits            *routingHitStore
	routingEgressProbeLast map[string]any
	dnsMap                 *dnsDomainMap
	dnsHijacker            *dnsHijacker
	nodeBypass             nodeBypassStatus
	tunAutoRecoverCancel   context.CancelFunc
	tunAutoRecoverRunning  bool
	tunAutoRecoverState    tunAutoRecoverState
	tunAutoRecoverSuspend  bool
	tunAutoRecoverReason   string
	bypassApplyRunning     bool
	bypassApplyPending     bool
	bypassApplyReason      string
	routeSelfHealEvents    []routeSelfHealEvent
	routeSelfHealLastKey   string
	routeSelfHealLastAt    time.Time
	loopRepairLast         map[string]time.Time
	loopRepairInFlight     map[string]bool
	loopRepairBlockedUntil map[string]time.Time
	loopRepairLastGlobal   time.Time
	nodeBypassFailCount    map[string]int
	nodeBypassOpenUntil    map[string]time.Time
	tasks                  map[string]*apiAsyncTask
	taskSeq                uint64
	tunTaskQueue           []tunTaskRequest
	tunTaskWorkerRunning   bool
	tunTaskWorkerLastKick  time.Time
	tunTaskWorkerLastBeat  time.Time
	tunTaskAvgDuration     time.Duration
	tunTaskGuardCancel     context.CancelFunc
	authUsername           string
	authPassword           string
}

const loopRepairCooldown = 8 * time.Second
const loopRepairBlockedFor = 45 * time.Second
const loopRepairGlobalCooldown = 12 * time.Second
const nodeBypassCircuitMax = 5 * time.Minute

type nodeBypassStatus struct {
	Total          int
	Success        int
	Failed         int
	Skipped        int
	FailedTargets  []string
	SkippedTargets []string
	UpdatedAt      string
}

type tunAutoRecoverState struct {
	LastAttemptAt string
	LastSuccessAt string
	LastError     string
}

type apiAsyncTask struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
	Result     any    `json:"result,omitempty"`
	CreatedAt  string `json:"created_at"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	QueuePos   int    `json:"queue_position,omitempty"`
	QueueTotal int    `json:"queue_total,omitempty"`
	QueueETA   int    `json:"queue_eta_seconds,omitempty"`
	ElapsedSec int    `json:"elapsed_seconds,omitempty"`
}

type tunTaskRequest struct {
	TaskID string
	Next   *clientTunConfig
}

type tunTaskQueueSnapshot struct {
	avgDuration      time.Duration
	runningTaskID    string
	runningRemaining time.Duration
	queueTotal       int
	queueIndex       map[string]int
}

type tunTaskQueueInfo struct {
	UpdatedAt           string `json:"updated_at"`
	Running             bool   `json:"running"`
	RunningTaskID       string `json:"running_task_id,omitempty"`
	RunningKind         string `json:"running_kind,omitempty"`
	RunningElapsedSec   int    `json:"running_elapsed_seconds,omitempty"`
	RunningETASeconds   int    `json:"running_eta_seconds,omitempty"`
	Pending             int    `json:"pending"`
	Total               int    `json:"total"`
	OldestPendingWait   int    `json:"oldest_pending_wait_seconds,omitempty"`
	AvgDurationSeconds  int    `json:"avg_duration_seconds,omitempty"`
	WorkerRunning       bool   `json:"worker_running"`
	WorkerStale         bool   `json:"worker_stale"`
	WorkerBeatAgoSecond int    `json:"worker_beat_ago_seconds,omitempty"`
	WorkerLastBeatAt    string `json:"worker_last_beat_at,omitempty"`
	WorkerLastKickAt    string `json:"worker_last_kick_at,omitempty"`
}

const tunPriorityWaitTimeout = 90 * time.Second
const tunPriorityPollInterval = 200 * time.Millisecond
const tunWorkerHeartbeatStaleAfter = 8 * time.Second
const tunRunningTaskStaleAfter = 20 * time.Second
const tunWorkerRestartCooldown = 2 * time.Second
const tunPendingTaskForceRestartAfter = 6 * time.Second
const tunPendingTaskHardFailAfter = 25 * time.Second

type routeSelfHealEvent struct {
	Time   string `json:"time"`
	Level  string `json:"level"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

func (s *apiState) setAuthCredential(username, password string) {
	if s == nil {
		return
	}
	s.authMu.Lock()
	s.authUsername = strings.TrimSpace(username)
	s.authPassword = password
	s.authMu.Unlock()
}

func (s *apiState) getAuthCredential() (string, string) {
	if s == nil {
		return "", ""
	}
	s.authMu.RLock()
	username := s.authUsername
	password := s.authPassword
	s.authMu.RUnlock()
	if username == "" && password == "" {
		s.lock.Lock()
		if s.cfg != nil {
			username = strings.TrimSpace(s.cfg.WebUsername)
			password = s.cfg.WebPassword
		}
		s.lock.Unlock()
		if username != "" || password != "" {
			s.authMu.Lock()
			s.authUsername = username
			s.authPassword = password
			s.authMu.Unlock()
		}
	}
	return username, password
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		switch typed := value.(type) {
		case map[string]any:
			out[key] = cloneAnyMap(typed)
		case []string:
			out[key] = append([]string(nil), typed...)
		case []any:
			out[key] = append([]any(nil), typed...)
		default:
			out[key] = value
		}
	}
	return out
}

func (s *apiState) setRoutingEgressProbeLast(result map[string]any) {
	if s == nil {
		return
	}
	s.lock.Lock()
	s.routingEgressProbeLast = cloneAnyMap(result)
	s.lock.Unlock()
}

func (s *apiState) getRoutingEgressProbeLastLocked() map[string]any {
	if s == nil {
		return nil
	}
	return cloneAnyMap(s.routingEgressProbeLast)
}

func runWithAPI(ctx context.Context, configPath, listenFlag string, minIdleFlag int, controlFlag, nodeFlag string) {
	apiCtx, stopAPI := context.WithCancel(ctx)
	defer stopAPI()

	logStep := func(step string) {
		logrus.Infoln("[Client] 启动: 正在执行", step)
	}

	logStep("读取客户端配置")
	cfg, err := loadClientConfig(configPath)
	if err != nil {
		logrus.Fatalln("load config:", err)
	}

	logStep("应用启动参数")
	if listenFlag != "" && listenFlag != "127.0.0.1:1080" {
		cfg.Listen = listenFlag
	}
	if minIdleFlag > 0 && minIdleFlag != 5 {
		cfg.MinIdleSession = minIdleFlag
	}
	if controlFlag != "" {
		cfg.Control = controlFlag
	}
	if cfg.Control == "" {
		cfg.Control = defaultControlAddr
	}

	selected := strings.TrimSpace(nodeFlag)
	if selected == "" {
		selected = cfg.DefaultNode
	}
	if _, ok := findNodeByName(cfg.Nodes, selected); !ok {
		logrus.Fatalln("node not found:", selected)
	}
	cfg.DefaultNode = selected

	logStep("写回配置文件")
	if err := saveClientConfig(configPath, cfg); err != nil {
		logrus.Fatalln("save config:", err)
	}

	logStep("初始化节点运行时")
	manager, err := newRuntimeClientManager(apiCtx, cfg.Nodes, selected, cfg.MinIdleSession)
	if err != nil {
		logrus.Fatalln("build client runtime:", err)
	}
	logStep("加载路由规则（后台预热远程规则集）")
	routingEngine, err := buildRoutingEngineFastWithContext(apiCtx, cfg.Routing, configPath)
	if err != nil {
		logrus.Fatalln("build routing rules:", err)
	}

	var tun *tunRuntime
	if cfg.Tun != nil && cfg.Tun.Enabled {
		logStep("启动 TUN")
		node, ok := findNodeByName(cfg.Nodes, selected)
		if !ok {
			logrus.Fatalln("tun init failed: selected node not found:", selected)
		}
		tun, err = startTunRuntimeWithTimeout(apiCtx, *cfg.Tun, cfg.Listen, node, 15*time.Second)
		if err != nil {
			logrus.Warnln("start tun runtime:", err)
			logrus.Warnln("[Client] TUN 启动失败，已跳过 TUN；可稍后在 Web 面板“基础配置”中手动开启 TUN")
		}
	}
	var mitm *mitmRuntime
	if cfg.MITM != nil && cfg.MITM.Enabled {
		logStep("启动 MITM")
		mitm, err = startMITMRuntime(apiCtx, *cfg.MITM, cfg.Listen, routingEngine)
		if err != nil {
			logrus.Warnln("start mitm runtime:", err)
			logrus.Warnln("[Client] MITM 启动失败，已跳过 MITM；请检查 CA 文件权限或在 Web 面板重新初始化证书")
		}
	}

	state := &apiState{
		ctx:                    apiCtx,
		stopAll:                stopAPI,
		startedAt:              time.Now(),
		configPath:             configPath,
		activeControl:          cfg.Control,
		activeListen:           cfg.Listen,
		cfg:                    cfg,
		manager:                manager,
		tun:                    tun,
		mitm:                   mitm,
		routing:                routingEngine,
		authGuard:              newAuthAttemptGuardFromEnv(),
		subStatus:              make(map[string]*subscriptionRuntimeStatus),
		routingProviderStatus:  make(map[string]*routingProviderRuntimeStatus),
		routingHits:            newRoutingHitStore(6000),
		dnsMap:                 newDNSDomainMap(),
		loopRepairLast:         make(map[string]time.Time),
		loopRepairInFlight:     make(map[string]bool),
		loopRepairBlockedUntil: make(map[string]time.Time),
		nodeBypassFailCount:    make(map[string]int),
		nodeBypassOpenUntil:    make(map[string]time.Time),
		tasks:                  make(map[string]*apiAsyncTask),
	}
	state.setAuthCredential(cfg.WebUsername, cfg.WebPassword)
	guardCtx, guardCancel := context.WithCancel(apiCtx)
	state.tunTaskGuardCancel = guardCancel
	go state.tunTaskGuardLoop(guardCtx)
	state.recordRouteSelfHealEvent("info", "api_start", "API runtime initialized")
	state.dnsHijacker = newDNSHijacker(state.dnsMap, cfg.Listen)
	setTunBypassRecoverHook(state.tryRecoverNodeBypass)
	setTunBypassActiveHook(state.isTunBypassRecoverActive)
	defer setTunBypassRecoverHook(nil)
	defer setTunBypassActiveHook(nil)
	if state.tun != nil {
		state.applyBypassRoutesAsync("startup")
	}
	state.lock.Lock()
	state.reconcileTunAutoRecoverMonitorLocked(state.cfg.Tun, "startup")
	state.lock.Unlock()
	logStep("启动订阅与规则集调度")
	state.startSubscriptionScheduler()
	state.startRoutingProviderScheduler()
	state.warmupRoutingProvidersAsync("startup")
	manager.SetAutoSwitchHook(func(from, to string) error {
		state.lock.Lock()
		if state.tun != nil {
			node, ok := findNodeByName(state.cfg.Nodes, to)
			if ok {
				if err := state.tun.OnSwitch(node); err != nil {
					state.lock.Unlock()
					return err
				}
				state.resetDNSProbeStateLocked("auto-switch")
				state.applyBypassRoutesLocked("auto-switch")
			}
		}
		state.lock.Unlock()
		state.reconnectAfterNodeSwitchLocked("auto-switch")
		logrus.Warnf("[Client] auto failover switched %s => %s", from, to)
		return nil
	})
	manager.SetFailoverExhaustHook(func(current string, failures int, cause error) {
		if cause == nil {
			return
		}
		if runtime.GOOS != "linux" {
			return
		}
		msg := strings.ToLower(cause.Error())
		if !strings.Contains(msg, "no healthy fallback node") {
			return
		}
		go state.failOpenDisableTun(current, failures, cause)
	})
	if cfg.Failover != nil && cfg.Failover.Enabled {
		manager.StartAutoFailover(*cfg.Failover)
		logrus.Infoln("[Client] failover enabled")
	}
	defer manager.Close()
	defer func() {
		if state.tunTaskGuardCancel != nil {
			state.tunTaskGuardCancel()
		}
	}()
	defer state.stopSubscriptionScheduler()
	defer state.stopRoutingProviderScheduler()
	defer func() {
		state.lock.Lock()
		state.stopTunAutoRecoverMonitorLocked("shutdown")
		state.lock.Unlock()
		if state.tun != nil {
			if err := state.tun.Close(); err != nil {
				logrus.Warnln("close tun runtime:", err)
			}
		}
		if state.mitm != nil {
			if err := state.mitm.Close(); err != nil {
				logrus.Warnln("close mitm runtime:", err)
			}
		}
	}()
	logStep("启动本地 API 服务")
	if err := startHTTPAPIServer(cfg.Control, state); err != nil {
		logrus.Fatalln("start api:", err)
	}

	logrus.Infoln("[Client] 启动: 完成")
	logrus.Infoln("[Client] mode api")
	logrus.Infoln("[Client] config", configPath)
	logrus.Infoln("[Client] socks5/http", cfg.Listen, "=>", manager.CurrentNodeName())
	logrus.Infoln("[Client] api", cfg.Control)
	logrus.Infoln("[Client] web", "http://"+cfg.Control+"/ui/")
	if cfg.Routing != nil && cfg.Routing.Enabled {
		logrus.Infoln("[Client] routing", "enabled rules=", len(cfg.Routing.Rules), "providers=", len(cfg.Routing.RuleProviders))
	}
	if state.tun != nil {
		logrus.Infoln("[Client] tun", cfg.Tun.Name, "auto_route=", cfg.Tun.AutoRoute, "address=", cfg.Tun.Address)
	}
	if state.mitm != nil {
		logrus.Infoln("[Client] mitm", state.mitm.ListenAddr(), "hosts=", state.mitm.HostCount(), "url_reject=", state.mitm.URLRejectCount())
	}
	runClientListener(apiCtx, cfg.Listen, newStateRoutingInbound(state))
}

func (s *apiState) failOpenDisableTun(current string, failures int, cause error) {
	if s == nil {
		return
	}
	var saveErr error
	s.lock.Lock()
	if s.tun == nil {
		s.lock.Unlock()
		return
	}
	tun := s.tun
	s.tun = nil
	if s.cfg != nil && s.cfg.Tun != nil {
		s.cfg.Tun.Enabled = false
		saveErr = saveClientConfig(s.configPath, s.cfg)
	}
	s.tunAutoRecoverSuspend = true
	s.tunAutoRecoverReason = "failover exhausted: waiting manual node switch or manual tun enable"
	s.tunAutoRecoverState.LastError = "自动恢复已暂停：故障切换无可用节点，请先切换到可用节点后再开启 TUN"
	s.stopTunAutoRecoverMonitorLocked("failover-exhausted")
	manager := s.manager
	s.lock.Unlock()

	logrus.Warnf("[Client] failover exhausted (node=%s failures=%d cause=%v), fail-open: disabling TUN to keep host connectivity", current, failures, cause)
	if saveErr != nil {
		logrus.Warnln("[Client] fail-open persist tun disabled failed:", saveErr)
		s.recordRouteSelfHealEvent("warn", "fail_open_persist_failed", saveErr.Error())
	}
	s.recordRouteSelfHealEvent("warn", "failover_exhausted", fmt.Sprintf("node=%s failures=%d cause=%v", current, failures, cause))
	if err := closeTunRuntimeWithTimeout(tun, 6*time.Second); err != nil {
		logrus.Warnln("[Client] fail-open disable tun cleanup warning:", err)
		s.recordRouteSelfHealEvent("warn", "fail_open_cleanup", err.Error())
	}
	if manager != nil {
		if err := resetManagerClientsWithTimeout(manager, 8*time.Second); err != nil {
			logrus.Warnln("[Client] fail-open reset clients failed:", err)
			s.recordRouteSelfHealEvent("warn", "fail_open_reset_clients", err.Error())
		}
	}
	logrus.Warnln("[Client] fail-open completed: TUN disabled; please select a healthy node then re-enable TUN")
	s.recordRouteSelfHealEvent("info", "fail_open_completed", "TUN disabled to keep host connectivity")
}

func startHTTPAPIServer(addr string, state *apiState) error {
	mux := http.NewServeMux()
	requireAuth := state.wrapAuth

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
		})
	})
	mux.HandleFunc("/api/v1/current", requireAuth(state.handleCurrent))
	mux.HandleFunc("/api/v1/switch", requireAuth(state.handleSwitch))
	mux.HandleFunc("/api/v1/config", requireAuth(state.handleConfig))
	mux.HandleFunc("/api/v1/nodes/import", requireAuth(state.handleImportNode))
	mux.HandleFunc("/api/v1/nodes", requireAuth(state.handleNodes))
	mux.HandleFunc("/api/v1/nodes/export", requireAuth(state.handleNodeExport))
	mux.HandleFunc("/api/v1/nodes/", requireAuth(state.handleNodeByName))
	mux.HandleFunc("/api/v1/config/backups", requireAuth(state.handleConfigBackups))
	mux.HandleFunc("/api/v1/config/rollback", requireAuth(state.handleConfigRollback))
	mux.HandleFunc("/api/v1/test/latency", requireAuth(state.handleTestLatency))
	mux.HandleFunc("/api/v1/test/bandwidth", requireAuth(state.handleTestBandwidth))
	mux.HandleFunc("/api/v1/diagnose", requireAuth(state.handleDiagnose))
	mux.HandleFunc("/api/v1/route/check", requireAuth(state.handleRouteCheck))
	mux.HandleFunc("/api/v1/route/selfheal", requireAuth(state.handleRouteSelfHeal))
	mux.HandleFunc("/api/v1/status", requireAuth(state.handleStatus))
	mux.HandleFunc("/api/v1/routing/update", requireAuth(state.handleRoutingUpdate))
	mux.HandleFunc("/api/v1/routing/providers", requireAuth(state.handleRoutingProviders))
	mux.HandleFunc("/api/v1/routing/probe", requireAuth(state.handleRoutingProbe))
	mux.HandleFunc("/api/v1/routing/match", requireAuth(state.handleRoutingMatch))
	mux.HandleFunc("/api/v1/routing/egress_probe", requireAuth(state.handleRoutingEgressProbe))
	mux.HandleFunc("/api/v1/routing/hits", requireAuth(state.handleRoutingHits))
	mux.HandleFunc("/api/v1/routing/hits/clear", requireAuth(state.handleRoutingHitsClear))
	mux.HandleFunc("/api/v1/mitm/ca", requireAuth(state.handleMITMCA))
	mux.HandleFunc("/api/v1/mitm/ca/status", requireAuth(state.handleMITMCAStatus))
	mux.HandleFunc("/api/v1/mitm/ca/install", requireAuth(state.handleMITMCAInstall))
	mux.HandleFunc("/api/v1/mitm/ca/install.sh", requireAuth(state.handleMITMCAInstallScript))
	mux.HandleFunc("/api/v1/openwrt/dns/repair", requireAuth(state.handleOpenWrtDNSRepair))
	mux.HandleFunc("/api/v1/tasks", requireAuth(state.handleTask))
	mux.HandleFunc("/api/v1/tasks/", requireAuth(state.handleTask))
	mux.HandleFunc("/api/v1/logs", requireAuth(state.handleLogs))
	mux.HandleFunc("/api/v1/logs/clear", requireAuth(state.handleLogsClear))
	mux.HandleFunc("/api/v1/subscriptions", requireAuth(state.handleSubscriptions))
	mux.HandleFunc("/api/v1/subscriptions/update", requireAuth(state.handleSubscriptionUpdate))
	mux.HandleFunc("/api/v1/subscriptions/", requireAuth(state.handleSubscriptionByID))
	mux.HandleFunc("/api/v1/shutdown", requireAuth(state.handleShutdown))
	mux.HandleFunc("/ui", state.handleWebUI)
	mux.HandleFunc("/ui/", state.handleWebUI)
	mux.HandleFunc("/", state.handleRoot)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		if isAddrInUseError(err) {
			if pingErr := probeAPIHealth(addr); pingErr == nil {
				return fmt.Errorf("listen tcp %s: address already in use (anytls-client api is already running, open http://%s/ui/ or use `anytls-client cli --control %s`)", addr, addr, addr)
			}
			return fmt.Errorf("listen tcp %s: address already in use (possibly occupied by another process/user)", addr)
		}
		return err
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logrus.Errorln("api serve:", err)
		}
	}()
	go func() {
		<-state.ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	return nil
}

func (s *apiState) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "shutdown requested",
	})
	go func() {
		time.Sleep(120 * time.Millisecond)
		if s.stopAll != nil {
			s.stopAll()
		}
	}()
}

func isAddrInUseError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return strings.Contains(strings.ToLower(opErr.Err.Error()), "address already in use")
	}
	return strings.Contains(strings.ToLower(err.Error()), "address already in use")
}

func probeAPIHealth(addr string) error {
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	resp, err := client.Get(apiURL(addr, "/api/v1/health"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return nil
	}
	return fmt.Errorf("health check status: %d", resp.StatusCode)
}

func (s *apiState) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusFound)
}

func (s *apiState) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.lock.Lock()
		defer s.lock.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"config_path": s.configPath,
			"current":     s.manager.CurrentNodeName(),
			"config":      s.cfg,
		})
	case http.MethodPut:
		var req struct {
			Listen         *string               `json:"listen"`
			MinIdleSession *int                  `json:"min_idle_session"`
			Control        *string               `json:"control"`
			WebUsername    *string               `json:"web_username"`
			WebPassword    *string               `json:"web_password"`
			DefaultNode    *string               `json:"default_node"`
			Routing        *clientRoutingConfig  `json:"routing"`
			Tun            *clientTunConfig      `json:"tun"`
			MITM           *clientMITMConfig     `json:"mitm"`
			Failover       *clientFailoverConfig `json:"failover"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.lock.Lock()
		defer s.lock.Unlock()
		prevTun := cloneTunConfig(s.cfg.Tun)
		prevMITM := cloneMITMConfig(s.cfg.MITM)
		prevRouting := cloneRoutingConfig(s.cfg.Routing)
		prevRoutingEngine := s.routing

		restartRequired := false
		triggerRoutingWarmup := false
		triggerRoutingReconnect := false
		triggerNodeSwitchReconnect := false
		var queuedTun *clientTunConfig
		if req.Listen != nil {
			next := strings.TrimSpace(*req.Listen)
			if next == "" {
				writeError(w, http.StatusBadRequest, "listen cannot be empty")
				return
			}
			if next != s.cfg.Listen {
				s.cfg.Listen = next
				restartRequired = true
			}
		}
		if req.Control != nil {
			next := strings.TrimSpace(*req.Control)
			if next == "" {
				writeError(w, http.StatusBadRequest, "control cannot be empty")
				return
			}
			if next != s.cfg.Control {
				s.cfg.Control = next
				restartRequired = true
			}
		}
		if req.WebUsername != nil {
			s.cfg.WebUsername = strings.TrimSpace(*req.WebUsername)
		}
		if req.WebPassword != nil {
			s.cfg.WebPassword = strings.TrimSpace(*req.WebPassword)
		}
		if req.MinIdleSession != nil {
			if *req.MinIdleSession <= 0 {
				writeError(w, http.StatusBadRequest, "min_idle_session must be > 0")
				return
			}
			s.cfg.MinIdleSession = *req.MinIdleSession
			restartRequired = true
		}
		if req.Tun != nil {
			nextTun := cloneTunConfig(req.Tun)
			if nextTun != nil {
				if err := normalizeTunConfig(nextTun); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			s.cfg.Tun = nextTun
			queuedTun = cloneTunConfig(nextTun)
		}
		if req.Failover != nil {
			s.cfg.Failover = req.Failover
			normalizeFailoverConfig(s.cfg.Failover)
			s.manager.StartAutoFailover(*s.cfg.Failover)
		}
		if req.Routing != nil {
			nextRouting := cloneRoutingConfig(req.Routing)
			if nextRouting != nil {
				if err := normalizeRoutingConfig(nextRouting); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			nextEngine, err := buildRoutingEngineFastWithContext(r.Context(), nextRouting, s.configPath)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.cfg.Routing = nextRouting
			s.routing = nextEngine
			s.syncRoutingProviderStatusLocked()
			s.syncRoutingGeoIPStatusLocked()
			triggerRoutingWarmup = true
			triggerRoutingReconnect = routingReconnectRequired(prevRouting, nextRouting)
			if s.cfg.MITM != nil && s.cfg.MITM.Enabled {
				if _, err := s.reconcileMITMLocked(s.cfg.MITM); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
		}
		if req.MITM != nil {
			nextMITM := cloneMITMConfig(req.MITM)
			if nextMITM != nil {
				if err := normalizeMITMConfig(nextMITM); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			if _, err := s.reconcileMITMLocked(nextMITM); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.cfg.MITM = nextMITM
		}

		if req.DefaultNode != nil {
			target := strings.TrimSpace(*req.DefaultNode)
			if target == "" {
				writeError(w, http.StatusBadRequest, "default_node cannot be empty")
				return
			}
			if _, ok := findNodeByName(s.cfg.Nodes, target); !ok {
				writeError(w, http.StatusNotFound, "node not found")
				return
			}
			prev := s.manager.CurrentNodeName()
			if prev != target {
				if err := s.manager.Switch(target); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				if s.tun != nil {
					node, _ := findNodeByName(s.cfg.Nodes, target)
					if err := s.tun.OnSwitch(node); err != nil {
						_ = s.manager.Switch(prev)
						writeError(w, http.StatusBadRequest, err.Error())
						return
					}
					s.resetDNSProbeStateLocked("config-default-node")
					s.applyBypassRoutesLocked("config-default-node")
				}
				triggerNodeSwitchReconnect = true
			}
			s.cfg.DefaultNode = target
		}

		if err := saveClientConfig(s.configPath, s.cfg); err != nil {
			if req.Tun != nil {
				s.cfg.Tun = prevTun
			}
			if req.Routing != nil {
				s.cfg.Routing = prevRouting
				s.routing = prevRoutingEngine
				s.syncRoutingProviderStatusLocked()
				s.syncRoutingGeoIPStatusLocked()
			}
			if req.MITM != nil {
				_, _ = s.reconcileMITMLocked(prevMITM)
				s.cfg.MITM = prevMITM
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.setAuthCredential(s.cfg.WebUsername, s.cfg.WebPassword)
		tunTaskID := ""
		if queuedTun != nil {
			tunTaskID = s.enqueueTunTask(queuedTun)
		}
		if triggerRoutingWarmup {
			s.warmupRoutingProvidersAsync("routing config changed")
		}
		if triggerRoutingReconnect {
			s.reconnectAfterRoutingChangeLocked("routing-updated")
		}
		if triggerNodeSwitchReconnect {
			s.reconnectAfterNodeSwitchLocked("default-node-updated")
		}
		resp := map[string]any{
			"saved":            true,
			"restart_required": restartRequired,
			"current":          s.manager.CurrentNodeName(),
			"config":           s.cfg,
		}
		if tunTaskID != "" {
			resp["tun_task_id"] = tunTaskID
			resp["tun_task_status"] = "pending"
			resp["tun_task_async"] = true
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *apiState) enqueueTunTask(next *clientTunConfig) string {
	if s == nil {
		return ""
	}
	req := tunTaskRequest{
		Next: cloneTunConfig(next),
	}
	s.taskMu.Lock()
	// Coalesce queued (not yet running) TUN requests to the latest one.
	// This prevents long pending chains when users toggle repeatedly.
	now := time.Now().Format(time.RFC3339)
	for _, queued := range s.tunTaskQueue {
		if task, ok := s.tasks[queued.TaskID]; ok && task != nil {
			if strings.EqualFold(task.Status, "pending") {
				task.Status = "failed"
				task.Error = "superseded by newer tun request"
				task.Message = "superseded"
				task.FinishedAt = now
			}
		}
	}
	s.tunTaskQueue = s.tunTaskQueue[:0]

	task := s.createTaskLocked("tun_toggle", "queued")
	req.TaskID = task.ID
	s.tunTaskQueue = append(s.tunTaskQueue, req)
	queueLen := len(s.tunTaskQueue)
	startWorker := s.ensureTunTaskWorkerLocked(true)
	if !startWorker && !s.hasRunningTunTaskLocked() {
		now := time.Now()
		s.tunTaskWorkerRunning = true
		s.tunTaskWorkerLastKick = now
		s.tunTaskWorkerLastBeat = now
		startWorker = true
		task.Message = "queued (force start worker)"
	}
	s.taskMu.Unlock()

	logrus.Infof("[Client] tun task enqueued: id=%s queue_len=%d start_worker=%v", req.TaskID, queueLen, startWorker)
	if startWorker {
		go s.runTunTaskWorker()
	} else {
		// Worker state may be stale (e.g. previous goroutine exited unexpectedly).
		// Schedule a delayed kick so new TUN tasks won't stay pending forever.
		s.scheduleTunTaskWorkerKick(2 * time.Second)
	}
	go s.watchTunTaskStart(req.TaskID)
	return req.TaskID
}

func (s *apiState) watchTunTaskStart(taskID string) {
	if s == nil {
		return
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return
	}
	startedAt := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()
		var (
			status          string
			inQueue         bool
			hasFreshRunning bool
			shouldStart     bool
			hardFail        bool
			hardFailError   string
		)

		s.taskMu.Lock()
		task, ok := s.tasks[taskID]
		if !ok || task == nil {
			s.taskMu.Unlock()
			return
		}
		status = strings.ToLower(strings.TrimSpace(task.Status))
		if status == "running" || status == "success" || status == "failed" {
			s.taskMu.Unlock()
			return
		}
		for _, req := range s.tunTaskQueue {
			if strings.TrimSpace(req.TaskID) == taskID {
				inQueue = true
				break
			}
		}
		for id, item := range s.tasks {
			if item == nil || id == taskID || !strings.EqualFold(strings.TrimSpace(item.Kind), "tun_toggle") {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(item.Status), "running") {
				continue
			}
			startedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(item.StartedAt))
			if err != nil {
				hasFreshRunning = true
				break
			}
			if now.Sub(startedAt) < tunRunningTaskStaleAfter {
				hasFreshRunning = true
				break
			}
		}
		waited := now.Sub(startedAt)
		if inQueue && !hasFreshRunning && waited >= tunPendingTaskForceRestartAfter {
			task.Message = "queued too long, force restarting worker"
			task.Error = ""
			s.tunTaskWorkerRunning = false
			shouldStart = s.ensureTunTaskWorkerLocked(true)
		}
		if inQueue && !hasFreshRunning && waited >= tunPendingTaskHardFailAfter {
			trimmed := s.tunTaskQueue[:0]
			for _, req := range s.tunTaskQueue {
				if strings.TrimSpace(req.TaskID) == taskID {
					continue
				}
				trimmed = append(trimmed, req)
			}
			s.tunTaskQueue = trimmed
			task.Status = "failed"
			task.Message = "queue timeout"
			task.Error = fmt.Sprintf("tun task stuck in queue for %ds, worker unresponsive", int(waited.Seconds()))
			task.FinishedAt = now.Format(time.RFC3339)
			hardFail = true
			hardFailError = task.Error
		}
		s.taskMu.Unlock()

		if shouldStart {
			logrus.Warnf("[Client] tun task queue watchdog kicked worker: id=%s waited=%s", taskID, waited.Round(time.Second))
			go s.runTunTaskWorker()
		}
		if hardFail {
			logrus.Errorf("[Client] tun task queue watchdog failed task: id=%s err=%s", taskID, hardFailError)
			return
		}
	}
}

func (s *apiState) scheduleTunTaskWorkerKick(delay time.Duration) {
	if s == nil {
		return
	}
	if delay <= 0 {
		delay = time.Second
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
		}
		s.taskMu.Lock()
		startWorker := s.ensureTunTaskWorkerLocked(true)
		s.taskMu.Unlock()
		if startWorker {
			logrus.Warnln("[Client] delayed tun task worker kick: restarting worker")
			go s.runTunTaskWorker()
		}
	}()
}

func (s *apiState) tunTaskGuardLoop(ctx context.Context) {
	if s == nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.taskMu.Lock()
		needKick := len(s.tunTaskQueue) > 0 || s.hasActiveTunTaskLocked()
		startWorker := false
		if needKick {
			startWorker = s.ensureTunTaskWorkerLocked(true)
		}
		s.taskMu.Unlock()
		if startWorker {
			logrus.Warnln("[Client] tun task guard: restarting worker")
			go s.runTunTaskWorker()
		}
	}
}

func (s *apiState) runTunTaskWorker() {
	logrus.Debugln("[Client] tun task worker started")
	defer func() {
		if v := recover(); v != nil {
			logrus.Errorf("[Client] tun task worker panic: %v", v)
		}
		s.taskMu.Lock()
		s.tunTaskWorkerRunning = false
		needRestart := len(s.tunTaskQueue) > 0
		if needRestart {
			s.tunTaskWorkerRunning = true
		}
		s.taskMu.Unlock()
		if needRestart {
			logrus.Warnln("[Client] tun task worker restarting due pending queue")
			go s.runTunTaskWorker()
		}
		logrus.Debugln("[Client] tun task worker stopped")
	}()

	for {
		s.taskMu.Lock()
		s.tunTaskWorkerLastBeat = time.Now()
		s.taskMu.Unlock()

		req, ok := s.takeNextTunTask()
		if !ok {
			return
		}

		logrus.Infof("[Client] tun task worker picked task: id=%s", req.TaskID)
		s.updateTaskProgress(req.TaskID, "开始执行 TUN 切换")
		err := s.applyTunTask(req.TaskID, req.Next)
		if err != nil {
			s.completeTask(req.TaskID, nil, err, "apply failed")
			logrus.Warnf("[Client] tun task worker apply failed: id=%s err=%v", req.TaskID, err)
		} else {
			s.completeTask(req.TaskID, map[string]any{"applied": true}, nil, "applied")
			logrus.Infof("[Client] tun task worker apply success: id=%s", req.TaskID)
		}

		s.taskMu.Lock()
		s.tunTaskWorkerLastBeat = time.Now()
		s.taskMu.Unlock()
	}
}

func (s *apiState) takeNextTunTask() (tunTaskRequest, bool) {
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	if len(s.tunTaskQueue) == 0 {
		s.tunTaskWorkerRunning = false
		return tunTaskRequest{}, false
	}
	req := s.tunTaskQueue[0]
	s.tunTaskQueue = s.tunTaskQueue[1:]
	if task, ok := s.tasks[req.TaskID]; ok && task != nil {
		task.Status = "running"
		task.Message = "applying"
		task.Error = ""
		task.StartedAt = time.Now().Format(time.RFC3339)
	}
	return req, true
}

// ensureTunTaskWorkerLocked makes sure TUN task worker is alive.
// Caller must hold s.taskMu. Returns true when caller should start a worker goroutine.
func (s *apiState) ensureTunTaskWorkerLocked(allowStaleKick bool) bool {
	if s == nil || len(s.tunTaskQueue) == 0 {
		return false
	}
	if !s.tunTaskWorkerRunning {
		s.tunTaskWorkerRunning = true
		s.tunTaskWorkerLastKick = time.Now()
		s.tunTaskWorkerLastBeat = s.tunTaskWorkerLastKick
		return true
	}
	if !allowStaleKick {
		return false
	}
	hasRunning := false
	runningTaskIDs := make([]string, 0, 2)
	oldestRunning := time.Time{}
	oldestPending := time.Time{}
	for _, task := range s.tasks {
		if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(task.Status))
		switch status {
		case "running":
			hasRunning = true
			runningTaskIDs = append(runningTaskIDs, task.ID)
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(task.StartedAt)); err == nil {
				if oldestRunning.IsZero() || t.Before(oldestRunning) {
					oldestRunning = t
				}
			}
		case "pending":
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(task.CreatedAt))
			if err != nil {
				continue
			}
			if oldestPending.IsZero() || t.Before(oldestPending) {
				oldestPending = t
			}
		}
	}
	if hasRunning {
		now := time.Now()
		workerStale := !s.tunTaskWorkerRunning || (!s.tunTaskWorkerLastBeat.IsZero() && now.Sub(s.tunTaskWorkerLastBeat) > tunWorkerHeartbeatStaleAfter)
		runningTooLong := oldestRunning.IsZero() || now.Sub(oldestRunning) > tunRunningTaskStaleAfter
		if !allowStaleKick || !workerStale || !runningTooLong {
			// Worker may still be processing a running task; wait.
			return false
		}

		// Force-clear stale running records so pending tasks can continue.
		finishedAt := now.Format(time.RFC3339)
		for _, taskID := range runningTaskIDs {
			if task, ok := s.tasks[taskID]; ok && task != nil {
				task.Status = "failed"
				task.Message = "worker stalled, auto recovered"
				task.Error = "tun task worker stalled; auto-recovered, please retry"
				task.FinishedAt = finishedAt
			}
		}
		s.tunTaskWorkerRunning = false
		s.tunTaskWorkerLastBeat = now
		logrus.Warnln("[Client] detected stalled tun running task, cleared stale state and restarting worker")
	}
	if oldestPending.IsZero() {
		// Queue exists but no running/pending task record => stale worker state.
		now := time.Now()
		if !s.tunTaskWorkerLastKick.IsZero() && now.Sub(s.tunTaskWorkerLastKick) < tunWorkerRestartCooldown {
			return false
		}
		logrus.Warnln("[Client] detected stale tun task worker state, restarting worker")
		s.tunTaskWorkerRunning = true
		s.tunTaskWorkerLastKick = now
		return true
	}
	now := time.Now()
	if !oldestPending.IsZero() && now.Sub(oldestPending) > tunPendingTaskForceRestartAfter {
		// Pending for too long while no running task means worker state is likely stale.
		// Force a worker restart proactively to avoid UI "queued forever".
		beatStale := s.tunTaskWorkerLastBeat.IsZero() || now.Sub(s.tunTaskWorkerLastBeat) > 2*time.Second
		if beatStale {
			logrus.Warnln("[Client] detected long-pending tun task, force restarting task worker")
			s.tunTaskWorkerRunning = true
			s.tunTaskWorkerLastKick = now
			s.tunTaskWorkerLastBeat = now
			return true
		}
	}
	// If worker heartbeat is stale while queue still pending, restart quickly.
	if !s.tunTaskWorkerLastBeat.IsZero() && now.Sub(s.tunTaskWorkerLastBeat) > tunWorkerHeartbeatStaleAfter {
		logrus.Warnln("[Client] detected stale tun task worker heartbeat, restarting task worker")
		s.tunTaskWorkerRunning = true
		s.tunTaskWorkerLastKick = now
		s.tunTaskWorkerLastBeat = now
		return true
	}
	if now.Sub(oldestPending) < 2*time.Second {
		return false
	}
	if !s.tunTaskWorkerLastKick.IsZero() && now.Sub(s.tunTaskWorkerLastKick) < tunWorkerRestartCooldown {
		return false
	}
	logrus.Warnln("[Client] detected stale tun task queue, restarting task worker")
	s.tunTaskWorkerRunning = true
	s.tunTaskWorkerLastKick = now
	return true
}

func (s *apiState) buildTunTaskQueueSnapshotLocked(now time.Time) tunTaskQueueSnapshot {
	snap := tunTaskQueueSnapshot{
		avgDuration: s.tunTaskAvgDuration,
		queueIndex:  make(map[string]int, len(s.tunTaskQueue)),
	}
	if snap.avgDuration <= 0 {
		snap.avgDuration = 20 * time.Second
	}

	var runningStart time.Time
	for _, task := range s.tasks {
		if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") || !strings.EqualFold(task.Status, "running") {
			continue
		}
		if snap.runningTaskID == "" {
			snap.runningTaskID = task.ID
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(task.StartedAt)); err == nil {
				runningStart = t
			}
			continue
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(task.StartedAt))
		if err != nil {
			continue
		}
		if runningStart.IsZero() || t.Before(runningStart) {
			snap.runningTaskID = task.ID
			runningStart = t
		}
	}

	if snap.runningTaskID != "" {
		elapsed := time.Duration(0)
		if !runningStart.IsZero() && now.After(runningStart) {
			elapsed = now.Sub(runningStart)
		}
		snap.runningRemaining = snap.avgDuration - elapsed
		if snap.runningRemaining <= 0 {
			snap.runningRemaining = time.Second
		}
	}

	for idx, req := range s.tunTaskQueue {
		taskID := strings.TrimSpace(req.TaskID)
		if taskID == "" {
			continue
		}
		snap.queueIndex[taskID] = idx + 1
	}
	snap.queueTotal = len(snap.queueIndex)
	if snap.runningTaskID != "" {
		snap.queueTotal++
	}
	return snap
}

func (s *apiState) buildTunTaskQueueInfoLocked(now time.Time, snap tunTaskQueueSnapshot) tunTaskQueueInfo {
	info := tunTaskQueueInfo{
		UpdatedAt:          now.Format(time.RFC3339),
		Running:            snap.runningTaskID != "",
		RunningTaskID:      snap.runningTaskID,
		Pending:            len(snap.queueIndex),
		Total:              snap.queueTotal,
		WorkerRunning:      s.tunTaskWorkerRunning,
		WorkerStale:        s.tunTaskWorkerRunning && !s.tunTaskWorkerLastBeat.IsZero() && now.Sub(s.tunTaskWorkerLastBeat) > 10*time.Second,
		WorkerLastBeatAt:   "",
		WorkerLastKickAt:   "",
		AvgDurationSeconds: int(snap.avgDuration.Seconds()),
	}
	if info.AvgDurationSeconds <= 0 {
		info.AvgDurationSeconds = int((20 * time.Second).Seconds())
	}
	if !s.tunTaskWorkerLastBeat.IsZero() {
		info.WorkerLastBeatAt = s.tunTaskWorkerLastBeat.Format(time.RFC3339)
		if now.After(s.tunTaskWorkerLastBeat) {
			info.WorkerBeatAgoSecond = int(now.Sub(s.tunTaskWorkerLastBeat).Seconds())
		}
	}
	if !s.tunTaskWorkerLastKick.IsZero() {
		info.WorkerLastKickAt = s.tunTaskWorkerLastKick.Format(time.RFC3339)
	}
	if info.Running {
		if eta := int(snap.runningRemaining.Seconds()); eta > 0 {
			info.RunningETASeconds = eta
		} else {
			info.RunningETASeconds = 1
		}
		if task, ok := s.tasks[snap.runningTaskID]; ok && task != nil {
			info.RunningKind = strings.TrimSpace(task.Kind)
			if startedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(task.StartedAt)); err == nil && now.After(startedAt) {
				info.RunningElapsedSec = int(now.Sub(startedAt).Seconds())
			}
		}
	}
	oldestPending := time.Time{}
	for _, task := range s.tasks {
		if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(task.Status), "pending") {
			continue
		}
		if _, ok := snap.queueIndex[task.ID]; !ok {
			continue
		}
		createdAt, err := time.Parse(time.RFC3339, strings.TrimSpace(task.CreatedAt))
		if err != nil {
			continue
		}
		if oldestPending.IsZero() || createdAt.Before(oldestPending) {
			oldestPending = createdAt
		}
	}
	if !oldestPending.IsZero() && now.After(oldestPending) {
		info.OldestPendingWait = int(now.Sub(oldestPending).Seconds())
	}
	return info
}

func (s *apiState) reconcileTunTaskStateLocked(now time.Time) {
	if s == nil {
		return
	}
	queueIDs := make(map[string]struct{}, len(s.tunTaskQueue))
	for _, req := range s.tunTaskQueue {
		taskID := strings.TrimSpace(req.TaskID)
		if taskID == "" {
			continue
		}
		queueIDs[taskID] = struct{}{}
	}
	hasRunning := false
	for _, task := range s.tasks {
		if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(task.Status), "running") {
			hasRunning = true
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(task.Status), "pending") {
			continue
		}
		if _, ok := queueIDs[task.ID]; ok {
			continue
		}
		createdAt, err := time.Parse(time.RFC3339, strings.TrimSpace(task.CreatedAt))
		if err == nil && now.Sub(createdAt) < 5*time.Second {
			// Grace period for just-created tasks.
			continue
		}
		task.Status = "failed"
		task.Message = "queue lost, auto finalized"
		task.Error = "tun task was pending but no longer exists in queue; please retry"
		task.FinishedAt = now.Format(time.RFC3339)
		logrus.Warnf("[Client] auto-finalized orphan tun task: %s", task.ID)
	}
	if len(s.tunTaskQueue) == 0 && !hasRunning {
		s.tunTaskWorkerRunning = false
	}
}

func (s *apiState) applyTunTaskQueueSnapshotLocked(task *apiAsyncTask, snap tunTaskQueueSnapshot, now time.Time) {
	if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") {
		return
	}
	task.QueuePos = 0
	task.QueueTotal = 0
	task.QueueETA = 0
	task.ElapsedSec = 0

	status := strings.ToLower(strings.TrimSpace(task.Status))
	switch status {
	case "running":
		task.QueuePos = 1
		if snap.queueTotal > 0 {
			task.QueueTotal = snap.queueTotal
		} else {
			task.QueueTotal = 1
		}
		if startedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(task.StartedAt)); err == nil {
			if now.After(startedAt) {
				task.ElapsedSec = int(now.Sub(startedAt).Seconds())
			}
		}
		eta := snap.runningRemaining
		if eta <= 0 {
			eta = snap.avgDuration
		}
		if eta > 0 {
			task.QueueETA = int(eta.Seconds())
			if task.QueueETA <= 0 {
				task.QueueETA = 1
			}
		}
	case "pending":
		idx, ok := snap.queueIndex[task.ID]
		if !ok {
			return
		}
		task.QueuePos = idx
		if snap.runningTaskID != "" {
			task.QueuePos++
		}
		if snap.queueTotal > 0 {
			task.QueueTotal = snap.queueTotal
		} else {
			task.QueueTotal = task.QueuePos
		}
		eta := time.Duration(0)
		if snap.runningTaskID != "" {
			eta += snap.runningRemaining
		}
		eta += time.Duration(idx) * snap.avgDuration
		if eta <= 0 {
			eta = snap.avgDuration
		}
		task.QueueETA = int(eta.Seconds())
		if task.QueueETA <= 0 {
			task.QueueETA = 1
		}
	}
}

func (s *apiState) applyTunTask(taskID string, next *clientTunConfig) error {
	lastStage := ""
	report := func(stage string) {
		stage = strings.TrimSpace(stage)
		if stage == "" {
			return
		}
		lastStage = stage
		s.updateTaskProgress(taskID, stage)
	}
	report("准备应用 TUN 配置")

	s.lock.Lock()
	defer s.lock.Unlock()

	prevTun := cloneTunConfig(s.cfg.Tun)
	if _, err := s.reconcileTunLocked(next, report); err != nil {
		report("TUN 应用失败，正在回滚上一版配置")
		_, _ = s.reconcileTunLocked(prevTun, nil)
		if lastStage != "" && !strings.Contains(err.Error(), lastStage) {
			return fmt.Errorf("%s: %w", lastStage, err)
		}
		return err
	}
	s.cfg.Tun = cloneTunConfig(next)
	if err := saveClientConfig(s.configPath, s.cfg); err != nil {
		report("保存配置失败，正在回滚")
		_, _ = s.reconcileTunLocked(prevTun, nil)
		s.cfg.Tun = prevTun
		return err
	}
	report("TUN 配置已生效")
	return nil
}

func (s *apiState) cleanupTasksLocked(max int) {
	if max <= 0 || len(s.tasks) <= max {
		return
	}
	type doneItem struct {
		id  string
		end string
	}
	done := make([]doneItem, 0, len(s.tasks))
	for id, task := range s.tasks {
		if task == nil {
			done = append(done, doneItem{id: id})
			continue
		}
		if task.Status == "success" || task.Status == "failed" {
			done = append(done, doneItem{id: id, end: task.FinishedAt})
		}
	}
	need := len(s.tasks) - max
	if need <= 0 || len(done) == 0 {
		return
	}
	sort.Slice(done, func(i, j int) bool {
		return done[i].end < done[j].end
	})
	if need > len(done) {
		need = len(done)
	}
	for i := 0; i < need; i++ {
		delete(s.tasks, done[i].id)
	}
}

func (s *apiState) handleTask(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		taskID := strings.TrimSpace(r.URL.Query().Get("id"))
		if taskID == "" {
			path := strings.TrimSpace(r.URL.Path)
			if strings.HasPrefix(path, "/api/v1/tasks/") {
				taskID = strings.TrimSpace(strings.TrimPrefix(path, "/api/v1/tasks/"))
			}
		}
		if taskID != "" {
			s.taskMu.Lock()
			now := time.Now()
			s.reconcileTunTaskStateLocked(now)
			startWorker := s.ensureTunTaskWorkerLocked(true)
			snapshot := s.buildTunTaskQueueSnapshotLocked(now)
			task, ok := s.tasks[taskID]
			if !ok || task == nil {
				s.taskMu.Unlock()
				if startWorker {
					go s.runTunTaskWorker()
				}
				writeError(w, http.StatusNotFound, "task not found")
				return
			}
			out := *task
			s.applyTunTaskQueueSnapshotLocked(&out, snapshot, now)
			s.taskMu.Unlock()
			if startWorker {
				go s.runTunTaskWorker()
			}
			writeJSON(w, http.StatusOK, out)
			return
		}

		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 {
				if v > 500 {
					v = 500
				}
				limit = v
			}
		}
		kindFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("kind")))
		statusFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status")))

		s.taskMu.Lock()
		now := time.Now()
		s.reconcileTunTaskStateLocked(now)
		startWorker := s.ensureTunTaskWorkerLocked(true)
		snapshot := s.buildTunTaskQueueSnapshotLocked(now)
		queueInfo := s.buildTunTaskQueueInfoLocked(now, snapshot)
		items := make([]apiAsyncTask, 0, len(s.tasks))
		for _, task := range s.tasks {
			if task == nil {
				continue
			}
			if kindFilter != "" && strings.ToLower(task.Kind) != kindFilter {
				continue
			}
			if statusFilter != "" && strings.ToLower(task.Status) != statusFilter {
				continue
			}
			out := *task
			s.applyTunTaskQueueSnapshotLocked(&out, snapshot, now)
			items = append(items, out)
		}
		s.taskMu.Unlock()
		if startWorker {
			go s.runTunTaskWorker()
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].CreatedAt == items[j].CreatedAt {
				return items[i].ID > items[j].ID
			}
			return items[i].CreatedAt > items[j].CreatedAt
		})
		if len(items) > limit {
			items = items[:limit]
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
			"count": len(items),
			"queue": queueInfo,
		})
	case http.MethodPost:
		var req struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
		}
		if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		kind := strings.TrimSpace(strings.ToLower(req.Kind))
		targetID := strings.TrimSpace(req.ID)
		switch kind {
		case "diagnose", "route_check", "subscription_update", "tun_check":
		default:
			writeError(w, http.StatusBadRequest, "unsupported task kind")
			return
		}
		taskID := s.createTask(kind, "queued")
		go s.runGenericTask(taskID, kind, targetID)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"task_id": taskID,
			"task": map[string]any{
				"id":     taskID,
				"kind":   kind,
				"status": "pending",
			},
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *apiState) runGenericTask(taskID, kind, targetID string) {
	if shouldWaitTunPriorityForTask(kind) {
		s.setTaskMessage(taskID, "waiting tun priority")
		if err := s.waitTunPriorityWindow(tunPriorityWaitTimeout); err != nil {
			payload := s.buildTunPriorityTimeoutPayload(kind, err)
			s.completeTask(taskID, payload, err, "waiting tun priority failed")
			return
		}
	}
	s.setTaskRunning(taskID, "running")
	switch kind {
	case "diagnose":
		res, err := s.runJSONTaskHandler(http.MethodGet, "/api/v1/diagnose", nil, s.handleDiagnose)
		if err != nil {
			s.completeTask(taskID, nil, err, "diagnose failed")
			return
		}
		s.completeTask(taskID, res, nil, "diagnose done")
	case "route_check":
		res, err := s.runJSONTaskHandler(http.MethodGet, "/api/v1/route/check", nil, s.handleRouteCheck)
		if err != nil {
			s.completeTask(taskID, nil, err, "route_check failed")
			return
		}
		s.completeTask(taskID, res, nil, "route_check done")
	case "subscription_update":
		req := map[string]any{"id": targetID}
		res, err := s.runJSONTaskHandler(http.MethodPost, "/api/v1/subscriptions/update", req, s.handleSubscriptionUpdate)
		if err != nil {
			s.completeTask(taskID, nil, err, "subscription_update failed")
			return
		}
		s.completeTask(taskID, res, nil, "subscription_update done")
	case "tun_check":
		res, err := s.runTunCheckTask(taskID)
		if err != nil {
			payload := map[string]any{
				"time": time.Now().Format(time.RFC3339),
				"summary": map[string]any{
					"ok":           false,
					"issue_count":  1,
					"failed_steps": 0,
					"total_steps":  0,
				},
				"issues": []string{err.Error()},
			}
			if res != nil {
				payload = res
			}
			s.completeTask(taskID, payload, err, "tun_check failed")
			return
		}
		ok := false
		if summary, okSummary := res["summary"].(map[string]any); okSummary {
			if value, okBool := summary["ok"].(bool); okBool {
				ok = value
			}
		}
		if ok {
			s.completeTask(taskID, res, nil, "tun_check done (ok)")
			return
		}
		s.completeTask(taskID, res, nil, "tun_check done (issues found)")
	default:
		s.completeTask(taskID, nil, fmt.Errorf("unsupported task kind: %s", kind), "unsupported")
	}
}

func shouldWaitTunPriorityForTask(kind string) bool {
	switch strings.TrimSpace(strings.ToLower(kind)) {
	case "subscription_update", "routing_update", "routing_probe":
		return true
	default:
		return false
	}
}

func (s *apiState) buildTunPriorityTimeoutPayload(kind string, waitErr error) map[string]any {
	now := time.Now()
	queue := map[string]any{
		"running": false,
		"pending": 0,
		"total":   0,
	}
	activeTunTasks := make([]map[string]any, 0, 4)
	if s != nil {
		s.taskMu.Lock()
		s.reconcileTunTaskStateLocked(now)
		snap := s.buildTunTaskQueueSnapshotLocked(now)
		queueInfo := s.buildTunTaskQueueInfoLocked(now, snap)
		queue = map[string]any{
			"updated_at":                 queueInfo.UpdatedAt,
			"running":                    queueInfo.Running,
			"running_task_id":            queueInfo.RunningTaskID,
			"running_kind":               queueInfo.RunningKind,
			"running_elapsed_seconds":    queueInfo.RunningElapsedSec,
			"running_eta_seconds":        queueInfo.RunningETASeconds,
			"pending":                    queueInfo.Pending,
			"total":                      queueInfo.Total,
			"oldest_pending_wait_second": queueInfo.OldestPendingWait,
			"worker_running":             queueInfo.WorkerRunning,
			"worker_stale":               queueInfo.WorkerStale,
			"worker_last_beat_at":        queueInfo.WorkerLastBeatAt,
			"worker_last_kick_at":        queueInfo.WorkerLastKickAt,
		}
		for _, task := range s.tasks {
			if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") {
				continue
			}
			status := strings.ToLower(strings.TrimSpace(task.Status))
			if status != "pending" && status != "running" {
				continue
			}
			item := map[string]any{
				"id":         task.ID,
				"status":     task.Status,
				"message":    task.Message,
				"created_at": task.CreatedAt,
			}
			taskSnap := *task
			s.applyTunTaskQueueSnapshotLocked(&taskSnap, snap, now)
			if taskSnap.QueuePos > 0 {
				item["queue_position"] = taskSnap.QueuePos
			}
			if taskSnap.QueueTotal > 0 {
				item["queue_total"] = taskSnap.QueueTotal
			}
			if taskSnap.QueueETA > 0 {
				item["queue_eta_seconds"] = taskSnap.QueueETA
			}
			if taskSnap.ElapsedSec > 0 {
				item["elapsed_seconds"] = taskSnap.ElapsedSec
			}
			activeTunTasks = append(activeTunTasks, item)
		}
		s.taskMu.Unlock()
	}
	sort.Slice(activeTunTasks, func(i, j int) bool {
		left := strings.TrimSpace(asStringMap(activeTunTasks[i], "created_at"))
		right := strings.TrimSpace(asStringMap(activeTunTasks[j], "created_at"))
		if left == right {
			return strings.TrimSpace(asStringMap(activeTunTasks[i], "id")) < strings.TrimSpace(asStringMap(activeTunTasks[j], "id"))
		}
		return left < right
	})
	issue := "waiting for TUN priority timed out"
	if waitErr != nil {
		issue = waitErr.Error()
	}
	return map[string]any{
		"time": now.Format(time.RFC3339),
		"summary": map[string]any{
			"ok":           false,
			"issue_count":  1,
			"failed_steps": 1,
			"total_steps":  1,
		},
		"issues": []string{issue},
		"steps": []map[string]any{
			{
				"name":        "wait_tun_priority",
				"message":     "等待 TUN 高优先级任务窗口",
				"status":      "failed",
				"error":       issue,
				"started_at":  "",
				"finished_at": now.Format(time.RFC3339),
				"duration_ms": 0,
			},
		},
		"queue": map[string]any{
			"task_kind":         strings.TrimSpace(kind),
			"snapshot":          queue,
			"active_tun_tasks":  activeTunTasks,
			"active_tun_count":  len(activeTunTasks),
			"priority_wait_sec": int(tunPriorityWaitTimeout.Seconds()),
		},
	}
}

func (s *apiState) runTunCheckTask(taskID string) (map[string]any, error) {
	type taskStep struct {
		Name       string `json:"name"`
		Message    string `json:"message"`
		Status     string `json:"status"`
		Error      string `json:"error,omitempty"`
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at"`
		DurationMS int64  `json:"duration_ms"`
	}
	type tunProbeGuard struct {
		Level             int     `json:"level"`
		Score             float64 `json:"score"`
		EMFILECooldownMS  int     `json:"emfile_cooldown_ms"`
		FDOpen            int     `json:"fd_open"`
		FDLimit           int     `json:"fd_limit"`
		FDUsagePercent    float64 `json:"fd_usage_percent"`
		Mode              string  `json:"mode"`
		HighPressure      bool    `json:"high_pressure"`
		ReducedProbe      bool    `json:"reduced_probe"`
		SkipHeavyProbe    bool    `json:"skip_heavy_probe"`
		DisableAutoRepair bool    `json:"disable_auto_dns_repair"`
	}

	asBool := func(v any) bool {
		b, ok := v.(bool)
		return ok && b
	}
	asInt := func(v any) int {
		switch n := v.(type) {
		case int:
			return n
		case int32:
			return int(n)
		case int64:
			return int(n)
		case float32:
			return int(n)
		case float64:
			return int(n)
		default:
			return 0
		}
	}
	asString := func(v any) string {
		text, _ := v.(string)
		return strings.TrimSpace(text)
	}
	appendIssue := func(issues []string, issueSet map[string]struct{}, text string) []string {
		text = strings.TrimSpace(text)
		if text == "" {
			return issues
		}
		if _, ok := issueSet[text]; ok {
			return issues
		}
		issueSet[text] = struct{}{}
		return append(issues, text)
	}
	removeIssuesByPrefix := func(issues []string, issueSet map[string]struct{}, prefixes ...string) []string {
		if len(issues) == 0 || len(prefixes) == 0 {
			return issues
		}
		filtered := issues[:0]
		for _, text := range issues {
			drop := false
			for _, prefix := range prefixes {
				if strings.HasPrefix(text, prefix) {
					drop = true
					break
				}
			}
			if drop {
				delete(issueSet, text)
				continue
			}
			filtered = append(filtered, text)
		}
		return filtered
	}
	markStepSoftSuccess := func(steps *[]taskStep, name string) bool {
		for idx := len(*steps) - 1; idx >= 0; idx-- {
			if (*steps)[idx].Name != name {
				continue
			}
			if strings.EqualFold(strings.TrimSpace((*steps)[idx].Status), "failed") {
				(*steps)[idx].Status = "success"
				(*steps)[idx].Error = ""
				return true
			}
			return false
		}
		return false
	}
	isStepFailure := func(status string) bool {
		s := strings.ToLower(strings.TrimSpace(status))
		return s != "success" && s != "skipped"
	}
	computeProbeGuard := func(status map[string]any) tunProbeGuard {
		guard := tunProbeGuard{
			Mode: "normal",
		}
		var inbound map[string]any
		if status != nil {
			if m, ok := status["inbound"].(map[string]any); ok {
				inbound = m
			}
		}
		if inbound == nil {
			if snap := inboundRuntimeStatsSnapshot(); len(snap) > 0 {
				inbound = snap
			}
		}
		if inbound == nil {
			return guard
		}
		guard.Level = asInt(inbound["pressure_level"])
		scoreX100 := asInt(inbound["pressure_score_x100"])
		guard.Score = float64(scoreX100) / 100.0
		guard.EMFILECooldownMS = asInt(inbound["emfile_cooldown_ms"])
		guard.FDOpen = asInt(inbound["fd_open"])
		guard.FDLimit = asInt(inbound["fd_limit"])
		if guard.FDOpen > 0 && guard.FDLimit > 0 {
			guard.FDUsagePercent = float64(guard.FDOpen) * 100.0 / float64(guard.FDLimit)
		}
		guard.HighPressure = guard.Level >= 2 || guard.EMFILECooldownMS > 0 || guard.FDUsagePercent >= 92
		guard.ReducedProbe = guard.Level >= 1 || guard.Score >= 1.5 || guard.FDUsagePercent >= 85
		guard.SkipHeavyProbe = guard.Level >= 3 || guard.EMFILECooldownMS > 0 || guard.FDUsagePercent >= 96
		guard.DisableAutoRepair = guard.Level >= 1 || guard.EMFILECooldownMS > 0 || guard.FDUsagePercent >= 85
		switch {
		case guard.SkipHeavyProbe:
			guard.Mode = "high"
		case guard.ReducedProbe:
			guard.Mode = "degraded"
		default:
			guard.Mode = "normal"
		}
		return guard
	}
	var emitProgress func()
	runStep := func(steps *[]taskStep, name, message string, fn func() (map[string]any, error)) (map[string]any, error) {
		s.setTaskMessage(taskID, message)
		startAt := time.Now()
		result, err := fn()
		finishedAt := time.Now()
		step := taskStep{
			Name:       name,
			Message:    message,
			Status:     "success",
			StartedAt:  startAt.Format(time.RFC3339),
			FinishedAt: finishedAt.Format(time.RFC3339),
			DurationMS: finishedAt.Sub(startAt).Milliseconds(),
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		}
		*steps = append(*steps, step)
		if emitProgress != nil {
			emitProgress()
		}
		return result, err
	}
	runSkippedStep := func(steps *[]taskStep, name, message, reason string) {
		s.setTaskMessage(taskID, message+"（已跳过）")
		now := time.Now()
		step := taskStep{
			Name:       name,
			Message:    message,
			Status:     "skipped",
			StartedAt:  now.Format(time.RFC3339),
			FinishedAt: now.Format(time.RFC3339),
			DurationMS: 0,
		}
		if strings.TrimSpace(reason) != "" {
			step.Error = strings.TrimSpace(reason)
		}
		*steps = append(*steps, step)
		if emitProgress != nil {
			emitProgress()
		}
	}

	steps := make([]taskStep, 0, 8)
	issues := make([]string, 0, 8)
	issueSet := make(map[string]struct{})
	extras := make(map[string]any)
	currentNode := ""
	var (
		statusRes   map[string]any
		diagnoseRes map[string]any
		routeRes    map[string]any
		selfHealRes map[string]any
	)

	emitProgress = func() {
		failedSteps := 0
		for _, step := range steps {
			if isStepFailure(step.Status) {
				failedSteps++
			}
		}
		s.updateTaskResult(taskID, map[string]any{
			"time":           time.Now().Format(time.RFC3339),
			"partial":        true,
			"current":        currentNode,
			"status":         statusRes,
			"diagnose":       diagnoseRes,
			"route_check":    routeRes,
			"route_selfheal": selfHealRes,
			"extras":         extras,
			"issues":         issues,
			"steps":          steps,
			"summary": map[string]any{
				"ok":           failedSteps == 0 && len(issues) == 0,
				"issue_count":  len(issues),
				"failed_steps": failedSteps,
				"total_steps":  len(steps),
			},
		})
	}

	statusRes, statusErr := runStep(&steps, "status", "TUN 连通性测试: 读取运行状态", func() (map[string]any, error) {
		return s.runJSONTaskHandler(http.MethodGet, "/api/v1/status", nil, s.handleStatus)
	})
	if statusErr != nil {
		issues = appendIssue(issues, issueSet, "状态检查失败: "+statusErr.Error())
	} else {
		currentNode = asString(statusRes["current"])
		if health, ok := statusRes["health"].(map[string]any); ok {
			if !asBool(health["ok"]) {
				if rows, okRows := health["issues"].([]any); okRows {
					for _, row := range rows {
						issues = appendIssue(issues, issueSet, asString(row))
					}
				}
			}
		}
		if tunMap, ok := statusRes["tun"].(map[string]any); ok {
			if asBool(tunMap["enabled"]) && !asBool(tunMap["running"]) {
				issues = appendIssue(issues, issueSet, "TUN 已启用但运行时未启动")
			}
		}
		if bypassMap, ok := statusRes["bypass"].(map[string]any); ok {
			if asInt(bypassMap["node_failed"]) > 0 {
				issues = appendIssue(issues, issueSet, fmt.Sprintf("节点旁路失败目标: %d", asInt(bypassMap["node_failed"])))
			}
		}
	}
	probeGuard := computeProbeGuard(statusRes)
	extras["probe_guard"] = map[string]any{
		"level":                   probeGuard.Level,
		"score":                   probeGuard.Score,
		"mode":                    probeGuard.Mode,
		"high_pressure":           probeGuard.HighPressure,
		"reduced_probe":           probeGuard.ReducedProbe,
		"skip_heavy_probe":        probeGuard.SkipHeavyProbe,
		"disable_auto_dns_repair": probeGuard.DisableAutoRepair,
		"emfile_cooldown_ms":      probeGuard.EMFILECooldownMS,
		"fd_open":                 probeGuard.FDOpen,
		"fd_limit":                probeGuard.FDLimit,
		"fd_usage_percent":        probeGuard.FDUsagePercent,
	}
	if probeGuard.HighPressure {
		extras["probe_guard_note"] = fmt.Sprintf("检测到连接压力（level=%d score=%.2f），已自动降级部分探测范围与超时", probeGuard.Level, probeGuard.Score)
	}

	diagnoseRes, diagnoseErr := runStep(&steps, "diagnose", "TUN 连通性测试: 执行基础诊断", func() (map[string]any, error) {
		return s.runJSONTaskHandler(http.MethodGet, "/api/v1/diagnose", nil, s.handleDiagnose)
	})
	if diagnoseErr != nil {
		issues = appendIssue(issues, issueSet, "基础诊断失败: "+diagnoseErr.Error())
	} else if summary, ok := diagnoseRes["summary"].(map[string]any); ok {
		if !asBool(summary["ok"]) {
			issues = appendIssue(issues, issueSet, fmt.Sprintf("基础诊断未通过（失败 %d 项）", asInt(summary["failed"])))
		}
	}

	routeRes, routeErr := runStep(&steps, "route_check", "TUN 连通性测试: 检查路由回环风险", func() (map[string]any, error) {
		return s.runJSONTaskHandler(http.MethodGet, "/api/v1/route/check", nil, s.handleRouteCheck)
	})
	if routeErr != nil {
		issues = appendIssue(issues, issueSet, "路由自检失败: "+routeErr.Error())
	} else if check, ok := routeRes["check"].(map[string]any); ok {
		if !asBool(check["ok"]) {
			issues = appendIssue(issues, issueSet, "路由自检未通过")
		}
		if asBool(check["risk_loop"]) {
			issues = appendIssue(issues, issueSet, "存在上游回环风险")
		}
	}

	selfHealRes, selfHealErr := runStep(&steps, "route_selfheal", "TUN 连通性测试: 获取自愈状态快照", func() (map[string]any, error) {
		return s.runJSONTaskHandler(http.MethodGet, "/api/v1/route/selfheal", nil, s.handleRouteSelfHeal)
	})
	if selfHealErr != nil {
		issues = appendIssue(issues, issueSet, "路由自愈状态读取失败: "+selfHealErr.Error())
	} else if health, ok := selfHealRes["health"].(map[string]any); ok {
		if !asBool(health["ok"]) {
			if rows, okRows := health["issues"].([]any); okRows {
				for _, row := range rows {
					issues = appendIssue(issues, issueSet, asString(row))
				}
			}
		}
	}

	httpsTargets := []string{
		"https://www.google.com/generate_204",
		"https://www.cloudflare.com/cdn-cgi/trace",
	}
	httpsTimeout := 4 * time.Second
	if probeGuard.ReducedProbe {
		httpsTimeout = 3 * time.Second
	}
	if probeGuard.SkipHeavyProbe {
		httpsTargets = []string{"https://www.google.com/generate_204"}
		httpsTimeout = 2500 * time.Millisecond
	}
	httpsProbeRes, httpsProbeErr := runStep(&steps, "https_probe", "TUN 连通性测试: 校验 HTTPS 证书与主机名", func() (map[string]any, error) {
		return s.runTunHTTPSProbe(httpsTargets, httpsTimeout)
	})
	if httpsProbeRes != nil {
		extras["https_probe"] = httpsProbeRes
		if summary, ok := httpsProbeRes["summary"].(map[string]any); ok {
			if asInt(summary["hostname_mismatch"]) > 0 {
				issues = appendIssue(issues, issueSet, fmt.Sprintf("HTTPS 证书主机名不匹配: %d 个目标", asInt(summary["hostname_mismatch"])))
			}
			if asInt(summary["failed"]) > 0 {
				issues = appendIssue(issues, issueSet, fmt.Sprintf("HTTPS 探测失败: %d 个目标", asInt(summary["failed"])))
			}
			if asInt(summary["success"]) == 0 {
				issues = appendIssue(issues, issueSet, "HTTPS 探测全部失败")
			}
		}
	}
	if httpsProbeErr != nil {
		issues = appendIssue(issues, issueSet, "HTTPS 证书校验失败: "+httpsProbeErr.Error())
	}

	systemTargets := []string{
		"https://www.google.com",
		"https://www.cloudflare.com/cdn-cgi/trace",
	}
	systemTimeout := 5
	if probeGuard.ReducedProbe {
		systemTimeout = 4
	}
	if probeGuard.SkipHeavyProbe {
		systemTargets = []string{"https://www.google.com"}
		systemTimeout = 3
	}
	systemHTTPSProbeRes, systemHTTPSProbeErr := runStep(&steps, "system_https_probe", "TUN 连通性测试: 校验系统 curl HTTPS 路径", func() (map[string]any, error) {
		return s.runTunSystemHTTPSProbeWithOptions(systemTargets, systemTimeout, tunSystemHTTPSProbeOptions{
			AutoDNSRepair: !probeGuard.DisableAutoRepair,
		})
	})
	if systemHTTPSProbeRes != nil {
		extras["system_https_probe"] = systemHTTPSProbeRes
		if summary, ok := systemHTTPSProbeRes["summary"].(map[string]any); ok {
			hardFailed := 0
			if _, hasHardFailed := summary["hard_failed"]; hasHardFailed {
				hardFailed = asInt(summary["hard_failed"])
			} else {
				// Older payloads may not carry hard_failed, fallback to failed.
				hardFailed = asInt(summary["failed"])
			}
			if asInt(summary["dns_path_unstable"]) > 0 {
				issues = appendIssue(issues, issueSet, fmt.Sprintf("系统 DNS 路径不稳定（回退 IP 可用）: %d 个目标", asInt(summary["dns_path_unstable"])))
			}
			if asInt(summary["hostname_mismatch"]) > 0 {
				issues = appendIssue(issues, issueSet, fmt.Sprintf("系统 curl 证书主机名不匹配: %d 个目标", asInt(summary["hostname_mismatch"])))
			}
			if !asBool(summary["skipped"]) && hardFailed > 0 {
				issues = appendIssue(issues, issueSet, fmt.Sprintf("系统 curl HTTPS 探测失败: %d 个目标", hardFailed))
			}
			if !asBool(summary["skipped"]) && asInt(summary["success"]) == 0 {
				issues = appendIssue(issues, issueSet, "系统 curl HTTPS 探测全部失败")
			}
		}
	}
	if systemHTTPSProbeErr != nil {
		issues = appendIssue(issues, issueSet, "系统 curl HTTPS 校验失败: "+systemHTTPSProbeErr.Error())
	}
	if httpsSummary, okHTTPS := httpsProbeRes["summary"].(map[string]any); okHTTPS {
		if sysSummary, okSys := systemHTTPSProbeRes["summary"].(map[string]any); okSys {
			if asBool(httpsSummary["ok"]) && !asBool(sysSummary["ok"]) {
				issues = appendIssue(issues, issueSet, "应用层探测可用但系统 curl 路径异常（可能导致实际终端访问失败）")
			}
			if !asBool(sysSummary["skipped"]) &&
				asBool(sysSummary["ok"]) &&
				asInt(httpsSummary["hostname_mismatch"]) == 0 &&
				(httpsProbeErr != nil || asInt(httpsSummary["failed"]) > 0) {
				issues = removeIssuesByPrefix(issues, issueSet,
					"HTTPS 探测失败:",
					"HTTPS 探测全部失败",
					"HTTPS 证书校验失败:",
				)
				softDowngraded := markStepSoftSuccess(&steps, "https_probe")
				extras["https_probe_soft_failover"] = map[string]any{
					"applied":         true,
					"step_downgraded": softDowngraded,
					"reason":          "system_https_probe_ok",
					"https_failed":    asInt(httpsSummary["failed"]),
					"https_success":   asInt(httpsSummary["success"]),
				}
				if softDowngraded && emitProgress != nil {
					emitProgress()
				}
			}
		}
	}

	if s.dnsMap != nil {
		quarantine := collectHostnameMismatchDomainIPBlocks(httpsProbeRes)
		quarantine = mergeDomainIPQuarantine(quarantine, collectHostnameMismatchDomainIPBlocks(systemHTTPSProbeRes))
		quarantineHosts := make([]string, 0, len(quarantine))
		for host := range quarantine {
			quarantineHosts = append(quarantineHosts, host)
		}
		sort.Strings(quarantineHosts)
		for _, host := range quarantineHosts {
			cachedIPs := s.dnsMap.LookupByDomain(host)
			if len(cachedIPs) == 0 {
				continue
			}
			ips := make([]string, 0, len(cachedIPs))
			for _, ip := range cachedIPs {
				if !ip.IsValid() {
					continue
				}
				ips = append(ips, ip.Unmap().String())
			}
			quarantine[host] = appendUniqueStrings(quarantine[host], ips...)
		}

		blockedByHost := make(map[string]int)
		blockedTotal := 0
		for _, host := range quarantineHosts {
			ips := appendUniqueStrings(nil, quarantine[host]...)
			if len(ips) == 0 {
				continue
			}
			blocked := s.dnsMap.BlockDomainIPs(host, ips, 45*time.Minute)
			if blocked <= 0 {
				continue
			}
			blockedByHost[host] = blocked
			blockedTotal += blocked
		}
		if blockedTotal > 0 {
			removed := s.dnsMap.RemoveDomains(quarantineHosts)
			extras["dns_poison_quarantine"] = map[string]any{
				"attempted":        true,
				"hosts":            quarantineHosts,
				"blocked_total":    blockedTotal,
				"blocked_by_host":  blockedByHost,
				"removed_mappings": removed,
				"ttl_sec":          int((45 * time.Minute).Seconds()),
			}
			logrus.Warnf("[Client] dns poison quarantine applied: hosts=%d blocked=%d removed=%d", len(quarantineHosts), blockedTotal, removed)
		}
	}

	mismatchHosts := collectHostnameMismatchHosts(httpsProbeRes)
	mismatchHosts = appendUniqueStrings(mismatchHosts, collectProbeFailedHosts(httpsProbeRes)...)
	mismatchHosts = appendUniqueStrings(mismatchHosts, collectHostnameMismatchHosts(systemHTTPSProbeRes)...)
	mismatchHosts = appendUniqueStrings(mismatchHosts, collectProbeFailedHosts(systemHTTPSProbeRes)...)
	if len(mismatchHosts) > 0 {
		if probeGuard.SkipHeavyProbe {
			runSkippedStep(&steps, "dns_resolution_probe", "TUN 连通性测试: 采样异常域名 DNS 解析", "pressure-guard skip heavy dns probe")
		} else {
			dnsServers := []string{
				"127.0.0.1:53",
				"223.5.5.5:53",
				"1.1.1.1:53",
				"8.8.8.8:53",
			}
			dnsTimeout := 3 * time.Second
			if probeGuard.ReducedProbe {
				dnsServers = []string{"127.0.0.1:53", "1.1.1.1:53"}
				dnsTimeout = 2 * time.Second
			}
			dnsProbeRes, dnsProbeErr := runStep(&steps, "dns_resolution_probe", "TUN 连通性测试: 采样异常域名 DNS 解析", func() (map[string]any, error) {
				hosts := mismatchHosts
				if probeGuard.ReducedProbe && len(hosts) > 1 {
					hosts = hosts[:1]
				}
				return s.runTunDNSResolutionProbe(hosts, dnsServers, dnsTimeout)
			})
			if dnsProbeRes != nil {
				extras["dns_resolution_probe"] = dnsProbeRes
			}
			if dnsProbeErr != nil {
				issues = appendIssue(issues, issueSet, "异常域名 DNS 采样失败: "+dnsProbeErr.Error())
			}
		}
	}

	if len(issues) > 0 {
		if strings.TrimSpace(currentNode) != "" {
			if probeGuard.SkipHeavyProbe {
				runSkippedStep(&steps, "latency_probe", "TUN 连通性测试: 异常后追加节点握手探测", "pressure-guard skip heavy latency probe")
			} else {
				latencyPayload := map[string]any{
					"name":       currentNode,
					"count":      1,
					"timeout_ms": 2000,
				}
				latencyRes, latencyErr := runStep(&steps, "latency_probe", "TUN 连通性测试: 异常后追加节点握手探测", func() (map[string]any, error) {
					return s.runJSONTaskHandler(http.MethodPost, "/api/v1/test/latency", latencyPayload, s.handleTestLatency)
				})
				if latencyErr != nil {
					issues = appendIssue(issues, issueSet, "追加节点握手探测失败: "+latencyErr.Error())
				} else {
					extras["latency_probe"] = latencyRes
				}
			}
		}

		refreshRes, refreshErr := runStep(&steps, "route_selfheal_refresh", "TUN 连通性测试: 异常后追加路由自愈复检", func() (map[string]any, error) {
			return s.runJSONTaskHandler(http.MethodGet, "/api/v1/route/selfheal", nil, s.handleRouteSelfHeal)
		})
		if refreshErr != nil {
			issues = appendIssue(issues, issueSet, "追加路由复检失败: "+refreshErr.Error())
		} else {
			extras["route_selfheal_refresh"] = refreshRes
		}
	}

	failedSteps := 0
	for _, step := range steps {
		if isStepFailure(step.Status) {
			failedSteps++
		}
	}

	return map[string]any{
		"time":           time.Now().Format(time.RFC3339),
		"current":        currentNode,
		"status":         statusRes,
		"diagnose":       diagnoseRes,
		"route_check":    routeRes,
		"route_selfheal": selfHealRes,
		"extras":         extras,
		"issues":         issues,
		"steps":          steps,
		"summary": map[string]any{
			"ok":           failedSteps == 0 && len(issues) == 0,
			"issue_count":  len(issues),
			"failed_steps": failedSteps,
			"total_steps":  len(steps),
		},
	}, nil
}

func (s *apiState) runTunHTTPSProbe(targets []string, timeout time.Duration) (map[string]any, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	openwrtProbe := runtime.GOOS == "linux" && isOpenWrtRuntime()
	results := make([]map[string]any, 0, len(targets))
	successCount := 0
	mismatchCount := 0
	failCount := 0
	var firstErr error

	for _, rawURL := range targets {
		targetURL := strings.TrimSpace(rawURL)
		if targetURL == "" {
			continue
		}
		item := map[string]any{
			"url": targetURL,
			"ok":  false,
		}
		startAt := time.Now()
		func() {
			parsed, err := neturl.Parse(targetURL)
			if err != nil {
				item["error"] = fmt.Sprintf("invalid url: %v", err)
				failCount++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			host := parsed.Hostname()
			item["host"] = host

			if openwrtProbe && host != "" && net.ParseIP(host) == nil {
				resolvedIPs, resolveErr := resolveHostByProbeUpstreams(host, timeout, true)
				if resolveErr != nil {
					item["resolve_error"] = resolveErr.Error()
				} else if len(resolvedIPs) > 0 {
					item["resolved_ips"] = append([]string(nil), resolvedIPs...)
					probeRes, probeErr := runHTTPSProbeViaResolvedIPs(targetURL, host, resolvedIPs, timeout)
					if probeErr == nil {
						item["ok"] = true
						item["status_code"] = probeRes.StatusCode
						if probeRes.UsedIP != "" {
							item["resolved_ip"] = probeRes.UsedIP
						}
						if strings.TrimSpace(probeRes.CertSubject) != "" {
							item["cert_subject"] = strings.TrimSpace(probeRes.CertSubject)
						}
						if len(probeRes.CertDNSNames) > 0 {
							item["cert_dns_names"] = append([]string(nil), probeRes.CertDNSNames...)
						}
						successCount++
						return
					}

					errText := probeErr.Error()
					item["resolved_probe_error"] = errText
					if isHostnameMismatchErrorText(strings.ToLower(errText)) {
						item["resolved_probe_error_type"] = "hostname_mismatch"
					}
				}
			}

			probeTimeout := timeout
			if probeTimeout >= 3*time.Second && probeTimeout < 5*time.Second {
				probeTimeout = 5 * time.Second
			}
			transport := &http.Transport{
				Proxy: nil,
				DialContext: (&net.Dialer{
					Timeout: probeTimeout,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				TLSHandshakeTimeout:   probeTimeout,
				ResponseHeaderTimeout: probeTimeout,
				ExpectContinueTimeout: 1 * time.Second,
				DisableKeepAlives:     true,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			}
			defer transport.CloseIdleConnections()

			client := &http.Client{
				Transport: transport,
				Timeout:   probeTimeout + 2*time.Second,
			}
			maxAttempts := 2
			if timeout < 3*time.Second {
				maxAttempts = 1
			}
			var resp *http.Response
			for attempt := 0; attempt < maxAttempts; attempt++ {
				req, err := http.NewRequest(http.MethodGet, targetURL, nil)
				if err != nil {
					item["error"] = fmt.Sprintf("build request failed: %v", err)
					failCount++
					if firstErr == nil {
						firstErr = err
					}
					return
				}
				req.Header.Set("User-Agent", "anytls-tun-check/1.0")
				resp, err = client.Do(req)
				if err == nil {
					break
				}
				if isHostnameMismatchError(err) {
					item["error_type"] = "hostname_mismatch"
					item["error"] = err.Error()
					mismatchCount++
					if firstErr == nil {
						firstErr = err
					}
					return
				}
				if attempt+1 < maxAttempts && shouldRetryHTTPSProbeError(err) {
					time.Sleep(120 * time.Millisecond)
					continue
				}
				finalErr := err
				if openwrtProbe && host != "" && !isHostnameMismatchError(finalErr) {
					fallbackTimeoutSec := int(math.Ceil(probeTimeout.Seconds()))
					if fallbackTimeoutSec < 3 {
						fallbackTimeoutSec = 3
					}
					if fallbackTimeoutSec > 8 {
						fallbackTimeoutSec = 8
					}
					fallbackErr := runSystemCurlProbeCommand(targetURL, fallbackTimeoutSec, true)
					if fallbackErr == nil {
						item["ok"] = true
						item["probe_fallback"] = "system_curl"
						successCount++
						return
					}
					item["system_curl_fallback_error"] = fallbackErr.Error()
					if isHostnameMismatchError(fallbackErr) {
						item["error_type"] = "hostname_mismatch"
						item["error"] = fallbackErr.Error()
						mismatchCount++
						if firstErr == nil {
							firstErr = fallbackErr
						}
						return
					}
					finalErr = fmt.Errorf("%v; system curl fallback failed: %v", finalErr, fallbackErr)
				}
				item["error"] = finalErr.Error()
				failCount++
				if firstErr == nil {
					firstErr = finalErr
				}
				return
			}
			if resp == nil {
				item["error"] = "https probe failed: empty response"
				failCount++
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))

			item["status_code"] = resp.StatusCode
			item["ok"] = true
			successCount++
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				leaf := resp.TLS.PeerCertificates[0]
				item["cert_subject"] = strings.TrimSpace(leaf.Subject.CommonName)
				if len(leaf.DNSNames) > 0 {
					limit := len(leaf.DNSNames)
					if limit > 8 {
						limit = 8
					}
					item["cert_dns_names"] = append([]string(nil), leaf.DNSNames[:limit]...)
				}
			}
		}()
		item["duration_ms"] = time.Since(startAt).Milliseconds()
		results = append(results, item)
	}

	if len(results) == 0 {
		return map[string]any{
			"summary": map[string]any{
				"ok":                false,
				"total":             0,
				"success":           0,
				"failed":            0,
				"hostname_mismatch": 0,
			},
			"results": results,
		}, fmt.Errorf("no https probe target configured")
	}

	result := map[string]any{
		"summary": map[string]any{
			"ok":                mismatchCount == 0 && failCount == 0 && successCount > 0,
			"total":             len(results),
			"success":           successCount,
			"failed":            failCount,
			"hostname_mismatch": mismatchCount,
		},
		"results": results,
	}
	if mismatchCount > 0 {
		return result, fmt.Errorf("detected certificate hostname mismatch on %d target(s)", mismatchCount)
	}
	if failCount > 0 {
		return result, fmt.Errorf("https probe failed on %d target(s)", failCount)
	}
	if successCount == 0 {
		if firstErr != nil {
			return result, fmt.Errorf("all https probe targets failed: %v", firstErr)
		}
		return result, fmt.Errorf("all https probe targets failed")
	}
	return result, nil
}

type tunSystemHTTPSProbeOptions struct {
	AutoDNSRepair bool
}

func (s *apiState) runTunSystemHTTPSProbe(targets []string, timeoutSec int) (map[string]any, error) {
	return s.runTunSystemHTTPSProbeWithOptions(targets, timeoutSec, tunSystemHTTPSProbeOptions{
		AutoDNSRepair: true,
	})
}

func (s *apiState) runTunSystemHTTPSProbeWithOptions(targets []string, timeoutSec int, options tunSystemHTTPSProbeOptions) (map[string]any, error) {
	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	if !commandExists("curl") {
		return map[string]any{
			"summary": map[string]any{
				"ok":                true,
				"skipped":           true,
				"reason":            "curl not found",
				"total":             0,
				"success":           0,
				"failed":            0,
				"hostname_mismatch": 0,
			},
			"results": []map[string]any{},
		}, nil
	}

	openwrtMode := runtime.GOOS == "linux" && isOpenWrtRuntime()
	eval := runTunSystemHTTPSProbeOnce(targets, timeoutSec, openwrtMode)
	dnsMapRemoved := 0
	if runtime.GOOS == "linux" && isOpenWrtRuntime() && s.dnsMap != nil && len(eval.failedHosts) > 0 {
		dnsMapRemoved = s.dnsMap.RemoveDomains(eval.failedHosts)
		if dnsMapRemoved > 0 {
			logrus.Warnf("[Client] system https probe cleared dns-map entries: removed=%d hosts=%s", dnsMapRemoved, strings.Join(eval.failedHosts, ","))
		}
	}

	var repairInfo map[string]any
	shouldTryOpenWrtDNSRepair := options.AutoDNSRepair &&
		runtime.GOOS == "linux" && isOpenWrtRuntime() &&
		(eval.mismatchCount > 0 || eval.dnsPathFlaky > 0 || eval.failCount > 0)
	if shouldTryOpenWrtDNSRepair {
		domains := buildDNSRepairTargetsForHosts(eval.failedHosts)
		if len(domains) > 0 {
			rep := repairOpenWrtDNSDomains(domains)
			repairInfo = map[string]any{
				"attempted":         true,
				"domains":           rep.Domains,
				"ok":                rep.OK,
				"issues":            rep.Issues,
				"address_removed":   rep.AddressRemoved,
				"server_removed":    rep.ServerRemoved,
				"server_patterns":   rep.ServerPatterns,
				"server_reset":      rep.ServerReset,
				"server_upstreams":  rep.ServerUpstreams,
				"options_forced":    rep.OptionsForced,
				"hosts_removed":     rep.HostsRemoved,
				"config_changed":    rep.ConfigChanged,
				"dnsmasq_restarted": rep.DNSMasqRestarted,
				"uci_committed":     rep.UCICommitted,
				"before": map[string]any{
					"failed":            eval.failCount,
					"hostname_mismatch": eval.mismatchCount,
					"dns_path_unstable": eval.dnsPathFlaky,
					"success":           eval.successCount,
				},
			}
			shouldRetryProbe := rep.OK && (rep.ConfigChanged || dnsMapRemoved > 0)
			repairInfo["retry_probe"] = shouldRetryProbe
			if shouldRetryProbe {
				retry := runTunSystemHTTPSProbeOnce(targets, timeoutSec, openwrtMode)
				repairInfo["after"] = map[string]any{
					"failed":            retry.failCount,
					"hostname_mismatch": retry.mismatchCount,
					"dns_path_unstable": retry.dnsPathFlaky,
					"success":           retry.successCount,
				}
				eval = retry
			}
		}
	}

	hardFailCount := eval.failCount - eval.dnsPathFlaky
	if hardFailCount < 0 {
		hardFailCount = 0
	}
	summary := map[string]any{
		"ok":                eval.mismatchCount == 0 && hardFailCount == 0 && eval.successCount > 0,
		"skipped":           false,
		"total":             len(eval.results),
		"success":           eval.successCount,
		"failed":            eval.failCount,
		"hard_failed":       hardFailCount,
		"hostname_mismatch": eval.mismatchCount,
		"dns_path_unstable": eval.dnsPathFlaky,
	}
	result := map[string]any{
		"summary": summary,
		"results": eval.results,
	}
	if repairInfo != nil {
		repairInfo["dns_map_removed"] = dnsMapRemoved
		result["auto_dns_repair"] = repairInfo
	} else if !options.AutoDNSRepair {
		result["auto_dns_repair"] = map[string]any{
			"attempted": false,
			"reason":    "disabled_for_readonly_probe",
		}
	} else if dnsMapRemoved > 0 {
		result["dns_map_repair"] = map[string]any{
			"attempted": true,
			"removed":   dnsMapRemoved,
			"hosts":     appendUniqueStrings(nil, eval.failedHosts...),
		}
	}
	if eval.mismatchCount > 0 {
		return result, fmt.Errorf("system curl detected certificate hostname mismatch on %d target(s)", eval.mismatchCount)
	}
	if hardFailCount > 0 {
		return result, fmt.Errorf("system curl probe failed on %d target(s)", hardFailCount)
	}
	if eval.successCount == 0 && eval.failCount > 0 {
		if eval.firstErr != nil {
			return result, fmt.Errorf("system curl probe failed on all targets: %v", eval.firstErr)
		}
		return result, fmt.Errorf("system curl probe failed on all targets")
	}
	return result, nil
}

type tunSystemHTTPSProbeEval struct {
	results       []map[string]any
	successCount  int
	failCount     int
	mismatchCount int
	dnsPathFlaky  int
	firstErr      error
	failedHosts   []string
}

func runTunSystemHTTPSProbeOnce(targets []string, timeoutSec int, openwrtMode bool) tunSystemHTTPSProbeEval {
	results := make([]map[string]any, 0, len(targets))
	successCount := 0
	failCount := 0
	mismatchCount := 0
	dnsPathFlaky := 0
	var firstErr error
	failedHosts := make([]string, 0, len(targets))

	for _, rawURL := range targets {
		targetURL := strings.TrimSpace(rawURL)
		if targetURL == "" {
			continue
		}
		host := parseProbeHost(targetURL)
		item := map[string]any{
			"url": targetURL,
			"ok":  false,
		}
		if host != "" {
			item["host"] = host
		}
		startAt := time.Now()
		err := runSystemCurlProbeCommand(targetURL, timeoutSec, openwrtMode)
		item["duration_ms"] = time.Since(startAt).Milliseconds()
		if err == nil {
			item["ok"] = true
			successCount++
			results = append(results, item)
			continue
		}

		errMsg := err.Error()
		item["error"] = errMsg
		lower := strings.ToLower(errMsg)
		if isHostnameMismatchErrorText(lower) {
			item["error_type"] = "hostname_mismatch"
			mismatchCount++
		} else if strings.Contains(lower, "system dns path failed:") && strings.Contains(lower, "resolved fallback succeeded") {
			item["error_type"] = "dns_path_unstable"
			dnsPathFlaky++
		} else if strings.Contains(lower, "curl -4 succeeded") {
			item["error_type"] = "dns_path_unstable"
			dnsPathFlaky++
		}
		if host != "" {
			failedHosts = append(failedHosts, host)
		}
		failCount++
		if firstErr == nil {
			firstErr = err
		}
		results = append(results, item)
	}

	return tunSystemHTTPSProbeEval{
		results:       results,
		successCount:  successCount,
		failCount:     failCount,
		mismatchCount: mismatchCount,
		dnsPathFlaky:  dnsPathFlaky,
		firstErr:      firstErr,
		failedHosts:   appendUniqueStrings(nil, failedHosts...),
	}
}

func parseProbeHost(targetURL string) string {
	parsed, err := neturl.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Hostname())
}

func buildDNSRepairTargetsForHosts(hosts []string) []string {
	targets := []string{
		"raw.githubusercontent.com",
		"githubusercontent.com",
		"github.com",
	}
	for _, host := range appendUniqueStrings(nil, hosts...) {
		h := strings.TrimSpace(strings.ToLower(host))
		if h == "" {
			continue
		}
		if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
			continue
		}
		targets = append(targets, h)
		parts := strings.Split(h, ".")
		if len(parts) >= 2 {
			root := strings.Join(parts[len(parts)-2:], ".")
			targets = append(targets, root)
		}
	}
	return appendUniqueStrings(nil, targets...)
}

func runSystemCurlProbeCommand(targetURL string, timeoutSec int, openwrtMode bool) error {
	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	parsed, err := neturl.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return fmt.Errorf("invalid probe url %q: %w", targetURL, err)
	}
	host := strings.TrimSpace(parsed.Hostname())
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}

	baseArgs := []string{
		"-q",
		"-fsS",
		"--proxy", "",
		"--noproxy", "*",
		"-o", "/dev/null",
	}
	runAttempt := func(ip string, attemptBudget time.Duration, connectCapSec int, forceIPv4 bool) error {
		if attemptBudget <= 0 {
			attemptBudget = 2 * time.Second
		}
		attemptBudget = minDuration(attemptBudget, 8*time.Second)
		maxTimeSec := int(math.Ceil(attemptBudget.Seconds()))
		if maxTimeSec < 1 {
			maxTimeSec = 1
		}
		connectSec := maxTimeSec
		if connectCapSec > 0 && connectSec > connectCapSec {
			connectSec = connectCapSec
		}
		args := append([]string(nil), baseArgs...)
		if forceIPv4 {
			args = append(args, "-4")
		}
		args = append(args,
			"--max-time", strconv.Itoa(maxTimeSec),
			"--connect-timeout", strconv.Itoa(connectSec),
		)
		if ip != "" {
			args = append(args, "--resolve", fmt.Sprintf("%s:%s:%s", host, port, ip))
		}
		args = append(args, targetURL)
		return runCurlProbeCommand(args, targetURL, attemptBudget+700*time.Millisecond)
	}

	totalBudget := time.Duration(timeoutSec) * time.Second
	if totalBudget < 2*time.Second {
		totalBudget = 2 * time.Second
	}
	deadline := time.Now().Add(totalBudget)
	plainBudget := minDuration(totalBudget, 2500*time.Millisecond)
	if plainBudget < 1200*time.Millisecond {
		plainBudget = minDuration(totalBudget, 1200*time.Millisecond)
	}

	// First probe the real system path (without --resolve), so the result matches user-facing curl behavior.
	plainErr := runAttempt("", plainBudget, 4, false)
	if plainErr == nil {
		return nil
	}
	if shouldRetrySystemCurlPath(plainErr) {
		remaining := time.Until(deadline)
		if remaining > 800*time.Millisecond {
			retryBudget := minDuration(remaining, 1500*time.Millisecond)
			if retryBudget < 800*time.Millisecond {
				retryBudget = remaining
			}
			retryErr := runAttempt("", retryBudget, 2, false)
			if retryErr == nil {
				return nil
			}
			plainErr = retryErr
		}
	}

	// On OpenWrt, also test curl -4 to detect dual-stack/system DNS path drift.
	if openwrtMode && host != "" && net.ParseIP(host) == nil && strings.EqualFold(parsed.Scheme, "https") {
		remaining := time.Until(deadline)
		if remaining > 700*time.Millisecond {
			v4Budget := minDuration(remaining, 1200*time.Millisecond)
			if v4Budget < 700*time.Millisecond {
				v4Budget = remaining
			}
			v4Err := runAttempt("", v4Budget, 2, true)
			if v4Err == nil {
				return fmt.Errorf("system default stack failed: %v; curl -4 succeeded", plainErr)
			}
		}
	}

	// Optional fallback probe for diagnostics only; if fallback succeeds, we still report failure
	// because system DNS path is broken.
	if !(openwrtMode && host != "" && net.ParseIP(host) == nil && strings.EqualFold(parsed.Scheme, "https")) {
		return plainErr
	}
	remaining := time.Until(deadline)
	if remaining <= 500*time.Millisecond {
		return plainErr
	}
	resolveBudget := minDuration(remaining, 1500*time.Millisecond)
	resolvedIPs, resolveErr := resolveHostByProbeUpstreams(host, resolveBudget, true)
	if resolveErr != nil || len(resolvedIPs) == 0 {
		return plainErr
	}
	candidates := appendUniqueStrings(nil, resolvedIPs...)
	if len(candidates) > 1 {
		candidates = candidates[:1]
	}
	remaining = time.Until(deadline)
	if remaining <= 400*time.Millisecond {
		return plainErr
	}
	fallbackBudget := minDuration(remaining, 1200*time.Millisecond)
	fallbackSucceeded := false
	var lastFallbackErr error
	for _, ip := range candidates {
		err := runAttempt(ip, fallbackBudget, 2, true)
		if err == nil {
			fallbackSucceeded = true
			break
		}
		lastFallbackErr = err
	}
	if fallbackSucceeded {
		return fmt.Errorf("system dns path failed: %v; resolved fallback succeeded", plainErr)
	}
	if lastFallbackErr != nil {
		return fmt.Errorf("system dns path failed: %v; resolved fallback also failed: %v", plainErr, lastFallbackErr)
	}
	return plainErr
}

func shouldRetrySystemCurlPath(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "timed out") ||
		strings.Contains(text, "timeout") ||
		strings.Contains(text, "unexpected eof") ||
		strings.Contains(text, "connection reset") ||
		strings.Contains(text, "broken pipe") ||
		strings.Contains(text, "temporarily unavailable")
}

func shouldRetryHTTPSProbeError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "timed out") ||
		strings.Contains(text, "timeout") ||
		strings.Contains(text, "i/o timeout") ||
		strings.Contains(text, "tls handshake timeout") ||
		strings.Contains(text, "unexpected eof") ||
		strings.Contains(text, "connection reset") ||
		strings.Contains(text, "broken pipe") ||
		strings.Contains(text, "temporary failure") ||
		strings.Contains(text, "temporarily unavailable")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type httpsProbeResolvedResult struct {
	StatusCode   int
	CertSubject  string
	CertDNSNames []string
	UsedIP       string
}

func runHTTPSProbeViaResolvedIPs(targetURL, host string, ips []string, timeout time.Duration) (httpsProbeResolvedResult, error) {
	result := httpsProbeResolvedResult{}
	parsed, err := neturl.Parse(targetURL)
	if err != nil {
		return result, err
	}
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}

	var lastErr error
	candidates := appendUniqueStrings(nil, ips...)
	if len(candidates) > 3 {
		candidates = candidates[:3]
	}
	deadline := time.Now().Add(maxDuration(timeout, 2*time.Second))
	for _, ip := range candidates {
		remaining := time.Until(deadline)
		if remaining <= 300*time.Millisecond {
			break
		}
		attemptTimeout := minDuration(remaining, maxDuration(timeout, 4*time.Second))
		targetAddr := net.JoinHostPort(ip, port)
		transport := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: attemptTimeout}
				return d.DialContext(ctx, network, targetAddr)
			},
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   attemptTimeout,
			ResponseHeaderTimeout: attemptTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: host,
			},
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   attemptTimeout + 1200*time.Millisecond,
		}
		req, reqErr := http.NewRequest(http.MethodGet, targetURL, nil)
		if reqErr != nil {
			transport.CloseIdleConnections()
			return result, reqErr
		}
		req.Header.Set("User-Agent", "anytls-tun-check/1.0")

		resp, doErr := client.Do(req)
		if doErr != nil {
			lastErr = doErr
			transport.CloseIdleConnections()
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		result.StatusCode = resp.StatusCode
		result.UsedIP = ip
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			result.CertSubject = strings.TrimSpace(leaf.Subject.CommonName)
			if len(leaf.DNSNames) > 0 {
				limit := len(leaf.DNSNames)
				if limit > 8 {
					limit = 8
				}
				result.CertDNSNames = append([]string(nil), leaf.DNSNames[:limit]...)
			}
		}
		transport.CloseIdleConnections()
		return result, nil
	}
	if lastErr != nil {
		return result, lastErr
	}
	return result, fmt.Errorf("no resolved ip available")
}

func runCurlProbeCommand(args []string, targetURL string, cmdTimeout time.Duration) error {
	if cmdTimeout <= 0 {
		cmdTimeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
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
	text := strings.TrimSpace(string(output))
	if ctx.Err() == context.DeadlineExceeded {
		if text == "" {
			return fmt.Errorf("curl %s: timeout after %s", targetURL, cmdTimeout)
		}
		return fmt.Errorf("curl %s: timeout after %s: %s", targetURL, cmdTimeout, text)
	}
	if err != nil {
		if text == "" {
			return fmt.Errorf("curl %s: %w", targetURL, err)
		}
		return fmt.Errorf("curl %s: %w: %s", targetURL, err, text)
	}
	return nil
}

func resolveHostByProbeUpstreams(host string, timeout time.Duration, forceIPv4 bool) ([]string, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	servers := []string{
		"127.0.0.1:53",
		"223.5.5.5:53",
		"1.1.1.1:53",
		"8.8.8.8:53",
	}
	type resolveCandidateScore struct {
		score      int
		hits       int
		publicHits int
	}
	candidateScore := make(map[string]resolveCandidateScore, 16)
	var lastErr error
	deadline := time.Now().Add(timeout)
	for idx, server := range servers {
		remaining := time.Until(deadline)
		if remaining <= 150*time.Millisecond {
			break
		}
		serversLeft := len(servers) - idx
		if serversLeft < 1 {
			serversLeft = 1
		}
		lookupTimeout := minDuration(remaining/time.Duration(serversLeft), 1500*time.Millisecond)
		if lookupTimeout <= 0 {
			lookupTimeout = minDuration(remaining, 400*time.Millisecond)
		}
		if lookupTimeout < 350*time.Millisecond {
			lookupTimeout = minDuration(remaining, 350*time.Millisecond)
		}
		ips, _, err := lookupHostWithDNSServerPreferTCP(host, server, lookupTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		perServerSeen := make(map[string]struct{}, len(ips))
		weight := dnsProbeServerWeight(server)
		publicServer := !isLoopbackDNSServer(server)
		for _, ip := range ips {
			addr := net.ParseIP(strings.TrimSpace(ip))
			if addr == nil {
				continue
			}
			if forceIPv4 && addr.To4() == nil {
				continue
			}
			key := addr.String()
			if key == "" {
				continue
			}
			if _, ok := perServerSeen[key]; ok {
				continue
			}
			perServerSeen[key] = struct{}{}
			sc := candidateScore[key]
			sc.hits++
			sc.score += weight
			if publicServer {
				sc.publicHits++
				sc.score++
			}
			candidateScore[key] = sc
		}
	}
	if len(candidateScore) > 0 {
		hasPublicBacked := false
		for _, sc := range candidateScore {
			if sc.publicHits > 0 {
				hasPublicBacked = true
				break
			}
		}
		resolved := make([]string, 0, len(candidateScore))
		for ip, sc := range candidateScore {
			if hasPublicBacked && sc.publicHits <= 0 {
				continue
			}
			resolved = append(resolved, ip)
		}
		if len(resolved) == 0 {
			for ip := range candidateScore {
				resolved = append(resolved, ip)
			}
		}
		sort.Slice(resolved, func(i, j int) bool {
			li := candidateScore[resolved[i]]
			lj := candidateScore[resolved[j]]
			if li.publicHits != lj.publicHits {
				return li.publicHits > lj.publicHits
			}
			if li.score != lj.score {
				return li.score > lj.score
			}
			if li.hits != lj.hits {
				return li.hits > lj.hits
			}
			return resolved[i] < resolved[j]
		})
		if len(resolved) > 8 {
			resolved = resolved[:8]
		}
		return resolved, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no address resolved for %s", host)
}

func dnsProbeServerWeight(server string) int {
	host, _, err := net.SplitHostPort(strings.TrimSpace(server))
	if err != nil {
		host = strings.TrimSpace(server)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	switch host {
	case "8.8.8.8", "1.1.1.1":
		return 5
	case "9.9.9.9", "119.29.29.29", "223.5.5.5":
		return 4
	default:
		if isLoopbackDNSServer(server) {
			return 2
		}
		return 3
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func lookupHostWithDNSServerTCP(host, server string, timeout time.Duration) ([]string, error) {
	ips, _, err := lookupHostWithDNSServerPreferTCP(host, server, timeout)
	return ips, err
}

func lookupHostWithDNSServerPreferTCP(host, server string, timeout time.Duration) ([]string, string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return nil, "tcp", fmt.Errorf("empty dns server")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	ips, err := lookupHostWithDNSServerNetwork(host, server, timeout, "tcp")
	if err == nil {
		return ips, "tcp", nil
	}
	tcpErr := err
	if shouldFallbackUDPDNSProbe(server, tcpErr.Error()) {
		udpTimeout := minDuration(timeout/2, 1200*time.Millisecond)
		if udpTimeout <= 0 {
			udpTimeout = minDuration(timeout, 1200*time.Millisecond)
		}
		ips, err = lookupHostWithDNSServerNetwork(host, server, udpTimeout, "udp")
		if err == nil {
			return ips, "udp", nil
		}
		return nil, "udp", fmt.Errorf("tcp: %v; udp: %w", tcpErr, err)
	}
	return nil, "tcp", tcpErr
}

func lookupHostWithDNSServerNetwork(host, server string, timeout time.Duration, network string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, server)
		},
	}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ipText := strings.TrimSpace(addr.IP.String())
		if ipText == "" {
			continue
		}
		out = append(out, ipText)
	}
	return appendUniqueStrings(nil, out...), nil
}

func isLoopbackDNSServer(server string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(server))
	if err != nil {
		host = strings.TrimSpace(server)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isHostnameMismatchError(err error) bool {
	if err == nil {
		return false
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return true
	}
	return isHostnameMismatchErrorText(strings.ToLower(err.Error()))
}

func isHostnameMismatchErrorText(lower string) bool {
	lower = strings.TrimSpace(strings.ToLower(lower))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "no alternative certificate subject name matches") ||
		strings.Contains(lower, "certificate is valid for") ||
		strings.Contains(lower, "certificate is not valid for any names") ||
		strings.Contains(lower, "certificate subject name") ||
		strings.Contains(lower, "hostname mismatch")
}

func appendUniqueStrings(base []string, extras ...string) []string {
	set := make(map[string]struct{}, len(base)+len(extras))
	out := make([]string, 0, len(base)+len(extras))
	for _, raw := range base {
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		if _, ok := set[text]; ok {
			continue
		}
		set[text] = struct{}{}
		out = append(out, text)
	}
	for _, raw := range extras {
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		if _, ok := set[text]; ok {
			continue
		}
		set[text] = struct{}{}
		out = append(out, text)
	}
	return out
}

func collectProbeResultRows(probeRes map[string]any) []map[string]any {
	rows, _ := probeRes["results"].([]map[string]any)
	if rows == nil {
		rawRows, _ := probeRes["results"].([]any)
		if len(rawRows) > 0 {
			rows = make([]map[string]any, 0, len(rawRows))
			for _, row := range rawRows {
				m, ok := row.(map[string]any)
				if !ok {
					continue
				}
				rows = append(rows, m)
			}
		}
	}
	return rows
}

func collectHostnameMismatchHosts(probeRes map[string]any) []string {
	rows := collectProbeResultRows(probeRes)
	if len(rows) == 0 {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, item := range rows {
		if !strings.EqualFold(strings.TrimSpace(asStringMap(item, "error_type")), "hostname_mismatch") {
			continue
		}
		host := strings.TrimSpace(asStringMap(item, "host"))
		if host == "" {
			rawURL := strings.TrimSpace(asStringMap(item, "url"))
			if rawURL != "" {
				if parsed, err := neturl.Parse(rawURL); err == nil {
					host = strings.TrimSpace(parsed.Hostname())
				}
			}
		}
		if host == "" {
			continue
		}
		out = append(out, host)
	}
	return appendUniqueStrings(nil, out...)
}

func collectProbeFailedHosts(probeRes map[string]any) []string {
	rows := collectProbeResultRows(probeRes)
	if len(rows) == 0 {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, item := range rows {
		okValue, _ := item["ok"].(bool)
		if okValue {
			continue
		}
		host := strings.TrimSpace(asStringMap(item, "host"))
		if host == "" {
			rawURL := strings.TrimSpace(asStringMap(item, "url"))
			if rawURL != "" {
				if parsed, err := neturl.Parse(rawURL); err == nil {
					host = strings.TrimSpace(parsed.Hostname())
				}
			}
		}
		if host == "" {
			continue
		}
		out = append(out, host)
	}
	return appendUniqueStrings(nil, out...)
}

func collectHostnameMismatchDomainIPBlocks(probeRes map[string]any) map[string][]string {
	rows := collectProbeResultRows(probeRes)
	if len(rows) == 0 {
		return nil
	}
	quarantine := make(map[string][]string)
	for _, item := range rows {
		if !strings.EqualFold(strings.TrimSpace(asStringMap(item, "error_type")), "hostname_mismatch") &&
			!strings.EqualFold(strings.TrimSpace(asStringMap(item, "resolved_probe_error_type")), "hostname_mismatch") {
			continue
		}
		host := strings.TrimSpace(asStringMap(item, "host"))
		if host == "" {
			rawURL := strings.TrimSpace(asStringMap(item, "url"))
			if rawURL != "" {
				if parsed, err := neturl.Parse(rawURL); err == nil {
					host = strings.TrimSpace(parsed.Hostname())
				}
			}
		}
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		ips := make([]string, 0, 8)
		if raw, ok := item["resolved_ips"].([]string); ok {
			ips = append(ips, raw...)
		} else if rawAny, okAny := item["resolved_ips"].([]any); okAny {
			for _, cell := range rawAny {
				text, _ := cell.(string)
				text = strings.TrimSpace(text)
				if text == "" {
					continue
				}
				ips = append(ips, text)
			}
		}
		if raw := strings.TrimSpace(asStringMap(item, "resolved_ip")); raw != "" {
			ips = append(ips, raw)
		}
		ips = append(ips, extractIPStringsFromText(asStringMap(item, "error"))...)
		ips = append(ips, extractIPStringsFromText(asStringMap(item, "resolved_probe_error"))...)
		cleaned := make([]string, 0, len(ips))
		for _, raw := range appendUniqueStrings(nil, ips...) {
			raw = strings.TrimSpace(strings.Trim(raw, "[]"))
			if raw == "" {
				continue
			}
			if ip := net.ParseIP(raw); ip != nil {
				cleaned = append(cleaned, ip.String())
			}
		}
		if len(cleaned) == 0 {
			continue
		}
		quarantine[host] = appendUniqueStrings(quarantine[host], cleaned...)
	}
	if len(quarantine) == 0 {
		return nil
	}
	return quarantine
}

func mergeDomainIPQuarantine(base map[string][]string, extra map[string][]string) map[string][]string {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = make(map[string][]string, len(extra))
	}
	for host, ips := range extra {
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		if len(ips) == 0 {
			continue
		}
		base[host] = appendUniqueStrings(base[host], ips...)
	}
	return base
}

func extractIPStringsFromText(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	tokens := strings.FieldsFunc(text, func(r rune) bool {
		switch {
		case r >= '0' && r <= '9':
			return false
		case r >= 'a' && r <= 'f':
			return false
		case r >= 'A' && r <= 'F':
			return false
		case r == '.' || r == ':' || r == '[' || r == ']':
			return false
		default:
			return true
		}
	})
	if len(tokens) == 0 {
		return nil
	}
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(strings.Trim(token, "[]"))
		if token == "" {
			continue
		}
		candidate := token
		if strings.Count(candidate, ":") == 1 && strings.Contains(candidate, ".") {
			if host, _, err := net.SplitHostPort(candidate); err == nil {
				candidate = strings.TrimSpace(strings.Trim(host, "[]"))
			}
		}
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		out = append(out, ip.String())
	}
	return appendUniqueStrings(nil, out...)
}

func asStringMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	text, _ := m[key].(string)
	return strings.TrimSpace(text)
}

func (s *apiState) runTunDNSResolutionProbe(hosts []string, servers []string, timeout time.Duration) (map[string]any, error) {
	hosts = appendUniqueStrings(nil, hosts...)
	if len(hosts) == 0 {
		return map[string]any{
			"summary": map[string]any{
				"ok":      false,
				"total":   0,
				"success": 0,
				"failed":  0,
			},
			"results": []map[string]any{},
		}, fmt.Errorf("no host to probe")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if len(servers) == 0 {
		servers = []string{"127.0.0.1:53", "223.5.5.5:53", "1.1.1.1:53", "8.8.8.8:53"}
	}

	type dnsRow struct {
		Host       string
		Server     string
		Network    string
		IPs        []string
		Error      string
		DurationMS int64
	}
	rows := make([]dnsRow, 0, len(hosts)*len(servers))
	success := 0
	failed := 0
	localDNS := func(server string) bool {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			host = server
		}
		host = strings.TrimSpace(strings.Trim(host, "[]"))
		if host == "" {
			return false
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}

	for _, host := range hosts {
		for _, server := range servers {
			srv := strings.TrimSpace(server)
			if srv == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(srv); err != nil {
				srv = net.JoinHostPort(srv, "53")
			}
			var (
				ips      []net.IPAddr
				err      error
				network  = "tcp"
				startAt  = time.Now()
				tcpError string
			)
			lookupWithNetwork := func(netName string, perTimeout time.Duration) ([]net.IPAddr, error) {
				if perTimeout <= 0 {
					perTimeout = timeout
				}
				ctx, cancel := context.WithTimeout(context.Background(), perTimeout)
				defer cancel()
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						d := net.Dialer{Timeout: perTimeout}
						return d.DialContext(ctx, netName, srv)
					},
				}
				return resolver.LookupIPAddr(ctx, host)
			}
			tcpTimeout := timeout
			if !localDNS(srv) {
				tcpTimeout = minDuration(timeout, 1800*time.Millisecond)
			}
			ips, err = lookupWithNetwork("tcp", tcpTimeout)
			if err != nil {
				tcpError = err.Error()
				if shouldFallbackUDPDNSProbe(srv, tcpError) {
					network = "udp"
					udpTimeout := minDuration(timeout/2, 1200*time.Millisecond)
					if udpTimeout <= 0 {
						udpTimeout = minDuration(timeout, 1200*time.Millisecond)
					}
					ips, err = lookupWithNetwork("udp", udpTimeout)
				}
			}
			row := dnsRow{
				Host:       host,
				Server:     srv,
				Network:    network,
				DurationMS: time.Since(startAt).Milliseconds(),
			}
			if err != nil {
				if tcpError != "" && network == "udp" {
					row.Error = fmt.Sprintf("tcp: %s; udp: %s", tcpError, err.Error())
				} else if tcpError != "" {
					row.Error = fmt.Sprintf("tcp: %s", tcpError)
				} else {
					row.Error = err.Error()
				}
				failed++
			} else {
				for _, item := range ips {
					row.IPs = append(row.IPs, item.IP.String())
				}
				if len(row.IPs) == 0 {
					row.Error = "no ip returned"
					failed++
				} else {
					success++
				}
			}
			rows = append(rows, row)
		}
	}

	resultRows := make([]map[string]any, 0, len(rows))
	for _, item := range rows {
		row := map[string]any{
			"host":        item.Host,
			"dns_server":  item.Server,
			"network":     item.Network,
			"duration_ms": item.DurationMS,
		}
		if item.Error != "" {
			row["ok"] = false
			row["error"] = item.Error
		} else {
			row["ok"] = true
			row["ips"] = item.IPs
		}
		resultRows = append(resultRows, row)
	}

	out := map[string]any{
		"summary": map[string]any{
			"ok":      success > 0 && failed == 0,
			"total":   len(rows),
			"success": success,
			"failed":  failed,
			"hosts":   hosts,
		},
		"results": resultRows,
	}
	if success == 0 {
		return out, fmt.Errorf("all dns probes failed")
	}
	return out, nil
}

func shouldFallbackUDPDNSProbe(server, tcpErr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(server))
	if err != nil {
		host = strings.TrimSpace(server)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	lower := strings.ToLower(strings.TrimSpace(tcpErr))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "deadline exceeded") {
		return false
	}
	if strings.Contains(lower, "connection refused") {
		return true
	}
	return false
}

func (s *apiState) runJSONTaskHandler(method, path string, payload any, handler http.HandlerFunc) (map[string]any, error) {
	var body io.Reader = http.NoBody
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code < 200 || rec.Code >= 300 {
		var out struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		msg := strings.TrimSpace(out.Error)
		if msg == "" {
			msg = strings.TrimSpace(rec.Body.String())
		}
		if msg == "" {
			msg = fmt.Sprintf("task handler failed: http %d", rec.Code)
		}
		return nil, errors.New(msg)
	}
	text := strings.TrimSpace(rec.Body.String())
	if text == "" {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func isAsyncRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("async")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func (s *apiState) maybeHandleAsyncTask(w http.ResponseWriter, r *http.Request, kind, method, path string, payload any, handler http.HandlerFunc) bool {
	if !isAsyncRequest(r) {
		return false
	}
	taskID := s.createTask(kind, "queued")
	go func() {
		if shouldWaitTunPriorityForTask(kind) {
			s.setTaskMessage(taskID, "waiting tun priority")
			if err := s.waitTunPriorityWindow(tunPriorityWaitTimeout); err != nil {
				payload := s.buildTunPriorityTimeoutPayload(kind, err)
				s.completeTask(taskID, payload, err, "waiting tun priority failed")
				return
			}
		}
		s.setTaskRunning(taskID, "running")
		res, err := s.runJSONTaskHandler(method, path, payload, handler)
		if err != nil {
			s.completeTask(taskID, nil, err, "task failed")
			return
		}
		s.completeTask(taskID, res, nil, "done")
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id": taskID,
		"task": map[string]any{
			"id":     taskID,
			"kind":   kind,
			"status": "pending",
		},
	})
	return true
}

func (s *apiState) createTask(kind, message string) string {
	s.taskMu.Lock()
	task := s.createTaskLocked(kind, message)
	s.taskMu.Unlock()
	return task.ID
}

func (s *apiState) createTaskLocked(kind, message string) *apiAsyncTask {
	if s.tasks == nil {
		s.tasks = make(map[string]*apiAsyncTask)
	}
	s.taskSeq++
	id := fmt.Sprintf("%s-%d-%d", strings.TrimSpace(kind), time.Now().UnixNano(), s.taskSeq)
	task := &apiAsyncTask{
		ID:        id,
		Kind:      kind,
		Status:    "pending",
		Message:   strings.TrimSpace(message),
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	s.tasks[id] = task
	s.cleanupTasksLocked(200)
	return task
}

func (s *apiState) setTaskRunning(taskID, message string) {
	s.taskMu.Lock()
	if task, ok := s.tasks[taskID]; ok && task != nil {
		task.Status = "running"
		task.Message = strings.TrimSpace(message)
		task.Error = ""
		task.StartedAt = time.Now().Format(time.RFC3339)
	}
	s.taskMu.Unlock()
}

func (s *apiState) setTaskMessage(taskID, message string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	s.taskMu.Lock()
	if task, ok := s.tasks[taskID]; ok && task != nil {
		status := strings.ToLower(strings.TrimSpace(task.Status))
		if status != "success" && status != "failed" {
			task.Message = message
		}
	}
	s.taskMu.Unlock()
}

func (s *apiState) updateTaskResult(taskID string, result any) {
	if s == nil || strings.TrimSpace(taskID) == "" {
		return
	}
	s.taskMu.Lock()
	if task, ok := s.tasks[taskID]; ok && task != nil {
		status := strings.ToLower(strings.TrimSpace(task.Status))
		if status != "success" && status != "failed" {
			task.Result = result
		}
	}
	s.taskMu.Unlock()
}

func (s *apiState) hasActiveTunTaskLocked() bool {
	if s == nil {
		return false
	}
	for _, task := range s.tasks {
		if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(task.Status))
		if status == "pending" || status == "running" {
			return true
		}
	}
	return false
}

func (s *apiState) hasRunningTunTaskLocked() bool {
	if s == nil {
		return false
	}
	for _, task := range s.tasks {
		if task == nil || !strings.EqualFold(task.Kind, "tun_toggle") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(task.Status), "running") {
			return true
		}
	}
	return false
}

func (s *apiState) waitTunPriorityWindow(timeout time.Duration) error {
	if s == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = tunPriorityWaitTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-s.ctx.Done():
			return fmt.Errorf("task context canceled")
		default:
		}
		now := time.Now()
		s.taskMu.Lock()
		s.reconcileTunTaskStateLocked(now)
		active := s.hasActiveTunTaskLocked()
		s.taskMu.Unlock()
		if !active {
			return nil
		}
		if now.After(deadline) {
			return fmt.Errorf("waiting for TUN priority timed out (%ds)", int(timeout.Seconds()))
		}
		time.Sleep(tunPriorityPollInterval)
	}
}

func (s *apiState) updateTaskProgress(taskID, message string) {
	message = strings.TrimSpace(message)
	if taskID == "" || message == "" {
		return
	}
	s.taskMu.Lock()
	if task, ok := s.tasks[taskID]; ok && task != nil {
		status := strings.ToLower(strings.TrimSpace(task.Status))
		if status != "success" && status != "failed" {
			task.Status = "running"
			task.Message = message
		}
	}
	s.taskMu.Unlock()
}

func (s *apiState) completeTask(taskID string, result any, taskErr error, message string) {
	s.taskMu.Lock()
	now := time.Now()
	if task, ok := s.tasks[taskID]; ok && task != nil {
		if taskErr != nil {
			task.Status = "failed"
			task.Error = taskErr.Error()
		} else {
			task.Status = "success"
			task.Error = ""
		}
		task.Result = result
		task.Message = strings.TrimSpace(message)
		task.FinishedAt = now.Format(time.RFC3339)
		if strings.EqualFold(task.Kind, "tun_toggle") && strings.TrimSpace(task.StartedAt) != "" {
			if startedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(task.StartedAt)); err == nil && now.After(startedAt) {
				dur := now.Sub(startedAt)
				if dur > 0 {
					if s.tunTaskAvgDuration <= 0 {
						s.tunTaskAvgDuration = dur
					} else {
						s.tunTaskAvgDuration = time.Duration((int64(s.tunTaskAvgDuration)*7 + int64(dur)*3) / 10)
					}
				}
			}
		}
	}
	s.cleanupTasksLocked(200)
	s.taskMu.Unlock()
}

func (s *apiState) wrapAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkAuth(w, r) {
			return
		}
		next(w, r)
	}
}

func (s *apiState) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	username, password := s.getAuthCredential()
	guard := s.authGuard

	if username == "" && password == "" {
		return true
	}
	authKey := authClientKey(r)
	if allowed, wait := guard.allow(authKey); !allowed {
		seconds := int(wait.Seconds())
		if seconds <= 0 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeError(w, http.StatusTooManyRequests, "too many auth failures, please retry later")
		return false
	}

	u, p, ok := r.BasicAuth()
	if !ok {
		_, _ = guard.recordFailure(authKey)
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
		if locked, wait := guard.recordFailure(authKey); locked {
			seconds := int(wait.Seconds())
			if seconds <= 0 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			writeError(w, http.StatusTooManyRequests, "too many auth failures, please retry later")
			return false
		}
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return false
	}
	guard.recordSuccess(authKey)
	return true
}

func authClientKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		items := strings.Split(xff, ",")
		if len(items) > 0 {
			return strings.TrimSpace(items[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (s *apiState) handleCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"current": s.manager.CurrentNodeName(),
		"default": s.cfg.DefaultNode,
	})
}

func (s *apiState) handleSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	if _, ok := findNodeByName(s.cfg.Nodes, req.Name); !ok {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	prev := s.manager.CurrentNodeName()
	if err := s.manager.Switch(req.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.tun != nil {
		node, ok := findNodeByName(s.cfg.Nodes, req.Name)
		if !ok {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		if err := s.tun.OnSwitch(node); err != nil {
			_ = s.manager.Switch(prev)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.resetDNSProbeStateLocked("manual-switch")
		s.applyBypassRoutesLocked("manual-switch")
	} else if s.cfg != nil && s.cfg.Tun != nil && s.cfg.Tun.Enabled && s.tunAutoRecoverSuspend {
		// Manual switch to a healthy node should unfreeze auto-recover.
		s.tunAutoRecoverSuspend = false
		s.tunAutoRecoverReason = ""
		s.tunAutoRecoverState.LastError = ""
		s.reconcileTunAutoRecoverMonitorLocked(s.cfg.Tun, "manual-switch-resume-auto-recover")
		s.recordRouteSelfHealEvent("info", "tun_auto_recover_resume", "manual switch resumed auto recover")
	}
	// Ensure existing connections do not keep using old routes/nodes after manual switch.
	s.reconnectAfterNodeSwitchLocked("manual-switch")
	writeJSON(w, http.StatusOK, map[string]any{
		"current": req.Name,
		"default": s.cfg.DefaultNode,
	})
}

func (s *apiState) handleImportNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	name, err := upsertNodeFromURI(s.cfg, req.Name, req.URI)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := saveClientConfig(s.configPath, s.cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node, ok := findNodeByName(s.cfg.Nodes, name); ok {
		s.manager.UpsertNode(node)
		if err := s.refreshCurrentIfUpdated(name); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if s.tun != nil {
			s.applyBypassRoutesLocked("import-node")
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name,
	})
}

func (s *apiState) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.lock.Lock()
		defer s.lock.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"current": s.manager.CurrentNodeName(),
			"default": s.cfg.DefaultNode,
			"nodes":   s.cfg.Nodes,
		})
	case http.MethodPost:
		var req clientNodeConfig
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}

		s.lock.Lock()
		defer s.lock.Unlock()
		if _, ok := findNodeByName(s.cfg.Nodes, req.Name); ok {
			writeError(w, http.StatusConflict, "node already exists")
			return
		}
		if err := normalizeNode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.cfg.Nodes = append(s.cfg.Nodes, req)
		if err := saveClientConfig(s.configPath, s.cfg); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.manager.UpsertNode(req)
		if s.tun != nil {
			s.applyBypassRoutesLocked("create-node")
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"name": req.Name,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *apiState) handleNodeExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	group := strings.TrimSpace(r.URL.Query().Get("group"))
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		writeError(w, http.StatusBadRequest, "format must be text or json")
		return
	}

	s.lock.Lock()
	nodes := append([]clientNodeConfig(nil), s.cfg.Nodes...)
	s.lock.Unlock()

	type item struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	items := make([]item, 0, len(nodes))
	textLines := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if group != "" {
			matched := false
			for _, g := range node.Groups {
				if strings.TrimSpace(g) == group {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		uri, err := buildAnyTLSURIFromNode(node)
		if err != nil {
			continue
		}
		items = append(items, item{Name: node.Name, URI: uri})
		textLines = append(textLines, fmt.Sprintf("%s,%s", node.Name, uri))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"group":  group,
		"format": format,
		"count":  len(items),
		"items":  items,
		"text":   strings.Join(textLines, "\n"),
	})
}

func (s *apiState) handleNodeByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req clientNodeConfig
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.lock.Lock()
		defer s.lock.Unlock()
		index := -1
		for i := range s.cfg.Nodes {
			if s.cfg.Nodes[i].Name == name {
				index = i
				break
			}
		}
		if index < 0 {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}

		if strings.TrimSpace(req.URI) != "" {
			newName, err := upsertNodeFromURI(s.cfg, name, req.URI)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := saveClientConfig(s.configPath, s.cfg); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if node, ok := findNodeByName(s.cfg.Nodes, newName); ok {
				s.manager.UpsertNode(node)
				if err := s.refreshCurrentIfUpdated(newName); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				if s.tun != nil {
					s.applyBypassRoutesLocked("update-node-uri")
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{"name": newName})
			return
		}

		node := s.cfg.Nodes[index]
		if v := strings.TrimSpace(req.Server); v != "" {
			node.Server = v
		}
		if v := strings.TrimSpace(req.Password); v != "" {
			node.Password = v
		}
		if v := strings.TrimSpace(req.SNI); v != "" {
			node.SNI = v
		}
		if v := strings.TrimSpace(req.EgressIP); v != "" {
			node.EgressIP = v
		}
		if v := strings.TrimSpace(req.EgressRule); v != "" {
			node.EgressRule = v
		}
		if req.Groups != nil {
			node.Groups = append([]string(nil), req.Groups...)
		}
		if err := normalizeNode(&node); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.cfg.Nodes[index] = node
		if err := saveClientConfig(s.configPath, s.cfg); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.manager.UpsertNode(node)
		if err := s.refreshCurrentIfUpdated(name); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if s.tun != nil {
			s.applyBypassRoutesLocked("update-node")
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": name})
	case http.MethodDelete:
		s.lock.Lock()
		defer s.lock.Unlock()
		if len(s.cfg.Nodes) <= 1 {
			writeError(w, http.StatusBadRequest, "cannot delete last node")
			return
		}

		index := -1
		for i := range s.cfg.Nodes {
			if s.cfg.Nodes[i].Name == name {
				index = i
				break
			}
		}
		if index < 0 {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}

		s.cfg.Nodes = append(s.cfg.Nodes[:index], s.cfg.Nodes[index+1:]...)

		current := s.manager.CurrentNodeName()
		if current == name {
			target := s.cfg.DefaultNode
			if target == name || target == "" {
				target = s.cfg.Nodes[0].Name
			}
			if err := s.manager.Switch(target); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.cfg.DefaultNode = target
			if s.tun != nil {
				node, ok := findNodeByName(s.cfg.Nodes, target)
				if !ok {
					writeError(w, http.StatusNotFound, "node not found")
					return
				}
				if err := s.tun.OnSwitch(node); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				s.resetDNSProbeStateLocked("delete-node-switch")
				s.applyBypassRoutesLocked("delete-node-switch")
			}
		} else if s.cfg.DefaultNode == name {
			s.cfg.DefaultNode = current
			if s.cfg.DefaultNode == "" {
				s.cfg.DefaultNode = s.cfg.Nodes[0].Name
			}
		}
		if s.cfg.Routing != nil && len(s.cfg.Routing.GroupEgress) > 0 {
			next := make(map[string]string, len(s.cfg.Routing.GroupEgress))
			for group, targetNode := range s.cfg.Routing.GroupEgress {
				if strings.TrimSpace(targetNode) == name {
					continue
				}
				next[group] = targetNode
			}
			s.cfg.Routing.GroupEgress = normalizeRoutingGroupEgress(next)
		}

		if err := saveClientConfig(s.configPath, s.cfg); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.manager.DeleteNode(name)
		if s.tun != nil {
			s.applyBypassRoutesLocked("delete-node")
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *apiState) refreshCurrentIfUpdated(nodeName string) error {
	if s.manager.CurrentNodeName() != nodeName {
		return nil
	}
	if err := s.manager.Switch(nodeName); err != nil {
		return err
	}
	if s.tun != nil {
		node, ok := findNodeByName(s.cfg.Nodes, nodeName)
		if !ok {
			return fmt.Errorf("node not found: %s", nodeName)
		}
		if err := s.tun.OnSwitch(node); err != nil {
			return err
		}
		s.resetDNSProbeStateLocked("refresh-current")
		s.applyBypassRoutesLocked("refresh-current")
		return nil
	}
	return nil
}

func cloneTunConfig(in *clientTunConfig) *clientTunConfig {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func routingReconnectRequired(prev, next *clientRoutingConfig) bool {
	if prev == nil && next == nil {
		return false
	}
	if prev == nil || next == nil {
		return true
	}
	return !reflect.DeepEqual(prev, next)
}

func cloneRoutingConfig(in *clientRoutingConfig) *clientRoutingConfig {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Rules) > 0 {
		out.Rules = append([]string(nil), in.Rules...)
	}
	if len(in.RuleProviders) > 0 {
		out.RuleProviders = make(map[string]clientRuleProvider, len(in.RuleProviders))
		for name, provider := range in.RuleProviders {
			p := provider
			if len(provider.Payload) > 0 {
				p.Payload = append([]string(nil), provider.Payload...)
			}
			if len(provider.Header) > 0 {
				p.Header = make(map[string][]string, len(provider.Header))
				for k, v := range provider.Header {
					p.Header[k] = append([]string(nil), v...)
				}
			}
			out.RuleProviders[name] = p
		}
	}
	if len(in.GroupEgress) > 0 {
		out.GroupEgress = make(map[string]string, len(in.GroupEgress))
		for group, node := range in.GroupEgress {
			out.GroupEgress[group] = node
		}
	}
	out.GeoIP = cloneRoutingGeoIPConfig(in.GeoIP)
	return &out
}

func cloneRoutingGeoIPConfig(in *clientRoutingGeoIPConfig) *clientRoutingGeoIPConfig {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Header) > 0 {
		out.Header = make(map[string][]string, len(in.Header))
		for k, v := range in.Header {
			out.Header[k] = append([]string(nil), v...)
		}
	}
	return &out
}

func cloneMITMConfig(in *clientMITMConfig) *clientMITMConfig {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Hosts) > 0 {
		out.Hosts = append([]string(nil), in.Hosts...)
	}
	if len(in.URLReject) > 0 {
		out.URLReject = append([]string(nil), in.URLReject...)
	}
	out.DoHDoT = cloneMITMDoHDoTConfig(in.DoHDoT)
	return &out
}

func cloneMITMDoHDoTConfig(in *clientMITMDoHDoTConfig) *clientMITMDoHDoTConfig {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.DoHHosts) > 0 {
		out.DoHHosts = append([]string(nil), in.DoHHosts...)
	}
	if len(in.DoTHosts) > 0 {
		out.DoTHosts = append([]string(nil), in.DoTHosts...)
	}
	return &out
}

func closeTunRuntimeWithTimeout(rt *tunRuntime, timeout time.Duration) error {
	if rt == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	done := make(chan error, 1)
	go func() {
		done <- rt.Close()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("close tun runtime timeout after %s", timeout)
	}
}

func resetManagerClientsWithTimeout(manager *runtimeClientManager, timeout time.Duration) error {
	if manager == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	done := make(chan error, 1)
	go func() {
		done <- manager.ResetClients()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("reset clients timeout after %s", timeout)
	}
}

func (s *apiState) reconcileTunLocked(next *clientTunConfig, report func(string)) (bool, error) {
	reportStep := func(msg string) {
		if report != nil {
			report(msg)
		}
	}
	defer s.reconcileTunAutoRecoverMonitorLocked(next, "reconcile-tun")
	if next != nil && next.Enabled {
		// User explicitly enables TUN: clear fail-open suspension.
		s.tunAutoRecoverSuspend = false
		s.tunAutoRecoverReason = ""
		if strings.Contains(s.tunAutoRecoverState.LastError, "自动恢复已暂停") {
			s.tunAutoRecoverState.LastError = ""
		}
	}

	if next == nil || !next.Enabled {
		if s.tun != nil {
			reportStep("正在关闭 TUN 运行时")
			logrus.Infoln("[Client] TUN 切换步骤 1/2: 正在关闭 TUN 运行时")
			old := s.tun
			s.tun = nil
			s.lock.Unlock()
			closeErr := closeTunRuntimeWithTimeout(old, 6*time.Second)
			resetErr := resetManagerClientsWithTimeout(s.manager, 8*time.Second)
			s.lock.Lock()
			if closeErr != nil {
				// Avoid blocking API responses on teardown edge cases; runtime already detached.
				logrus.Warnln("[Client] tun disable cleanup warning:", closeErr)
			}
			reportStep("TUN 运行时关闭完成")
			logrus.Infoln("[Client] TUN 切换步骤 2/2: 已关闭 TUN 运行时")
			s.recordRouteSelfHealEvent("info", "tun_disable", "TUN runtime stopped by config toggle")
			if resetErr != nil {
				logrus.Warnln("[Client] reset clients after tun disable failed:", resetErr)
			} else {
				reportStep("会话池重建完成")
				logrus.Infoln("[Client] TUN 切换步骤: 已重建客户端会话池（避免旧连接断流）")
			}
			logrus.Infoln("[Client] tun disabled")
			reportStep("TUN 已关闭")
			return true, nil
		}
		return false, nil
	}

	current := s.manager.CurrentNodeName()
	node, ok := findNodeByName(s.cfg.Nodes, current)
	if !ok {
		return false, fmt.Errorf("current node not found: %s", current)
	}

	if s.tun != nil && s.tun.sameConfig(*next) {
		reportStep("复用现有 TUN，正在切换当前节点")
		currentTun := s.tun
		s.lock.Unlock()
		switchErr := currentTun.OnSwitch(node)
		s.lock.Lock()
		if switchErr != nil {
			return false, switchErr
		}
		if s.tun != currentTun {
			return false, fmt.Errorf("tun runtime changed while applying switch, please retry")
		}
		s.applyBypassRoutesLocked("tun-reuse")
		reportStep("节点切换完成，旁路目标已后台刷新")
		return false, nil
	}

	if s.tun != nil {
		reportStep("正在关闭旧的 TUN 运行时")
		old := s.tun
		s.tun = nil
		s.lock.Unlock()
		closeErr := closeTunRuntimeWithTimeout(old, 6*time.Second)
		s.lock.Lock()
		if closeErr != nil {
			logrus.Warnln("[Client] tun replace cleanup warning:", closeErr)
		}
		reportStep("旧 TUN 已关闭")
	}

	reportStep("正在启动 TUN 运行时（创建接口/路由）")
	logrus.Infoln("[Client] TUN 切换步骤 1/3: 正在启动 TUN 运行时")
	ctx := s.ctx
	listen := s.activeListen
	if report != nil {
		ctx = withTunStartProgressCallback(ctx, func(message string) {
			reportStep(message)
		})
	}
	s.lock.Unlock()
	tun, err := startTunRuntimeWithTimeout(ctx, *next, listen, node, 15*time.Second)
	s.lock.Lock()
	if err != nil {
		s.recordRouteSelfHealEvent("warn", "tun_enable_failed", err.Error())
		return false, err
	}
	reportStep("TUN 运行时已启动，正在重建会话池")
	logrus.Infoln("[Client] TUN 切换步骤 2/3: TUN 运行时已启动")
	s.tun = tun
	s.lock.Unlock()
	resetErr := resetManagerClientsWithTimeout(s.manager, 8*time.Second)
	s.lock.Lock()
	if resetErr != nil {
		logrus.Warnln("[Client] reset clients after tun enable failed:", resetErr)
	} else {
		reportStep("会话池重建完成")
		logrus.Infoln("[Client] TUN 切换步骤: 已重建客户端会话池（避免旧连接断流）")
	}
	s.applyBypassRoutesLocked("tun-enable")
	reportStep("旁路目标已转后台下发")
	logrus.Infoln("[Client] TUN 切换步骤 3/3: 旁路目标下发已转后台执行")
	logrus.Infoln("[Client] tun enabled", next.Name, "auto_route=", next.AutoRoute, "address=", next.Address)
	s.recordRouteSelfHealEvent("info", "tun_enable", fmt.Sprintf("name=%s auto_route=%v", next.Name, next.AutoRoute))
	reportStep("TUN 启用完成")
	return true, nil
}

func (s *apiState) reconcileTunAutoRecoverMonitorLocked(next *clientTunConfig, reason string) {
	if s == nil {
		return
	}
	wantRunning := next != nil && next.Enabled && s.tun == nil
	if wantRunning {
		if s.tunAutoRecoverRunning {
			return
		}
		monitorCtx, cancel := context.WithCancel(s.ctx)
		s.tunAutoRecoverCancel = cancel
		s.tunAutoRecoverRunning = true
		logrus.Infof("[Client] TUN 自动恢复监测已启动 (%s)", reason)
		go s.tunAutoRecoverLoop(monitorCtx)
		return
	}
	s.stopTunAutoRecoverMonitorLocked(reason)
}

func (s *apiState) stopTunAutoRecoverMonitorLocked(reason string) {
	if s == nil || !s.tunAutoRecoverRunning {
		return
	}
	cancel := s.tunAutoRecoverCancel
	s.tunAutoRecoverCancel = nil
	s.tunAutoRecoverRunning = false
	if cancel != nil {
		cancel()
	}
	if strings.TrimSpace(reason) != "" {
		logrus.Infof("[Client] TUN 自动恢复监测已停止 (%s)", reason)
	}
}

func (s *apiState) tunAutoRecoverLoop(ctx context.Context) {
	if s == nil {
		return
	}
	tryStart := func() {
		s.lock.Lock()
		if !s.tunAutoRecoverRunning || s.tun != nil {
			s.lock.Unlock()
			return
		}
		if s.tunAutoRecoverSuspend {
			if strings.TrimSpace(s.tunAutoRecoverReason) != "" {
				s.tunAutoRecoverState.LastError = "自动恢复暂停中: " + s.tunAutoRecoverReason
			} else {
				s.tunAutoRecoverState.LastError = "自动恢复暂停中"
			}
			s.lock.Unlock()
			return
		}
		cfg := cloneTunConfig(s.cfg.Tun)
		listen := s.activeListen
		current := s.manager.CurrentNodeName()
		node, ok := findNodeByName(s.cfg.Nodes, current)
		s.tunAutoRecoverState.LastAttemptAt = time.Now().Format(time.RFC3339)
		s.lock.Unlock()

		if cfg == nil || !cfg.Enabled {
			return
		}
		if !ok {
			s.lock.Lock()
			s.tunAutoRecoverState.LastError = fmt.Sprintf("current node not found: %s", current)
			s.lock.Unlock()
			return
		}

		ready, detail, uplinkErr := detectTunAutoRecoverUplink()
		if uplinkErr != nil {
			s.lock.Lock()
			s.tunAutoRecoverState.LastError = uplinkErr.Error()
			s.lock.Unlock()
			logrus.Warnf("[Client] TUN 自动恢复: 物理路由检测失败: %v", uplinkErr)
			return
		}
		if !ready {
			waiting := "物理上行路由未就绪"
			if strings.TrimSpace(detail) != "" {
				waiting = fmt.Sprintf("物理上行路由未就绪（当前默认路由: %s）", detail)
			}
			s.lock.Lock()
			s.tunAutoRecoverState.LastError = waiting
			s.lock.Unlock()
			return
		}

		logrus.Infof("[Client] TUN 自动恢复: 检测到物理上行路由 %s，开始重启 TUN", detail)
		s.recordRouteSelfHealEvent("info", "tun_auto_recover_attempt", fmt.Sprintf("uplink=%s", detail))
		tun, err := startTunRuntimeWithTimeout(s.ctx, *cfg, listen, node, 15*time.Second)
		if err != nil {
			s.lock.Lock()
			s.tunAutoRecoverState.LastError = err.Error()
			s.lock.Unlock()
			logrus.Warnf("[Client] TUN 自动恢复: 启动失败: %v", err)
			s.recordRouteSelfHealEvent("warn", "tun_auto_recover_failed", err.Error())
			return
		}

		s.lock.Lock()
		if !s.tunAutoRecoverRunning {
			s.lock.Unlock()
			_ = tun.Close()
			return
		}
		if s.tun != nil {
			s.lock.Unlock()
			_ = tun.Close()
			return
		}
		s.tun = tun
		s.tunAutoRecoverState.LastSuccessAt = time.Now().Format(time.RFC3339)
		s.tunAutoRecoverState.LastError = ""
		s.applyBypassRoutesLocked("tun-auto-recover")
		s.reconcileTunAutoRecoverMonitorLocked(cfg, "tun-auto-recover-success")
		s.lock.Unlock()
		logrus.Infoln("[Client] TUN 自动恢复: 启动成功")
		s.recordRouteSelfHealEvent("info", "tun_auto_recover_success", fmt.Sprintf("node=%s", current))
	}

	tryStart()
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tryStart()
		}
	}
}

func detectTunAutoRecoverUplink() (bool, string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := runCommand("route", "-n", "get", "default")
		if err != nil {
			if isDarwinRouteNotInTableText(err.Error()) {
				return false, "route-not-ready", nil
			}
			return false, "", fmt.Errorf("read default route failed: %w", err)
		}
		gateway, iface := parseDarwinRouteGetOutput(out)
		if strings.TrimSpace(iface) == "" {
			return false, "", fmt.Errorf("cannot parse default interface from route output: %q", out)
		}
		if strings.HasPrefix(strings.ToLower(iface), "utun") {
			return false, iface, nil
		}
		if gateway != "" {
			return true, fmt.Sprintf("%s via %s", iface, gateway), nil
		}
		return true, iface, nil
	case "linux":
		spec, _, dev, err := detectLinuxDefaultRoute()
		if err != nil {
			return false, "", fmt.Errorf("read default route failed: %w", err)
		}
		if strings.TrimSpace(dev) == "" {
			return false, "", fmt.Errorf("cannot parse default route device from spec: %q", spec)
		}
		lowerDev := strings.ToLower(dev)
		if strings.HasPrefix(lowerDev, "tun") || strings.HasPrefix(lowerDev, "utun") || strings.HasPrefix(lowerDev, "wg") {
			return false, dev, nil
		}
		if strings.TrimSpace(spec) == "" {
			return true, dev, nil
		}
		return true, spec, nil
	default:
		return true, runtime.GOOS, nil
	}
}

func (s *apiState) applyBypassRoutesAsync(reason string) {
	if s == nil {
		return
	}
	s.lock.Lock()
	start, initialReason := s.scheduleBypassApplyLocked(reason)
	s.lock.Unlock()
	if !start {
		return
	}
	go s.runBypassApplyLoop(initialReason)
}

func (s *apiState) applyBypassRoutesLocked(reason string) {
	if s == nil {
		return
	}
	start, initialReason := s.scheduleBypassApplyLocked(reason)
	if !start {
		return
	}
	go s.runBypassApplyLoop(initialReason)
}

func (s *apiState) scheduleBypassApplyLocked(reason string) (bool, string) {
	if s == nil {
		return false, ""
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "manual"
	}
	if s.bypassApplyRunning {
		s.bypassApplyPending = true
		s.bypassApplyReason = reason
		return false, ""
	}
	s.bypassApplyRunning = true
	s.bypassApplyReason = reason
	return true, reason
}

func (s *apiState) runBypassApplyLoop(initialReason string) {
	if s == nil {
		return
	}
	currentReason := strings.TrimSpace(initialReason)
	if currentReason == "" {
		currentReason = "manual"
	}
	for {
		started := time.Now()
		s.lock.Lock()
		tun := s.tun
		currentName := ""
		currentServer := ""
		if s.manager != nil {
			currentName = strings.TrimSpace(s.manager.CurrentNodeName())
		}
		if tun == nil {
			s.bypassApplyRunning = false
			s.bypassApplyPending = false
			s.bypassApplyReason = ""
			s.lock.Unlock()
			return
		}
		nodes := append([]clientNodeConfig(nil), s.cfg.Nodes...)
		if currentName != "" {
			if node, ok := findNodeByName(nodes, currentName); ok {
				currentServer = strings.TrimSpace(node.Server)
			}
		}
		upstreams := make([]string, 0)
		if s.dnsHijacker != nil {
			upstreams = append(upstreams, s.dnsHijacker.RouteBypassTargets()...)
		}
		s.lock.Unlock()

		logrus.Infof("[Client] TUN 路由步骤: 正在执行 旁路目标下发 (%s)", currentReason)
		nodeStatus := s.applyNodeBypassForTargets(tun, nodes, currentServer, currentReason)
		s.applyDNSBypassForTargets(tun, upstreams, currentReason)
		s.lock.Lock()
		if s.tun == tun {
			s.nodeBypass = nodeStatus
		}
		s.lock.Unlock()
		if nodeStatus.Failed > 0 {
			s.recordRouteSelfHealEvent("warn", "node_bypass_update", fmt.Sprintf("reason=%s failed=%d targets=%s", currentReason, nodeStatus.Failed, strings.Join(nodeStatus.FailedTargets, ",")))
		} else if nodeStatus.Total > 0 && (currentReason == "startup" || currentReason == "tun-enable" || currentReason == "manual-switch") {
			s.recordRouteSelfHealEvent("info", "node_bypass_update", fmt.Sprintf("reason=%s success=%d total=%d", currentReason, nodeStatus.Success, nodeStatus.Total))
		}
		logrus.Infof("[Client] TUN 路由步骤: 完成 旁路目标下发 (%s) (%s)", currentReason, time.Since(started).Round(time.Millisecond))

		s.lock.Lock()
		if s.bypassApplyPending {
			currentReason = strings.TrimSpace(s.bypassApplyReason)
			if currentReason == "" {
				currentReason = "coalesced"
			}
			s.bypassApplyPending = false
			s.bypassApplyReason = ""
			s.lock.Unlock()
			continue
		}
		s.bypassApplyRunning = false
		s.bypassApplyReason = ""
		s.lock.Unlock()
		return
	}
}

func (s *apiState) resetDNSProbeStateLocked(reason string) {
	if s == nil {
		return
	}
	if s.dnsHijacker != nil {
		s.dnsHijacker.ResetUpstreamHealth(reason)
	}
}

func normalizeServerKey(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return strings.ToLower(server)
	}
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	port = strings.TrimSpace(port)
	if host == "" {
		return strings.ToLower(server)
	}
	if port == "" {
		return host
	}
	return strings.ToLower(net.JoinHostPort(host, port))
}

func detectLinuxServerRouteOnTun(server string) (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(server))
	if err != nil {
		return false, "", fmt.Errorf("invalid server address: %w", err)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	targetIPv4, err := resolveIPv4ForServerHost(host)
	if err != nil {
		return false, "", err
	}
	out, err := runCommand("ip", "-4", "route", "get", targetIPv4)
	if err != nil {
		return false, "", err
	}
	_, dev, _ := parseLinuxRouteGetOutput(out)
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return false, "", fmt.Errorf("cannot parse route device from output")
	}
	return isLikelyTunInterfaceName(dev), dev, nil
}

func (s *apiState) tryRecoverNodeBypass(server string) bool {
	server = strings.TrimSpace(server)
	if s == nil || server == "" {
		return false
	}
	key := normalizeServerKey(server)
	now := time.Now()

	knownNodes := map[string]struct{}{}
	s.lock.Lock()
	tun := s.tun
	if s.cfg != nil {
		for _, node := range s.cfg.Nodes {
			nodeKey := normalizeServerKey(node.Server)
			if nodeKey == "" {
				continue
			}
			knownNodes[nodeKey] = struct{}{}
		}
	}
	s.lock.Unlock()
	if tun == nil {
		return false
	}
	if key != "" && len(knownNodes) > 0 {
		if _, ok := knownNodes[key]; !ok {
			// Ignore unknown target to avoid accidental repair storms on non-node destinations.
			return false
		}
	}
	if key == "" {
		return false
	}

	s.loopRepairMu.Lock()
	if until, ok := s.loopRepairBlockedUntil[key]; ok {
		if now.Before(until) {
			s.loopRepairMu.Unlock()
			return false
		}
		delete(s.loopRepairBlockedUntil, key)
	}
	if s.loopRepairInFlight[key] {
		s.loopRepairMu.Unlock()
		// A repair for this target is already in progress.
		// Skip immediate re-dial to avoid repair storms under high concurrency.
		return false
	}
	if lastAt, ok := s.loopRepairLast[key]; ok && now.Sub(lastAt) < loopRepairCooldown {
		s.loopRepairMu.Unlock()
		// Recent repair was just attempted; avoid hammering route updates.
		return false
	}
	s.loopRepairInFlight[key] = true
	s.loopRepairMu.Unlock()
	defer func() {
		s.loopRepairMu.Lock()
		s.loopRepairInFlight[key] = false
		s.loopRepairLast[key] = time.Now()
		s.loopRepairMu.Unlock()
	}()

	destination := M.ParseSocksaddr(server)
	if !destination.IsValid() {
		logrus.Warnf("[Client] auto bypass repair skipped: invalid server %s", server)
		s.recordRouteSelfHealEvent("warn", "loop_repair_skip", fmt.Sprintf("invalid server %s", server))
		return false
	}
	if err := tun.EnsureDirectBypass(destination); err != nil {
		logrus.Warnf("[Client] auto bypass repair failed for %s: %v", server, err)
		s.recordRouteSelfHealEvent("warn", "loop_repair_failed", fmt.Sprintf("server=%s err=%v", server, err))
		return false
	}

	if runtime.GOOS == "linux" {
		onTun, dev, verifyErr := detectLinuxServerRouteOnTun(server)
		if verifyErr != nil {
			logrus.Warnf("[Client] auto bypass repair verify failed for %s: %v", server, verifyErr)
			s.recordRouteSelfHealEvent("warn", "loop_repair_verify_failed", fmt.Sprintf("server=%s err=%v", server, verifyErr))
		} else if onTun {
			triggerGlobal := false
			s.loopRepairMu.Lock()
			s.loopRepairBlockedUntil[key] = time.Now().Add(loopRepairBlockedFor)
			if time.Since(s.loopRepairLastGlobal) >= loopRepairGlobalCooldown {
				s.loopRepairLastGlobal = time.Now()
				triggerGlobal = true
			}
			s.loopRepairMu.Unlock()
			if triggerGlobal {
				s.applyBypassRoutesAsync("loop-repair-verify-failed")
			}
			logrus.Warnf("[Client] auto bypass repair still on tun route for %s (dev=%s), suspended for %s", server, dev, loopRepairBlockedFor)
			s.recordRouteSelfHealEvent("warn", "loop_repair_still_tun", fmt.Sprintf("server=%s dev=%s", server, dev))
			return false
		}
	}

	logrus.Debugf("[Client] auto bypass repair applied for %s", server)
	s.recordRouteSelfHealEvent("info", "loop_repair_applied", server)
	return true
}

func (s *apiState) isTunBypassRecoverActive() bool {
	if s == nil {
		return false
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.tun != nil
}

func (s *apiState) recordRouteSelfHealEvent(level, action, detail string) {
	if s == nil {
		return
	}
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "" {
		level = "info"
	}
	action = strings.TrimSpace(action)
	detail = strings.TrimSpace(detail)
	if action == "" {
		return
	}
	now := time.Now()
	key := level + "|" + action + "|" + detail

	s.routeSelfHealMu.Lock()
	defer s.routeSelfHealMu.Unlock()
	if key == s.routeSelfHealLastKey && now.Sub(s.routeSelfHealLastAt) < 12*time.Second {
		return
	}
	s.routeSelfHealLastKey = key
	s.routeSelfHealLastAt = now
	s.routeSelfHealEvents = append(s.routeSelfHealEvents, routeSelfHealEvent{
		Time:   now.Format(time.RFC3339),
		Level:  level,
		Action: action,
		Detail: detail,
	})
	if len(s.routeSelfHealEvents) > 120 {
		s.routeSelfHealEvents = append([]routeSelfHealEvent(nil), s.routeSelfHealEvents[len(s.routeSelfHealEvents)-120:]...)
	}
}

func isNodeBypassResolveError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "resolve server host") ||
		strings.Contains(msg, "resolve target host") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "temporary failure in name resolution") ||
		(strings.Contains(msg, "lookup") && strings.Contains(msg, "i/o timeout"))
}

func (s *apiState) nodeBypassCircuitRemaining(target string, now time.Time) (time.Duration, bool) {
	if s == nil {
		return 0, false
	}
	s.nodeBypassCircuitMu.Lock()
	defer s.nodeBypassCircuitMu.Unlock()
	until, ok := s.nodeBypassOpenUntil[target]
	if !ok {
		return 0, false
	}
	if !now.Before(until) {
		delete(s.nodeBypassOpenUntil, target)
		return 0, false
	}
	return until.Sub(now), true
}

func (s *apiState) nodeBypassMarkSuccess(target string) {
	if s == nil || target == "" {
		return
	}
	s.nodeBypassCircuitMu.Lock()
	delete(s.nodeBypassFailCount, target)
	delete(s.nodeBypassOpenUntil, target)
	s.nodeBypassCircuitMu.Unlock()
}

func (s *apiState) nodeBypassMarkFailure(target string, now time.Time, resolveFailure bool) (opened bool, until time.Time, failures int) {
	if s == nil || target == "" {
		return false, time.Time{}, 0
	}
	s.nodeBypassCircuitMu.Lock()
	defer s.nodeBypassCircuitMu.Unlock()
	failures = s.nodeBypassFailCount[target] + 1
	s.nodeBypassFailCount[target] = failures

	threshold := 2
	base := 10 * time.Second
	if resolveFailure {
		threshold = 1
		base = 30 * time.Second
	}
	if failures < threshold {
		delete(s.nodeBypassOpenUntil, target)
		return false, time.Time{}, failures
	}
	shift := failures - threshold
	openFor := base
	if shift > 0 {
		openFor = base * time.Duration(1<<shift)
	}
	if openFor > nodeBypassCircuitMax {
		openFor = nodeBypassCircuitMax
	}
	until = now.Add(openFor)
	s.nodeBypassOpenUntil[target] = until
	return true, until, failures
}

func (s *apiState) applyNodeBypassForTargets(tun *tunRuntime, nodes []clientNodeConfig, preferredServer, reason string) nodeBypassStatus {
	status := nodeBypassStatus{
		FailedTargets:  make([]string, 0, 8),
		SkippedTargets: make([]string, 0, 8),
		UpdatedAt:      time.Now().Format(time.RFC3339),
	}
	if s == nil || tun == nil {
		return status
	}
	if len(nodes) == 0 {
		return status
	}
	seen := make(map[string]struct{}, len(nodes))
	ordered := make([]string, 0, len(nodes))
	preferredServer = strings.TrimSpace(preferredServer)
	if preferredServer != "" {
		ordered = append(ordered, preferredServer)
	}
	for _, node := range nodes {
		target := strings.TrimSpace(node.Server)
		if target == "" {
			continue
		}
		ordered = append(ordered, target)
	}

	for _, target := range ordered {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		status.Total++
		if wait, open := s.nodeBypassCircuitRemaining(target, time.Now()); open {
			status.Skipped++
			status.SkippedTargets = append(status.SkippedTargets, target)
			s.recordRouteSelfHealEvent("warn", "node_bypass_circuit_open", fmt.Sprintf("target=%s wait=%s reason=%s", target, wait.Round(time.Second), reason))
			continue
		}

		destination := M.ParseSocksaddr(target)
		if !destination.IsValid() {
			status.Failed++
			status.FailedTargets = append(status.FailedTargets, target)
			s.nodeBypassMarkFailure(target, time.Now(), false)
			logrus.Warnf("[Client] node bypass route skip invalid server (%s): %s", reason, target)
			continue
		}
		if destination.IsIP() && destination.Addr.IsLoopback() {
			status.Skipped++
			status.SkippedTargets = append(status.SkippedTargets, target)
			s.nodeBypassMarkSuccess(target)
			continue
		}
		if destination.IsFqdn() && strings.EqualFold(strings.TrimSpace(destination.Fqdn), "localhost") {
			status.Skipped++
			status.SkippedTargets = append(status.SkippedTargets, target)
			s.nodeBypassMarkSuccess(target)
			continue
		}
		if err := tun.EnsureDirectBypass(destination); err != nil {
			resolveErr := isNodeBypassResolveError(err)
			opened, until, failures := s.nodeBypassMarkFailure(target, time.Now(), resolveErr)
			if resolveErr {
				status.Skipped++
				status.SkippedTargets = append(status.SkippedTargets, target)
				logrus.Warnf("[Client] node bypass route skip unresolved server (%s): %s: %v", reason, target, err)
				if opened {
					s.recordRouteSelfHealEvent("warn", "node_bypass_circuit_open", fmt.Sprintf("target=%s failures=%d until=%s reason=%s", target, failures, until.Format(time.RFC3339), reason))
				}
				continue
			}
			status.Failed++
			status.FailedTargets = append(status.FailedTargets, target)
			logrus.Warnf("[Client] node bypass route add failed (%s): %s: %v", reason, target, err)
			if opened {
				s.recordRouteSelfHealEvent("warn", "node_bypass_circuit_open", fmt.Sprintf("target=%s failures=%d until=%s reason=%s", target, failures, until.Format(time.RFC3339), reason))
			}
			continue
		}
		s.nodeBypassMarkSuccess(target)
		status.Success++
	}
	if status.Total == 0 {
		return status
	}
	if status.Failed > 0 {
		logrus.Warnf("[Client] node bypass update (%s): total=%d success=%d failed=%d skipped=%d", reason, status.Total, status.Success, status.Failed, status.Skipped)
		return status
	}
	if reason == "startup" || reason == "tun-enable" || reason == "manual-switch" {
		logrus.Infof("[Client] node bypass update (%s): total=%d success=%d failed=%d skipped=%d", reason, status.Total, status.Success, status.Failed, status.Skipped)
	}
	return status
}

func (s *apiState) applyNodeBypassLocked(reason string) {
	if s == nil || s.tun == nil || s.cfg == nil {
		return
	}
	currentName := ""
	if s.manager != nil {
		currentName = strings.TrimSpace(s.manager.CurrentNodeName())
	}
	currentServer := ""
	if currentName != "" {
		if node, ok := findNodeByName(s.cfg.Nodes, currentName); ok {
			currentServer = strings.TrimSpace(node.Server)
		}
	}
	s.nodeBypass = s.applyNodeBypassForTargets(s.tun, s.cfg.Nodes, currentServer, reason)
}

func (s *apiState) applyDNSBypassForTargets(tun *tunRuntime, upstreams []string, reason string) {
	if s == nil || tun == nil {
		return
	}
	if len(upstreams) == 0 {
		return
	}
	success := 0
	failed := 0
	for _, target := range upstreams {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		destination := M.ParseSocksaddr(target)
		if !destination.IsValid() {
			failed++
			logrus.Warnf("[Client] dns bypass route skip invalid target (%s): %s", reason, target)
			continue
		}
		if err := tun.EnsureDirectBypass(destination); err != nil {
			failed++
			logrus.Warnf("[Client] dns bypass route add failed (%s): %s: %v", reason, target, err)
			continue
		}
		success++
	}
	if failed > 0 {
		logrus.Warnf("[Client] dns bypass update (%s): total=%d success=%d failed=%d", reason, len(upstreams), success, failed)
		return
	}
	if reason == "startup" || reason == "tun-enable" {
		logrus.Infof("[Client] dns bypass update (%s): total=%d success=%d failed=%d", reason, len(upstreams), success, failed)
	}
}

func (s *apiState) applyDNSBypassLocked(reason string) {
	if s == nil || s.tun == nil || s.dnsHijacker == nil {
		return
	}
	s.applyDNSBypassForTargets(s.tun, s.dnsHijacker.RouteBypassTargets(), reason)
}

func (s *apiState) reconnectAfterRoutingChangeLocked(reason string) {
	if s == nil {
		return
	}
	if s.manager != nil {
		if err := s.manager.ResetClients(); err != nil {
			logrus.Warnf("[Client] routing reconnect reset clients failed: reason=%s err=%v", strings.TrimSpace(reason), err)
		}
	}
	if s.mitm != nil {
		s.mitm.ResetConnections(reason)
	}
	closeAllInboundConnections(reason)
}

func (s *apiState) reconnectAfterNodeSwitchLocked(reason string) {
	if s == nil {
		return
	}
	if s.mitm != nil {
		s.mitm.ResetConnections(reason)
	}
	closeAllInboundConnections(reason)
}

func (s *apiState) reconcileMITMLocked(next *clientMITMConfig) (bool, error) {
	if next == nil || !next.Enabled {
		if s.mitm != nil {
			if err := s.mitm.Close(); err != nil {
				return false, err
			}
			s.mitm = nil
			logrus.Infoln("[Client] mitm disabled")
			return true, nil
		}
		return false, nil
	}

	if s.mitm != nil {
		if s.mitm.reusableWith(*next, s.activeListen) {
			if err := s.mitm.refreshDynamicRules(*next, s.routing); err != nil {
				return false, err
			}
			dohdotEnabled := next.DoHDoT != nil && next.DoHDoT.Enabled
			logrus.Infoln("[Client] mitm refreshed", s.mitm.ListenAddr(), "hosts=", s.mitm.HostCount(), "url_reject=", s.mitm.URLRejectCount(), "doh_dot=", dohdotEnabled)
			return false, nil
		}
		if err := s.mitm.Close(); err != nil {
			return false, err
		}
		s.mitm = nil
	}
	rt, err := startMITMRuntime(s.ctx, *next, s.activeListen, s.routing)
	if err != nil {
		return false, err
	}
	s.mitm = rt
	dohdotEnabled := next.DoHDoT != nil && next.DoHDoT.Enabled
	logrus.Infoln("[Client] mitm enabled", rt.ListenAddr(), "hosts=", rt.HostCount(), "url_reject=", rt.URLRejectCount(), "doh_dot=", dohdotEnabled)
	return false, nil
}

func decodeJSONBody(r *http.Request, out any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]any{
		"error": message,
	})
}

func apiURL(addr, path string) string {
	return fmt.Sprintf("http://%s%s", addr, path)
}
