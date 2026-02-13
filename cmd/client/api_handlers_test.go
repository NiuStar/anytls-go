package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestAPIState(t *testing.T, cfg *clientProfileConfig, configPath string) *apiState {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	manager, err := newRuntimeClientManager(ctx, cfg.Nodes, cfg.DefaultNode, cfg.MinIdleSession)
	if err != nil {
		t.Fatalf("newRuntimeClientManager failed: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	return &apiState{
		ctx:           ctx,
		startedAt:     time.Now(),
		configPath:    configPath,
		activeControl: cfg.Control,
		activeListen:  cfg.Listen,
		cfg:           cfg,
		manager:       manager,
		authGuard:     newAuthAttemptGuard(5, time.Second),
		tasks:         make(map[string]*apiAsyncTask),
	}
}

func doJSONRequest(t *testing.T, method, path string, payload any, handler func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	if payload != nil {
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			t.Fatalf("encode payload failed: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &body)
	resp := httptest.NewRecorder()
	handler(resp, req)
	return resp
}

func TestHandleConfigPutSwitchAndPersist(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")

	cfg := testClientConfig()
	cfg.Nodes = append(cfg.Nodes, clientNodeConfig{
		Name:     "node-2",
		Server:   "node2.example.com:8443",
		Password: "change-me-2",
		SNI:      "node2.example.com",
	})
	cfg.DefaultNode = "node-1"
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save initial config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodPut, "/api/v1/config", map[string]any{
		"default_node": "node-2",
		"web_username": "admin",
		"web_password": "secret",
		"failover": map[string]any{
			"enabled": false,
		},
	}, state.handleConfig)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	if state.manager.CurrentNodeName() != "node-2" {
		t.Fatalf("expected current node switched to node-2, got %s", state.manager.CurrentNodeName())
	}

	reloaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	if reloaded.DefaultNode != "node-2" {
		t.Fatalf("unexpected default node: %s", reloaded.DefaultNode)
	}
	if reloaded.WebUsername != "admin" || reloaded.WebPassword != "secret" {
		t.Fatalf("unexpected web auth values: %+v", reloaded)
	}
	if reloaded.Failover == nil || reloaded.Failover.Enabled {
		t.Fatalf("expected failover disabled: %+v", reloaded.Failover)
	}
}

func TestHandleConfigPutTunEnqueueTask(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save initial config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodPut, "/api/v1/config", map[string]any{
		"tun": map[string]any{
			"enabled": false,
		},
	}, state.handleConfig)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	taskID, _ := out["tun_task_id"].(string)
	if strings.TrimSpace(taskID) == "" {
		t.Fatalf("expected tun_task_id in response, body=%s", resp.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID, nil)
		rec := httptest.NewRecorder()
		state.handleTask(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected task status code: %d body=%s", rec.Code, rec.Body.String())
		}
		var taskOut map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &taskOut); err != nil {
			t.Fatalf("decode task response failed: %v", err)
		}
		status, _ := taskOut["status"].(string)
		switch status {
		case "success":
			return
		case "failed":
			t.Fatalf("tun task failed: %v", taskOut["error"])
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tun task did not finish in time")
}

func TestHandleTaskPostRouteCheckAndGet(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	cfg.Nodes[0].Server = "127.0.0.1:8443"
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save initial config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodPost, "/api/v1/tasks", map[string]any{
		"kind": "route_check",
	}, state.handleTask)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	taskID, _ := out["task_id"].(string)
	if strings.TrimSpace(taskID) == "" {
		t.Fatalf("expected task_id in response, body=%s", resp.Body.String())
	}

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID, nil)
		rec := httptest.NewRecorder()
		state.handleTask(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected task status code: %d body=%s", rec.Code, rec.Body.String())
		}
		var taskOut map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &taskOut); err != nil {
			t.Fatalf("decode task response failed: %v", err)
		}
		status, _ := taskOut["status"].(string)
		if status == "success" || status == "failed" {
			if _, ok := taskOut["result"]; !ok && status == "success" {
				t.Fatalf("expected result in successful task")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("task did not finish in time")
}

func TestHandleTaskListEndpointDoesNotTreatBasePathAsTaskID(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save initial config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)
	_ = state.createTask("diagnose", "queued")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks?limit=200", nil)
	rec := httptest.NewRecorder()
	state.handleTask(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Items []apiAsyncTask   `json:"items"`
		Count int              `json:"count"`
		Queue tunTaskQueueInfo `json:"queue"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if out.Count != len(out.Items) {
		t.Fatalf("unexpected count/items mismatch: count=%d items=%d", out.Count, len(out.Items))
	}
	if out.Count == 0 {
		t.Fatalf("expected at least one task item")
	}
	if out.Queue.UpdatedAt == "" {
		t.Fatalf("expected queue summary in task list response")
	}
}

func TestHandleTaskAutoFinalizeOrphanTunPendingTask(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save initial config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)
	taskID := state.createTask("tun_toggle", "queued")

	state.taskMu.Lock()
	task := state.tasks[taskID]
	if task == nil {
		state.taskMu.Unlock()
		t.Fatalf("task not found after create")
	}
	task.Status = "pending"
	task.CreatedAt = time.Now().Add(-20 * time.Second).Format(time.RFC3339)
	state.tunTaskQueue = nil
	state.tunTaskWorkerRunning = true
	state.taskMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID, nil)
	rec := httptest.NewRecorder()
	state.handleTask(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var out apiAsyncTask
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %+v", out)
	}
	if !strings.Contains(strings.ToLower(out.Error), "no longer exists in queue") {
		t.Fatalf("expected orphan queue error, got %+v", out)
	}
}

func TestWaitTunPriorityWindowBlocksUntilTunCleared(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save initial config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)
	tunTaskID := state.createTask("tun_toggle", "queued")

	state.taskMu.Lock()
	tunTask := state.tasks[tunTaskID]
	if tunTask == nil {
		state.taskMu.Unlock()
		t.Fatalf("missing tun task")
	}
	tunTask.Status = "pending"
	tunTask.CreatedAt = time.Now().Format(time.RFC3339)
	state.tunTaskQueue = []tunTaskRequest{{TaskID: tunTaskID, Next: cloneTunConfig(state.cfg.Tun)}}
	state.taskMu.Unlock()

	go func() {
		time.Sleep(150 * time.Millisecond)
		state.taskMu.Lock()
		if task := state.tasks[tunTaskID]; task != nil {
			task.Status = "success"
			task.FinishedAt = time.Now().Format(time.RFC3339)
		}
		state.tunTaskQueue = nil
		state.taskMu.Unlock()
	}()

	start := time.Now()
	if err := state.waitTunPriorityWindow(2 * time.Second); err != nil {
		t.Fatalf("waitTunPriorityWindow failed: %v", err)
	}
	if time.Since(start) < 120*time.Millisecond {
		t.Fatalf("waitTunPriorityWindow did not wait for tun task")
	}
}

func TestHandleImportNodeAndList(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save initial config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodPost, "/api/v1/nodes/import", map[string]any{
		"name": "node-imported",
		"uri":  "anytls://pass%40word@import.example.com:8443/?sni=import.example.com",
	}, state.handleImportNode)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	if !state.manager.HasNode("node-imported") {
		t.Fatalf("expected imported node in runtime manager")
	}

	resp = doJSONRequest(t, http.MethodGet, "/api/v1/nodes", nil, state.handleNodes)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	var out struct {
		Nodes []clientNodeConfig `json:"nodes"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if len(out.Nodes) != 1 {
		t.Fatalf("expected template node to be replaced, got %d nodes", len(out.Nodes))
	}
	var imported *clientNodeConfig
	for i := range out.Nodes {
		if out.Nodes[i].Name == "node-imported" {
			imported = &out.Nodes[i]
			break
		}
	}
	if imported == nil {
		t.Fatalf("imported node not found in response")
	}
	if imported.Password != "pass@word" {
		t.Fatalf("expected decoded password, got %q", imported.Password)
	}
}

func TestHandleConfigRollbackEndpoint(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")

	cfg1 := testClientConfig()
	cfg1.Nodes[0].Server = "before.example.com:8443"
	if err := saveClientConfig(configPath, cfg1); err != nil {
		t.Fatalf("save cfg1 failed: %v", err)
	}
	cfg2 := testClientConfig()
	cfg2.Nodes[0].Server = "after.example.com:8443"
	if err := saveClientConfig(configPath, cfg2); err != nil {
		t.Fatalf("save cfg2 failed: %v", err)
	}

	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodPost, "/api/v1/config/rollback", map[string]any{}, state.handleConfigRollback)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}

	reloaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	if got := reloaded.Nodes[0].Server; got != "before.example.com:8443" {
		t.Fatalf("rollback not applied, got server=%s", got)
	}
}

func TestHandleMITMCAReturnsFileWhenRuntimeNotStarted(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	caPath := filepath.Join(dir, "mitm_ca.crt")
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatalf("write ca file failed: %v", err)
	}

	cfg := testClientConfig()
	cfg.MITM = &clientMITMConfig{
		Enabled:    false,
		CACertPath: caPath,
	}
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodGet, "/api/v1/mitm/ca", nil, state.handleMITMCA)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	if got := resp.Body.String(); got != string(caPEM) {
		t.Fatalf("unexpected ca pem body: %q", got)
	}
	if got := resp.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Fatalf("unexpected content-type: %q", got)
	}
}

func TestHandleMITMCAAutoGenerate(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	cfg.MITM = &clientMITMConfig{
		Enabled:    false,
		CACertPath: filepath.Join(dir, "auto_ca.crt"),
		CAKeyPath:  filepath.Join(dir, "auto_ca.key"),
	}
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodGet, "/api/v1/mitm/ca", nil, state.handleMITMCA)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	if got := resp.Body.String(); !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatalf("expected pem certificate body, got=%q", got)
	}
}

func TestHandleMITMCAInstallScriptNoPlaceholder(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	caPath := filepath.Join(dir, "mitm_ca.crt")
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nTEST-INSTALL\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatalf("write ca file failed: %v", err)
	}

	cfg := testClientConfig()
	cfg.MITM = &clientMITMConfig{
		Enabled:    false,
		CACertPath: caPath,
	}
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodGet, "/api/v1/mitm/ca/install.sh", nil, state.handleMITMCAInstallScript)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Content-Type"); !strings.Contains(got, "text/x-shellscript") {
		t.Fatalf("unexpected content-type: %q", got)
	}

	body := resp.Body.String()
	if !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Fatalf("expected embedded certificate in install script")
	}
	if !strings.Contains(body, "/etc/ssl/certs/anytls-mitm-ca.crt") {
		t.Fatalf("expected openwrt install target in script")
	}
	if strings.Contains(body, "AUTH_OPT") {
		t.Fatalf("install script should not contain AUTH_OPT placeholder")
	}
}

func TestHandleMITMCAStatus(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	cfg.MITM = &clientMITMConfig{
		Enabled:    false,
		CACertPath: filepath.Join(dir, "status_ca.crt"),
		CAKeyPath:  filepath.Join(dir, "status_ca.key"),
	}
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodGet, "/api/v1/mitm/ca/status", nil, state.handleMITMCAStatus)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if _, ok := out["installed"]; !ok {
		t.Fatalf("status should include installed field")
	}
	if _, ok := out["fingerprint"]; !ok {
		t.Fatalf("status should include fingerprint field")
	}
}

func TestHandleMITMCAInstallMethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodGet, "/api/v1/mitm/ca/install", nil, state.handleMITMCAInstall)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestHandleRoutingUpdateNoHTTPProvider(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")

	cfg := testClientConfig()
	cfg.Routing = &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,ads,REJECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"ads": {
				Type:        "inline",
				Behavior:    "domain",
				Format:      "yaml",
				Payload:     []string{"DOMAIN-SUFFIX,ads.example.com"},
				IntervalSec: 60,
			},
		},
	}
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodPost, "/api/v1/routing/update", map[string]any{}, state.handleRoutingUpdate)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}

	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if out.Error == "" {
		t.Fatalf("expected api error message, got empty")
	}
}

func TestHandleRoutingProviders(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")

	cfg := testClientConfig()
	cfg.Routing = &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"ads": {
				Type:        "http",
				Behavior:    "classical",
				Format:      "yaml",
				URL:         "https://example.com/ads.yaml",
				IntervalSec: 600,
			},
			"local": {
				Type:     "inline",
				Behavior: "domain",
				Format:   "yaml",
				Payload:  []string{"DOMAIN-SUFFIX,example.com"},
			},
		},
	}
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodGet, "/api/v1/routing/providers", nil, state.handleRoutingProviders)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}

	var out struct {
		Count     int `json:"count"`
		Providers []struct {
			Name       string `json:"name"`
			Type       string `json:"type"`
			AutoUpdate bool   `json:"auto_update"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if out.Count != 2 || len(out.Providers) != 2 {
		t.Fatalf("unexpected providers count: %+v", out)
	}
	autoMap := make(map[string]bool, len(out.Providers))
	for _, item := range out.Providers {
		autoMap[item.Name] = item.AutoUpdate
	}
	if !autoMap["ads"] || autoMap["local"] {
		t.Fatalf("unexpected auto_update flags: %+v", autoMap)
	}
}

func TestUpdateRoutingProvidersFallbackKeepsLastSuccess(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")

	cfg := testClientConfig()
	cfg.Routing = &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,ads,DIRECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"ads": {
				Type:        "http",
				Behavior:    "classical",
				Format:      "text",
				URL:         "http://127.0.0.1:1/always-fail",
				IntervalSec: 1,
			},
		},
	}
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)
	state.lock.Lock()
	state.routing = &routingEngine{enabled: true}
	state.ensureRoutingProviderStatusLocked("ads").LastSuccessAt = time.Date(2026, 2, 11, 1, 2, 3, 0, time.UTC)
	firstSuccess := state.routingProviderStatus["ads"].LastSuccessAt
	state.lock.Unlock()

	updated, items, err := state.updateRoutingProviders(context.Background(), []string{"ads"}, true)
	if err != nil {
		t.Fatalf("expected fallback without error, got: %v", err)
	}
	if updated {
		t.Fatalf("expected updated=false on failed refresh with fallback")
	}
	if len(items) != 1 {
		t.Fatalf("unexpected fallback items: %+v", items)
	}
	if items[0].Error != "" {
		t.Fatalf("expected empty status error on fallback, got: %+v", items[0])
	}
	state.lock.Lock()
	secondSuccess := state.routingProviderStatus["ads"].LastSuccessAt
	state.lock.Unlock()
	if !secondSuccess.Equal(firstSuccess) {
		t.Fatalf("last success changed on fallback, before=%s after=%s", firstSuccess, secondSuccess)
	}
}

func TestHandleRoutingProbeAutoDetectSGModule(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "adblock.rules")
	content := `
[Rule]
DOMAIN-SUFFIX,example.com,REJECT
[MITM]
hostname = %APPEND% *.example.com
`
	if err := os.WriteFile(providerPath, []byte(content), 0644); err != nil {
		t.Fatalf("write provider failed: %v", err)
	}

	cfg := testClientConfig()
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	resp := doJSONRequest(t, http.MethodPost, "/api/v1/routing/probe", map[string]any{
		"type":   "file",
		"format": "auto",
		"path":   providerPath,
	}, state.handleRoutingProbe)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	var out struct {
		DetectedFormat    string `json:"detected_format"`
		SuggestedBehavior string `json:"suggested_behavior"`
		EntryCount        int    `json:"entry_count"`
		MITMHostCount     int    `json:"mitm_host_count"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if out.DetectedFormat != "sgmodule" {
		t.Fatalf("unexpected detected format: %q", out.DetectedFormat)
	}
	if out.SuggestedBehavior != "classical" {
		t.Fatalf("unexpected suggested behavior: %q", out.SuggestedBehavior)
	}
	if out.EntryCount == 0 {
		t.Fatalf("expected non-zero entry count")
	}
	if out.MITMHostCount == 0 {
		t.Fatalf("expected non-zero mitm host count")
	}
}

func TestHandleNodeExportByGroup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	cfg := testClientConfig()
	cfg.Nodes = append(cfg.Nodes,
		clientNodeConfig{
			Name:     "hk-1",
			Server:   "1.2.3.4:443",
			Password: "p1",
			Groups:   []string{"hk", "prod"},
		},
		clientNodeConfig{
			Name:     "us-1",
			Server:   "5.6.7.8:443",
			Password: "p2",
			Groups:   []string{"us"},
		},
	)
	if err := saveClientConfig(configPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	loaded, err := loadClientConfig(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	state := newTestAPIState(t, loaded, configPath)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/export?group=hk&format=text", nil)
	resp := httptest.NewRecorder()
	state.handleNodeExport(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
	var out struct {
		Group string `json:"group"`
		Count int    `json:"count"`
		Text  string `json:"text"`
		Items []struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		} `json:"items"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if out.Group != "hk" {
		t.Fatalf("unexpected group: %q", out.Group)
	}
	if out.Count != 1 || len(out.Items) != 1 {
		t.Fatalf("unexpected count/items: %+v", out)
	}
	if out.Items[0].Name != "hk-1" {
		t.Fatalf("unexpected node name: %q", out.Items[0].Name)
	}
	if !strings.Contains(out.Text, "hk-1,anytls://") {
		t.Fatalf("unexpected export text: %q", out.Text)
	}
}
