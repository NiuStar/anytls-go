package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestHandleStatus(t *testing.T) {
	cfg := testClientConfig()
	cfg.Tun.Enabled = true
	state := &apiState{
		startedAt:     time.Now().Add(-5 * time.Second),
		configPath:    "/tmp/client.json",
		activeControl: "127.0.0.1:18990",
		activeListen:  "127.0.0.1:1080",
		cfg:           cfg,
		manager:       &runtimeClientManager{currentName: "node-1"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	resp := httptest.NewRecorder()
	state.handleStatus(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d body=%s", resp.Code, resp.Body.String())
	}

	var out struct {
		Current       string `json:"current"`
		ConfigPath    string `json:"config_path"`
		ActiveListen  string `json:"active_listen"`
		ActiveControl string `json:"active_control"`
		NodeCount     int    `json:"node_count"`
		UptimeSec     int64  `json:"uptime_sec"`
		Tun           struct {
			Enabled bool `json:"enabled"`
			Running bool `json:"running"`
		} `json:"tun"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if out.Current != "node-1" {
		t.Fatalf("unexpected current: %s", out.Current)
	}
	if out.ConfigPath != "/tmp/client.json" || out.ActiveListen != "127.0.0.1:1080" || out.ActiveControl != "127.0.0.1:18990" {
		t.Fatalf("unexpected runtime fields: %+v", out)
	}
	if out.NodeCount != 1 || out.UptimeSec <= 0 {
		t.Fatalf("unexpected counters: %+v", out)
	}
	if !out.Tun.Enabled || out.Tun.Running {
		t.Fatalf("unexpected tun status: %+v", out.Tun)
	}
}

func TestCheckAuthLockout(t *testing.T) {
	cfg := testClientConfig()
	cfg.WebUsername = "admin"
	cfg.WebPassword = "secret"
	state := &apiState{
		cfg:       cfg,
		authGuard: newAuthAttemptGuard(2, 60*time.Second),
	}

	wrongReq1 := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	wrongReq1.RemoteAddr = "203.0.113.1:12345"
	wrongReq1.SetBasicAuth("admin", "bad")
	wrongResp1 := httptest.NewRecorder()
	if state.checkAuth(wrongResp1, wrongReq1) {
		t.Fatalf("expected first wrong auth to fail")
	}
	if wrongResp1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for first failure, got %d", wrongResp1.Code)
	}

	wrongReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	wrongReq2.RemoteAddr = "203.0.113.1:12345"
	wrongReq2.SetBasicAuth("admin", "bad")
	wrongResp2 := httptest.NewRecorder()
	if state.checkAuth(wrongResp2, wrongReq2) {
		t.Fatalf("expected second wrong auth to fail")
	}
	if wrongResp2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after lockout, got %d", wrongResp2.Code)
	}
	if wrongResp2.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on lockout")
	}

	rightReq := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rightReq.RemoteAddr = "203.0.113.1:12345"
	rightReq.SetBasicAuth("admin", "secret")
	rightResp := httptest.NewRecorder()
	if state.checkAuth(rightResp, rightReq) {
		t.Fatalf("expected locked client to still be denied")
	}
	if rightResp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while locked, got %d", rightResp.Code)
	}
}

func TestCloneRoutingConfigGeoIPDeepCopy(t *testing.T) {
	in := &clientRoutingConfig{
		Enabled: true,
		GeoIP: &clientRoutingGeoIPConfig{
			Type:        "http",
			URL:         "https://static-sg.529851.xyz/GeoLite2-Country.mmdb",
			IntervalSec: 3600,
			Header: map[string][]string{
				"X-Test": {"a", "b"},
			},
		},
	}
	out := cloneRoutingConfig(in)
	if out == nil || out.GeoIP == nil {
		t.Fatalf("expected cloned geoip config")
	}
	if out.GeoIP == in.GeoIP {
		t.Fatalf("expected geoip pointer deep copy")
	}
	if !reflect.DeepEqual(out.GeoIP.Header, in.GeoIP.Header) {
		t.Fatalf("unexpected cloned geoip header: %#v", out.GeoIP.Header)
	}

	in.GeoIP.URL = "https://example.com/new.mmdb"
	in.GeoIP.Header["X-Test"][0] = "changed"
	if out.GeoIP.URL == in.GeoIP.URL {
		t.Fatalf("expected cloned geoip url not affected by source mutation")
	}
	if out.GeoIP.Header["X-Test"][0] == "changed" {
		t.Fatalf("expected cloned geoip header not affected by source mutation")
	}
}
