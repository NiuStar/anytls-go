package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNativeProxyNodeURISS(t *testing.T) {
	spec, ok, err := parseNativeProxyNodeURI("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ss-node")
	if !ok || err != nil {
		t.Fatalf("parse ss failed: ok=%v err=%v", ok, err)
	}
	if spec.Scheme != "ss" {
		t.Fatalf("unexpected scheme: %q", spec.Scheme)
	}
	if spec.Server != "1.2.3.4:8388" {
		t.Fatalf("unexpected server: %q", spec.Server)
	}
	if got := strings.TrimSpace(spec.NameHint); got != "ss-node" {
		t.Fatalf("unexpected name hint: %q", got)
	}
	if typ := strings.TrimSpace(spec.Outbound["type"].(string)); typ != "shadowsocks" {
		t.Fatalf("unexpected outbound type: %q", typ)
	}
}

func TestParseNativeProxyNodeURIVMess(t *testing.T) {
	payload := map[string]any{
		"v":    "2",
		"ps":   "vmess-node",
		"add":  "example.com",
		"port": "443",
		"id":   "11111111-1111-1111-1111-111111111111",
		"aid":  "0",
		"net":  "ws",
		"host": "example.com",
		"path": "/ws",
		"tls":  "tls",
		"sni":  "example.com",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal vmess payload failed: %v", err)
	}
	uri := "vmess://" + base64.StdEncoding.EncodeToString(raw)
	spec, ok, err := parseNativeProxyNodeURI(uri)
	if !ok || err != nil {
		t.Fatalf("parse vmess failed: ok=%v err=%v", ok, err)
	}
	if spec.Server != "example.com:443" {
		t.Fatalf("unexpected server: %q", spec.Server)
	}
	if spec.Outbound["type"] != "vmess" {
		t.Fatalf("unexpected outbound type: %#v", spec.Outbound["type"])
	}
}

func TestBuildExternalCoreSpecFromNativeNode(t *testing.T) {
	spec, ok, err := parseNativeProxyNodeURI("trojan://password@example.com:443?sni=example.com#trojan-node")
	if !ok || err != nil {
		t.Fatalf("parse trojan failed: ok=%v err=%v", ok, err)
	}
	ext, err := buildExternalCoreSpecFromNativeNode("trojan-node", spec)
	if err != nil {
		t.Fatalf("build external spec failed: %v", err)
	}
	if ext.Engine != "sing-box" || !ext.AutoStart {
		t.Fatalf("unexpected external spec: %+v", ext)
	}
	if strings.TrimSpace(ext.Config) == "" || strings.TrimSpace(ext.SOCKS.Server) == "" {
		t.Fatalf("invalid external spec paths: %+v", ext)
	}
	if _, err := os.Stat(ext.Config); err != nil {
		t.Fatalf("generated config not found: %v", err)
	}
	raw, err := os.ReadFile(ext.Config)
	if err != nil {
		t.Fatalf("read generated config failed: %v", err)
	}
	if !strings.Contains(string(raw), `"type": "socks"`) {
		t.Fatalf("generated config missing socks inbound: %s", filepath.Base(ext.Config))
	}
}

func TestParseWireGuardReserved(t *testing.T) {
	got := parseWireGuardReserved("[1, 2,3]")
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("unexpected reserved parse: %#v", got)
	}
	if bad := parseWireGuardReserved("1,2,300"); len(bad) != 0 {
		t.Fatalf("expected invalid reserved to be empty, got %#v", bad)
	}
}
