package main

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSubscriptionLines(t *testing.T) {
	raw := `
# comment
hk-1,anytls://pass@1.2.3.4:443/
anytls://pass2@5.6.7.8:443/
`
	items, warning := parseSubscriptionLines(raw)
	if warning != "" {
		t.Fatalf("unexpected warning: %s", warning)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Name != "hk-1" {
		t.Fatalf("unexpected first name: %q", items[0].Name)
	}
	if items[1].Name != "" {
		t.Fatalf("unexpected second name: %q", items[1].Name)
	}
}

func TestParseSubscriptionJSON(t *testing.T) {
	raw := `[{"name":"n1","uri":"anytls://p@1.2.3.4:443/"},{"uri":"anytls://x@5.6.7.8:443/"}]`
	items, ok := parseSubscriptionJSON(raw)
	if !ok {
		t.Fatalf("expected json parse success")
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Name != "n1" {
		t.Fatalf("unexpected first name: %q", items[0].Name)
	}
}

func TestParseSubscriptionJSONNestedVLESS(t *testing.T) {
	raw := `{
  "proxies": [
    {
      "name": "vless-json",
      "type": "vless",
      "server": "vless.example.com",
      "port": 443,
      "username": "11111111-1111-1111-1111-111111111111",
      "tls": true,
      "sni": "vless.example.com",
      "network": "ws",
      "ws-opts": {
        "path": "/json-ws",
        "headers": {
          "Host": "vless.example.com"
        }
      }
    }
  ]
}`
	items, ok := parseSubscriptionJSON(raw)
	if !ok {
		t.Fatalf("expected json parse success")
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !strings.HasPrefix(strings.ToLower(items[0].URI), "vless://") {
		t.Fatalf("unexpected uri: %q", items[0].URI)
	}
	if !strings.Contains(items[0].URI, "type=ws") {
		t.Fatalf("expected ws type in uri: %q", items[0].URI)
	}
	if !strings.Contains(items[0].URI, "path=%2Fjson-ws") {
		t.Fatalf("expected ws path in uri: %q", items[0].URI)
	}
}

func TestParseSubscriptionJSONOutboundsSSAndVLESS(t *testing.T) {
	raw := `{
  "outbounds": [
    {
      "tag": "ss-out",
      "type": "shadowsocks",
      "server": "1.2.3.4",
      "server_port": 443,
      "method": "aes-128-gcm",
      "password": "abc123"
    },
    {
      "tag": "vless-out",
      "type": "vless",
      "server": "v.example.com",
      "server_port": 443,
      "uuid": "11111111-1111-1111-1111-111111111111",
      "tls": {
        "enabled": true,
        "server_name": "v.example.com"
      },
      "transport": {
        "type": "ws",
        "path": "/ws"
      }
    }
  ]
}`
	items, ok := parseSubscriptionJSON(raw)
	if !ok {
		t.Fatalf("expected json parse success")
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d: %#v", len(items), items)
	}
	var ssURI, vlessURI string
	for _, item := range items {
		if item.Name == "ss-out" {
			ssURI = item.URI
		}
		if item.Name == "vless-out" {
			vlessURI = item.URI
		}
	}
	if !strings.HasPrefix(strings.ToLower(ssURI), "ss://") {
		t.Fatalf("unexpected ss uri: %q", ssURI)
	}
	if !strings.HasPrefix(strings.ToLower(vlessURI), "vless://") {
		t.Fatalf("unexpected vless uri: %q", vlessURI)
	}
	if !strings.Contains(vlessURI, "security=tls") {
		t.Fatalf("expected tls security in vless uri: %q", vlessURI)
	}
	if !strings.Contains(vlessURI, "type=ws") || !strings.Contains(vlessURI, "path=%2Fws") {
		t.Fatalf("expected ws fields in vless uri: %q", vlessURI)
	}
}

func TestAllocateSubscriptionNodeName(t *testing.T) {
	existingSource := map[string]string{
		"node-1": "",
	}
	used := map[string]struct{}{}
	name := allocateSubscriptionNodeName("node-1", "sub-a", existingSource, used)
	if name == "node-1" {
		t.Fatalf("expected conflict rename, got %q", name)
	}
}

func TestParseSubscriptionClashYAML(t *testing.T) {
	raw := `
proxies:
  - name: hk-any
    type: anytls
    server: 1.2.3.4
    port: 443
    password: pass@@
    sni: hk.example.com
  - name: ignored-ss
    type: ss
    server: 5.6.7.8
    port: 443
    cipher: aes-128-gcm
    password: abc123
`
	items, warning, sourceFmt := parseSubscriptionContent([]byte(raw))
	if len(items) < 2 {
		t.Fatalf("expected anytls + ss nodes, got %d warning=%q", len(items), warning)
	}
	if sourceFmt != "clash" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	var hkURI string
	var ssURI string
	for _, item := range items {
		if item.Name == "hk-any" {
			hkURI = item.URI
		}
		if item.Name == "ignored-ss" {
			ssURI = item.URI
		}
	}
	if hkURI == "" {
		t.Fatalf("missing hk-any node: %#v", items)
	}
	if ssURI == "" || !strings.HasPrefix(strings.ToLower(ssURI), "ss://") {
		t.Fatalf("missing/invalid ss uri: %q", ssURI)
	}
	server, password, sni, _, _, err := parseAnyTLSURI(hkURI)
	if err != nil {
		t.Fatalf("parse anytls uri failed: %v", err)
	}
	if server != "1.2.3.4:443" || password != "pass@@" || sni != "hk.example.com" {
		t.Fatalf("unexpected node fields: server=%q password=%q sni=%q", server, password, sni)
	}
}

func TestParseSubscriptionClashProxyGroups(t *testing.T) {
	raw := `
proxies:
  - name: hk-any
    type: anytls
    server: 1.2.3.4
    port: 443
    password: pass@@
  - name: sg-any
    type: anytls
    server: 5.6.7.8
    port: 443
    password: pass@@
proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - DIRECT
      - hk-any
      - sg-any
  - name: hk
    type: select
    proxies:
      - hk-any
`
	items, warning, sourceFmt := parseSubscriptionContent([]byte(raw))
	if warning != "" && !strings.Contains(strings.ToLower(warning), "ignored field") {
		t.Fatalf("unexpected warning: %q", warning)
	}
	if sourceFmt != "clash" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(items))
	}
	groupByName := make(map[string][]string, len(items))
	for _, item := range items {
		groupByName[item.Name] = item.Groups
	}
	if got := groupByName["hk-any"]; len(got) != 2 || got[0] != "hk" || got[1] != "节点选择" {
		t.Fatalf("unexpected hk-any groups: %#v", got)
	}
	if got := groupByName["sg-any"]; len(got) != 1 || got[0] != "节点选择" {
		t.Fatalf("unexpected sg-any groups: %#v", got)
	}
}

func TestParseSubscriptionClashProxyGroupsWithInlineComments(t *testing.T) {
	raw := `
proxies:
  - name: hk-any
    type: anytls
    server: 1.2.3.4
    port: 443
    password: pass@@
  - name: sg-any
    type: anytls
    server: 5.6.7.8
    port: 443
    password: pass@@
proxy-groups:
  - name: 节点选择 # 注释
    type: select
    proxies:
      - DIRECT
      - hk-any # 香港
      - sg-any # 新加坡
  - name: hk # 注释
    type: select
    proxies: [ "hk-any", "DIRECT" ] # 行尾注释
`
	items, warning, sourceFmt := parseSubscriptionContent([]byte(raw))
	if warning != "" {
		t.Fatalf("unexpected warning: %q", warning)
	}
	if sourceFmt != "clash" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(items))
	}
	groupByName := make(map[string][]string, len(items))
	for _, item := range items {
		groupByName[item.Name] = item.Groups
	}
	if got := groupByName["hk-any"]; len(got) != 2 || got[0] != "hk" || got[1] != "节点选择" {
		t.Fatalf("unexpected hk-any groups: %#v", got)
	}
	if got := groupByName["sg-any"]; len(got) != 1 || got[0] != "节点选择" {
		t.Fatalf("unexpected sg-any groups: %#v", got)
	}
}

func TestParseSubscriptionSurgeProxy(t *testing.T) {
	raw := `
[General]
skip-proxy = localhost

[Proxy]
HK = anytls, 1.2.3.4, 443, password=pass@1, sni=hk.example.com
OTHER = ss, 5.6.7.8, 443, password=abc, encrypt-method=aes-128-gcm
`
	items, warning, sourceFmt := parseSubscriptionContent([]byte(raw))
	if len(items) < 2 {
		t.Fatalf("expected anytls + ss node, got %d warning=%q", len(items), warning)
	}
	if sourceFmt != "surge" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	var hkURI string
	var otherURI string
	for _, item := range items {
		if item.Name == "HK" {
			hkURI = item.URI
		}
		if item.Name == "OTHER" {
			otherURI = item.URI
		}
	}
	if hkURI == "" {
		t.Fatalf("missing HK node: %#v", items)
	}
	if otherURI == "" || !strings.HasPrefix(strings.ToLower(otherURI), "ss://") {
		t.Fatalf("missing/invalid OTHER ss node: %q", otherURI)
	}
	server, password, sni, _, _, err := parseAnyTLSURI(hkURI)
	if err != nil {
		t.Fatalf("parse anytls uri failed: %v", err)
	}
	if server != "1.2.3.4:443" || password != "pass@1" || sni != "hk.example.com" {
		t.Fatalf("unexpected node fields: server=%q password=%q sni=%q", server, password, sni)
	}
}

func TestParseSubscriptionBase64Payload(t *testing.T) {
	plain := "anytls://pass@1.2.3.4:443/\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	items, warning, sourceFmt := parseSubscriptionContent([]byte(encoded))
	if len(items) != 1 {
		t.Fatalf("expected 1 node from base64 payload, got %d warning=%q", len(items), warning)
	}
	if sourceFmt != "base64->lines" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
}

func TestParseSubscriptionClashVLessAndVMess(t *testing.T) {
	raw := `
proxies:
  - name: vless-1
    type: vless
    server: vless.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: vless.example.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: vless.example.com
  - name: vmess-1
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    alterId: 0
    cipher: auto
    tls: true
    servername: vmess.example.com
    network: ws
    ws-opts:
      path: /ray
`
	items, warning, sourceFmt := parseSubscriptionContent([]byte(raw))
	if warning != "" {
		t.Fatalf("unexpected warning: %q", warning)
	}
	if sourceFmt != "clash" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d: %#v", len(items), items)
	}
	var vlessURI, vmessURI string
	for _, item := range items {
		if item.Name == "vless-1" {
			vlessURI = item.URI
		}
		if item.Name == "vmess-1" {
			vmessURI = item.URI
		}
	}
	if !strings.HasPrefix(strings.ToLower(vlessURI), "vless://") {
		t.Fatalf("unexpected vless uri: %q", vlessURI)
	}
	if !strings.HasPrefix(strings.ToLower(vmessURI), "vmess://") {
		t.Fatalf("unexpected vmess uri: %q", vmessURI)
	}
}

func TestParseSubscriptionClashVLessWithTransportFields(t *testing.T) {
	raw := `
proxies:
  - name: vless-transport
    type: vless
    server: vless.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls:
      enabled: true
      server_name: vless.example.com
    transport:
      type: ws
      path: /ws
      headers:
        Host: vless.example.com
`
	items, warning, sourceFmt := parseSubscriptionContent([]byte(raw))
	if warning != "" && !strings.Contains(strings.ToLower(warning), "ignored field") {
		t.Fatalf("unexpected warning: %q", warning)
	}
	if sourceFmt != "clash" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	uri := items[0].URI
	if !strings.HasPrefix(strings.ToLower(uri), "vless://") {
		t.Fatalf("unexpected uri: %q", uri)
	}
	if !strings.Contains(uri, "security=tls") {
		t.Fatalf("expected tls security in uri: %q", uri)
	}
	if !strings.Contains(uri, "type=ws") || !strings.Contains(uri, "path=%2Fws") {
		t.Fatalf("expected ws params in uri: %q", uri)
	}
}

func TestParseSubscriptionClashWarnIgnoredFields(t *testing.T) {
	raw := `
proxies:
  - name: vless-with-extra
    type: vless
    server: vless.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: vless.example.com
    random-extra-field: abc
`
	items, warning, sourceFmt := parseSubscriptionContent([]byte(raw))
	if sourceFmt != "clash" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !strings.Contains(strings.ToLower(warning), "ignored field") {
		t.Fatalf("expected ignored field warning, got %q", warning)
	}
}

func TestParseSubscriptionClashParseSummary(t *testing.T) {
	raw := `
proxies:
  - name: vless-with-extra
    type: vless
    server: vless.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: vless.example.com
    random-extra-field: abc
`
	items, warning, sourceFmt, summary := parseSubscriptionContentWithMeta([]byte(raw))
	if sourceFmt != "clash" {
		t.Fatalf("unexpected source format: %q", sourceFmt)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !strings.Contains(strings.ToLower(warning), "ignored field") {
		t.Fatalf("expected ignored field warning, got %q", warning)
	}
	if summary == nil {
		t.Fatal("expected non-nil parse summary")
	}
	if summary.PartialMapped < 1 || summary.IgnoredFieldCount < 1 {
		t.Fatalf("unexpected parse summary: %#v", summary)
	}
	if len(summary.IgnoredFieldTop) == 0 {
		t.Fatalf("expected ignored field top entries, got %#v", summary)
	}
}

func TestBuildSSPluginOptsFromKV(t *testing.T) {
	kv := map[string]string{
		"plugin":              "v2ray-plugin",
		"plugin-opts-mode":    "websocket",
		"plugin-opts-host":    "example.com",
		"plugin-opts-path":    "/ws",
		"plugin-opts-tls":     "true",
		"plugin-opts-mux":     "false",
		"plugin-opts-timeout": "5",
	}
	opts := buildSSPluginOptsFromKV(kv)
	if !strings.Contains(opts, "mode=websocket") || !strings.Contains(opts, "host=example.com") {
		t.Fatalf("unexpected plugin opts: %q", opts)
	}
}

func TestApplySubscriptionNodesLockedAssignGroups(t *testing.T) {
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

	sub := clientSubscription{
		ID:                "sub-hk",
		Name:              "HK",
		URL:               "https://example.com/sub.txt",
		Enabled:           true,
		UpdateIntervalSec: 3600,
		NodePrefix:        "hk",
		Groups:            []string{"香港", "自动订阅"},
	}
	items := []subscriptionNodeItem{
		{Name: "hk-1", URI: "anytls://pass@1.2.3.4:443/", Groups: []string{"节点选择", "香港"}},
	}
	if _, err := state.applySubscriptionNodesLocked(sub, items); err != nil {
		t.Fatalf("apply subscription nodes failed: %v", err)
	}

	node, ok := findNodeByName(state.cfg.Nodes, "hk-1")
	if !ok {
		t.Fatalf("expected imported node hk-1")
	}
	if node.SourceID != "sub-hk" {
		t.Fatalf("unexpected source id: %q", node.SourceID)
	}
	if len(node.Groups) != 3 {
		t.Fatalf("unexpected node groups len: %#v", node.Groups)
	}
	seen := map[string]struct{}{}
	for _, g := range node.Groups {
		seen[g] = struct{}{}
	}
	if _, ok := seen["香港"]; !ok {
		t.Fatalf("missing group 香港: %#v", node.Groups)
	}
	if _, ok := seen["自动订阅"]; !ok {
		t.Fatalf("missing group 自动订阅: %#v", node.Groups)
	}
	if _, ok := seen["节点选择"]; !ok {
		t.Fatalf("missing group 节点选择: %#v", node.Groups)
	}
}
