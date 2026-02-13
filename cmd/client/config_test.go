package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testClientConfig() *clientProfileConfig {
	return &clientProfileConfig{
		Listen:         "127.0.0.1:1080",
		MinIdleSession: 5,
		Control:        "127.0.0.1:18990",
		DefaultNode:    "node-1",
		Nodes: []clientNodeConfig{
			{
				Name:     "node-1",
				Server:   "example.com:8443",
				Password: "change-me",
				SNI:      "example.com",
			},
		},
		Tun: &clientTunConfig{
			Enabled:   false,
			Name:      "anytls0",
			MTU:       1500,
			Address:   "198.18.0.1/15",
			AutoRoute: true,
		},
	}
}

func TestParseAnyTLSURIDecodePassword(t *testing.T) {
	server, password, sni, egressIP, egressRule, err := parseAnyTLSURI("anytls://Wangzai007..%40%40@23.141.52.18:20086/?sni=test.example&egress-ip=203.0.113.9&egress-rule=default=203.0.113.10")
	if err != nil {
		t.Fatalf("parse uri failed: %v", err)
	}
	if server != "23.141.52.18:20086" {
		t.Fatalf("unexpected server: %s", server)
	}
	if password != "Wangzai007..@@" {
		t.Fatalf("unexpected password: %q", password)
	}
	if sni != "test.example" || egressIP != "203.0.113.9" || egressRule != "default=203.0.113.10" {
		t.Fatalf("unexpected query fields: sni=%q egressIP=%q egressRule=%q", sni, egressIP, egressRule)
	}
}

func TestNormalizeTunDeviceNameForOS(t *testing.T) {
	if got := normalizeTunDeviceNameForOS("darwin", ""); got != "utun" {
		t.Fatalf("expected darwin empty -> utun, got %q", got)
	}
	if got := normalizeTunDeviceNameForOS("darwin", "anytls0"); got != "utun" {
		t.Fatalf("expected darwin anytls0 -> utun, got %q", got)
	}
	if got := normalizeTunDeviceNameForOS("darwin", "utun5"); got != "utun5" {
		t.Fatalf("expected darwin utun5 keep same, got %q", got)
	}
	if got := normalizeTunDeviceNameForOS("linux", ""); got != "anytls0" {
		t.Fatalf("expected linux empty -> anytls0, got %q", got)
	}
}

func TestNormalizeSubscriptionDefaults(t *testing.T) {
	sub := clientSubscription{
		URL: "https://example.com/sub.txt",
	}
	if err := normalizeSubscription(&sub); err != nil {
		t.Fatalf("normalizeSubscription failed: %v", err)
	}
	if sub.ID == "" || sub.Name == "" {
		t.Fatalf("expected id and name assigned, got %+v", sub)
	}
	if sub.UpdateIntervalSec != 3600 {
		t.Fatalf("expected default interval 3600, got %d", sub.UpdateIntervalSec)
	}
	if sub.NodePrefix == "" {
		t.Fatalf("expected node prefix assigned")
	}
}

func TestNormalizeSubscriptionGroups(t *testing.T) {
	sub := clientSubscription{
		URL:    "https://example.com/sub.txt",
		Groups: []string{" hk ", "prod", "hk", ""},
	}
	if err := normalizeSubscription(&sub); err != nil {
		t.Fatalf("normalizeSubscription failed: %v", err)
	}
	if len(sub.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d (%v)", len(sub.Groups), sub.Groups)
	}
	if sub.Groups[0] != "hk" || sub.Groups[1] != "prod" {
		t.Fatalf("unexpected groups: %v", sub.Groups)
	}
}

func TestNormalizeNodePasswordCompatibilityDecode(t *testing.T) {
	node := clientNodeConfig{
		Name:     "n1",
		Server:   "23.141.52.18:20086",
		Password: "Wangzai007..%40%40",
		URI:      "anytls://Wangzai007..%40%40@23.141.52.18:20086/",
	}
	if err := normalizeNode(&node); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if node.Password != "Wangzai007..@@" {
		t.Fatalf("expected decoded password, got %q", node.Password)
	}
}

func TestNormalizeNodePasswordPreserveURIWhitespace(t *testing.T) {
	node := clientNodeConfig{
		Name: "n1",
		URI:  "anytls://%0A%0AWangzai007..%40%40@23.141.52.18:20086/",
	}
	if err := normalizeNode(&node); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if node.Password != "\n\nWangzai007..@@" {
		t.Fatalf("unexpected password: %q", node.Password)
	}
}

func TestNormalizeNodeGroups(t *testing.T) {
	node := clientNodeConfig{
		Name:     "n1",
		Server:   "example.com:443",
		Password: "p1",
		Groups:   []string{" hk ", "prod", "hk", "", " test "},
	}
	if err := normalizeNode(&node); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(node.Groups) != 3 {
		t.Fatalf("unexpected groups count: %+v", node.Groups)
	}
	want := []string{"hk", "prod", "test"}
	for i := range want {
		if node.Groups[i] != want[i] {
			t.Fatalf("unexpected groups[%d]: got=%q want=%q", i, node.Groups[i], want[i])
		}
	}
}

func TestNormalizeNodeWithSOCKSURI(t *testing.T) {
	node := clientNodeConfig{
		Name: "socks-node",
		URI:  "socks5://user:pass@127.0.0.1:1081",
	}
	if err := normalizeNode(&node); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if node.Server != "127.0.0.1:1081" {
		t.Fatalf("unexpected server: %q", node.Server)
	}
	if node.Password == "" {
		t.Fatalf("expected placeholder password for socks bridge")
	}
}

func TestNormalizeNodeWithExternalCoreURI(t *testing.T) {
	node := clientNodeConfig{
		Name: "sb-node",
		URI:  "singbox://x?socks=127.0.0.1:2080&config=/etc/sing-box/config.json&autostart=1",
	}
	if err := normalizeNode(&node); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if node.Server != "127.0.0.1:2080" {
		t.Fatalf("unexpected server: %q", node.Server)
	}
	if node.Password == "" {
		t.Fatalf("expected placeholder password for external core")
	}
}

func TestBuildAnyTLSURIFromNodeExternal(t *testing.T) {
	node := clientNodeConfig{
		Name: "ext",
		URI:  "mihomo://x?socks=127.0.0.1:7890&config=/etc/mihomo/config.yaml",
	}
	uri, err := buildAnyTLSURIFromNode(node)
	if err != nil {
		t.Fatalf("build uri failed: %v", err)
	}
	if uri != node.URI {
		t.Fatalf("expected raw external uri, got %q", uri)
	}
}

func TestNormalizeNodeWithNativeProtocolURI(t *testing.T) {
	node := clientNodeConfig{
		Name: "vless-node",
		URI:  "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fws",
	}
	if err := normalizeNode(&node); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if node.Server != "example.com:443" {
		t.Fatalf("unexpected server: %q", node.Server)
	}
	if node.Password == "" {
		t.Fatalf("expected placeholder password for native protocol bridge")
	}
}

func TestFailoverDefaultsAndDisablePreserved(t *testing.T) {
	cfg := testClientConfig()
	cfg.Failover = nil
	if err := normalizeAndValidateConfig(cfg); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if cfg.Failover == nil || !cfg.Failover.Enabled {
		t.Fatalf("expected failover to be enabled by default")
	}
	if cfg.Failover.CheckIntervalSec <= 0 || cfg.Failover.FailureThreshold <= 0 || cfg.Failover.ProbeTimeoutMS <= 0 {
		t.Fatalf("invalid failover defaults: %+v", cfg.Failover)
	}

	cfg2 := testClientConfig()
	cfg2.Failover = &clientFailoverConfig{Enabled: false}
	if err := normalizeAndValidateConfig(cfg2); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if cfg2.Failover == nil || cfg2.Failover.Enabled {
		t.Fatalf("expected explicit failover disabled to be preserved")
	}
	if cfg2.Failover.CheckIntervalSec <= 0 || cfg2.Failover.FailureThreshold <= 0 || cfg2.Failover.ProbeTimeoutMS <= 0 {
		t.Fatalf("expected failover defaults even when disabled: %+v", cfg2.Failover)
	}
}

func TestRoutingGroupEgressNormalizeAndValidate(t *testing.T) {
	cfg := testClientConfig()
	cfg.Routing = &clientRoutingConfig{
		Enabled: true,
		GroupEgress: map[string]string{
			" hk ":   " node-1 ",
			"empty":  " ",
			" ":      "node-1",
			"unused": "",
		},
	}
	if err := normalizeAndValidateConfig(cfg); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if cfg.Routing == nil || len(cfg.Routing.GroupEgress) != 1 {
		t.Fatalf("unexpected routing group_egress: %+v", cfg.Routing)
	}
	if got := cfg.Routing.GroupEgress["hk"]; got != "node-1" {
		t.Fatalf("unexpected group mapping: %q", got)
	}
}

func TestRoutingGroupEgressUnknownNodeRejected(t *testing.T) {
	cfg := testClientConfig()
	cfg.Routing = &clientRoutingConfig{
		Enabled: true,
		GroupEgress: map[string]string{
			"hk": "node-2",
		},
	}
	if err := normalizeAndValidateConfig(cfg); err == nil {
		t.Fatalf("expected unknown node validation error")
	}
}

func TestRoutingDefaultActionNormalize(t *testing.T) {
	cfg := testClientConfig()
	cfg.Routing = &clientRoutingConfig{
		Enabled:       true,
		DefaultAction: " group: hk ",
		GroupEgress: map[string]string{
			"hk": "node-1",
		},
	}
	if err := normalizeAndValidateConfig(cfg); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if got := cfg.Routing.DefaultAction; got != "GROUP:hk" {
		t.Fatalf("unexpected default_action: %q", got)
	}

	cfg2 := testClientConfig()
	cfg2.Routing = &clientRoutingConfig{
		Enabled:       true,
		DefaultAction: "reject-drop",
	}
	if err := normalizeAndValidateConfig(cfg2); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if got := cfg2.Routing.DefaultAction; got != "REJECT" {
		t.Fatalf("unexpected default_action canonical value: %q", got)
	}
}

func TestRoutingDefaultActionInvalid(t *testing.T) {
	cfg := testClientConfig()
	cfg.Routing = &clientRoutingConfig{
		Enabled:       true,
		DefaultAction: "node-1",
	}
	if err := normalizeAndValidateConfig(cfg); err == nil {
		t.Fatalf("expected invalid default_action validation error")
	}
}

func TestSaveBackupAndRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")

	cfg1 := testClientConfig()
	cfg1.Nodes[0].Server = "s1.example.com:8443"
	if err := saveClientConfig(path, cfg1); err != nil {
		t.Fatalf("save cfg1 failed: %v", err)
	}

	time.Sleep(2 * time.Millisecond)
	cfg2 := testClientConfig()
	cfg2.Nodes[0].Server = "s2.example.com:8443"
	if err := saveClientConfig(path, cfg2); err != nil {
		t.Fatalf("save cfg2 failed: %v", err)
	}

	time.Sleep(2 * time.Millisecond)
	cfg3 := testClientConfig()
	cfg3.Nodes[0].Server = "s3.example.com:8443"
	if err := saveClientConfig(path, cfg3); err != nil {
		t.Fatalf("save cfg3 failed: %v", err)
	}

	backups, err := listClientConfigBackups(path)
	if err != nil {
		t.Fatalf("list backups failed: %v", err)
	}
	if len(backups) < 2 {
		t.Fatalf("expected at least 2 backups, got %d", len(backups))
	}

	restored, err := rollbackClientConfig(path, backups[0].Name)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if restored != backups[0].Name {
		t.Fatalf("unexpected restored backup: %s", restored)
	}
	cfgAfter, err := loadClientConfig(path)
	if err != nil {
		t.Fatalf("load after rollback failed: %v", err)
	}
	if got := cfgAfter.Nodes[0].Server; got != "s2.example.com:8443" {
		t.Fatalf("unexpected server after rollback, got %s", got)
	}
}

func TestNormalizeRuleProviderAutoDetectMRS(t *testing.T) {
	p := clientRuleProvider{
		Type: "http",
		URL:  "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs",
	}
	if err := normalizeRuleProvider(&p); err != nil {
		t.Fatalf("normalize rule provider failed: %v", err)
	}
	if p.Format != "mrs" {
		t.Fatalf("expected mrs format, got %q", p.Format)
	}
	if p.Behavior != "" {
		t.Fatalf("expected empty behavior for mrs auto-detect, got %q", p.Behavior)
	}
}

func TestNormalizeRuleProviderRejectMRSInline(t *testing.T) {
	p := clientRuleProvider{
		Type:    "inline",
		Format:  "mrs",
		Payload: []string{"DOMAIN,example.com"},
	}
	if err := normalizeRuleProvider(&p); err == nil {
		t.Fatalf("expected mrs inline to be rejected")
	}
}

func TestNormalizeRuleProviderAutoDetectSGModule(t *testing.T) {
	p := clientRuleProvider{
		Type: "http",
		URL:  "https://example.com/adblock.beta.sgmodule",
	}
	if err := normalizeRuleProvider(&p); err != nil {
		t.Fatalf("normalize rule provider failed: %v", err)
	}
	if p.Format != "sgmodule" {
		t.Fatalf("expected sgmodule format, got %q", p.Format)
	}
	if p.Behavior != "classical" {
		t.Fatalf("expected classical behavior default, got %q", p.Behavior)
	}
}

func TestNormalizeRoutingGeoIPConfigHTTP(t *testing.T) {
	cfg := &clientRoutingGeoIPConfig{
		Type: "http",
		URL:  "https://static-sg.529851.xyz/GeoLite2-Country.mmdb",
	}
	if err := normalizeRoutingGeoIPConfig(cfg); err != nil {
		t.Fatalf("normalize geoip http failed: %v", err)
	}
	if cfg.IntervalSec != 3600 {
		t.Fatalf("expected default interval 3600, got %d", cfg.IntervalSec)
	}
}

func TestNormalizeRoutingGeoIPConfigFileMissingPath(t *testing.T) {
	cfg := &clientRoutingGeoIPConfig{Type: "file"}
	if err := normalizeRoutingGeoIPConfig(cfg); err == nil {
		t.Fatalf("expected error for missing geoip file path")
	}
}

func TestNormalizeRoutingConfigInjectGeoIPCNDirectRule(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"DOMAIN-SUFFIX,example.com,DIRECT",
		},
		GeoIP: &clientRoutingGeoIPConfig{
			Type: "http",
			URL:  "https://static-sg.529851.xyz/GeoLite2-Country.mmdb",
		},
	}
	if err := normalizeRoutingConfig(cfg); err != nil {
		t.Fatalf("normalize routing config failed: %v", err)
	}
	if len(cfg.Rules) == 0 || cfg.Rules[0] != "GEOIP,CN,DIRECT" {
		t.Fatalf("expected GEOIP,CN,DIRECT injected at top, got %#v", cfg.Rules)
	}
}

func TestNormalizeRoutingConfigKeepExistingGeoIPCNRule(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"GEOIP,CN,DIRECT",
			"DOMAIN-SUFFIX,example.com,DIRECT",
		},
		GeoIP: &clientRoutingGeoIPConfig{
			Type: "http",
			URL:  "https://static-sg.529851.xyz/GeoLite2-Country.mmdb",
		},
	}
	if err := normalizeRoutingConfig(cfg); err != nil {
		t.Fatalf("normalize routing config failed: %v", err)
	}
	count := 0
	for _, line := range cfg.Rules {
		if strings.EqualFold(strings.TrimSpace(line), "GEOIP,CN,DIRECT") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected GEOIP,CN,DIRECT appears once, got %d in %#v", count, cfg.Rules)
	}
}

func TestNormalizeMITMConfigDefaults(t *testing.T) {
	m := &clientMITMConfig{
		Enabled: true,
		Hosts:   []string{" *.Example.com ", ".foo.com", "bad host"},
	}
	if err := normalizeMITMConfig(m); err != nil {
		t.Fatalf("normalize mitm failed: %v", err)
	}
	if m.Listen == "" {
		t.Fatalf("expected default mitm listen")
	}
	if len(m.Hosts) == 0 {
		t.Fatalf("expected normalized mitm hosts")
	}
	if m.CACertPath == "" || m.CAKeyPath == "" {
		t.Fatalf("expected default ca paths")
	}
}

func TestNormalizeMITMConfigInvalidRegex(t *testing.T) {
	m := &clientMITMConfig{
		Enabled:   true,
		Listen:    "127.0.0.1:1090",
		URLReject: []string{"["},
	}
	if err := normalizeMITMConfig(m); err == nil {
		t.Fatalf("expected invalid regex error")
	}
}

func TestNormalizeMITMConfigDoHDoT(t *testing.T) {
	m := &clientMITMConfig{
		Enabled: true,
		Listen:  "127.0.0.1:1090",
		DoHDoT: &clientMITMDoHDoTConfig{
			Enabled:  true,
			DoHHosts: []string{" DNS.Google ", "*.Example.com", "bad host"},
			DoTHosts: []string{".dot.example.com"},
		},
	}
	if err := normalizeMITMConfig(m); err != nil {
		t.Fatalf("normalize mitm dohdot failed: %v", err)
	}
	if m.DoHDoT == nil || !m.DoHDoT.Enabled {
		t.Fatalf("expected dohdot enabled")
	}
	if got, want := len(m.DoHDoT.DoHHosts), 2; got != want {
		t.Fatalf("unexpected dohdot hosts len: got=%d want=%d", got, want)
	}
	if m.DoHDoT.DoHHosts[0] != "*.example.com" || m.DoHDoT.DoHHosts[1] != "dns.google" {
		t.Fatalf("unexpected dohdot hosts: %#v", m.DoHDoT.DoHHosts)
	}
	if got, want := len(m.DoHDoT.DoTHosts), 1; got != want {
		t.Fatalf("unexpected dot hosts len: got=%d want=%d", got, want)
	}
	if m.DoHDoT.DoTHosts[0] != "*.dot.example.com" {
		t.Fatalf("unexpected dot host: %q", m.DoHDoT.DoTHosts[0])
	}
}
