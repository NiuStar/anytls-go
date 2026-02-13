package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRoutingEngineDecideByDomainSuffix(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,node-2",
			"MATCH,node-1",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	googleDest := M.Socksaddr{Fqdn: "www.google.com", Port: 443}
	decision := decideRouting(engine, googleDest, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-2" {
		t.Fatalf("unexpected decision for google: %+v", decision)
	}

	otherDest := M.Socksaddr{Fqdn: "example.com", Port: 443}
	decision = decideRouting(engine, otherDest, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("unexpected default decision: %+v", decision)
	}
}

func TestRoutingEngineGroupActionResolveNode(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,GROUP:hk",
			"MATCH,node-1",
		},
		GroupEgress: map[string]string{
			"hk": "node-2",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	decision := decideRouting(engine, M.Socksaddr{Fqdn: "www.google.com", Port: 443}, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-2" {
		t.Fatalf("expected group action resolved to node-2, got %+v", decision)
	}
}

func TestRoutingEngineGroupActionFallbackDefaultNode(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,GROUP:hk",
			"MATCH,node-1",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	decision := decideRouting(engine, M.Socksaddr{Fqdn: "www.google.com", Port: 443}, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("expected unresolved group fallback to default node, got %+v", decision)
	}
}

func TestRoutingEngineGroupActionResolveNodeCaseInsensitive(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,GROUP:HK",
			"MATCH,node-1",
		},
		GroupEgress: map[string]string{
			"hk": "node-2",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	decision := decideRouting(engine, M.Socksaddr{Fqdn: "www.google.com", Port: 443}, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-2" {
		t.Fatalf("expected case-insensitive group resolve to node-2, got %+v", decision)
	}
}

func TestRoutingEngineDefaultActionDirect(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled:       true,
		DefaultAction: "DIRECT",
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,node-2",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	decision := decideRouting(engine, M.Socksaddr{Fqdn: "example.com", Port: 443}, "node-1")
	if decision.action.kind != routeActionDirect {
		t.Fatalf("expected default action DIRECT, got %+v", decision)
	}
	if decision.matchedRule != "DEFAULT" {
		t.Fatalf("expected DEFAULT rule, got %q", decision.matchedRule)
	}
}

func TestRoutingEngineDefaultActionGroup(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled:       true,
		DefaultAction: "GROUP:hk",
		GroupEgress: map[string]string{
			"hk": "node-2",
		},
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,node-1",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	decision := decideRouting(engine, M.Socksaddr{Fqdn: "example.com", Port: 443}, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-2" {
		t.Fatalf("expected default GROUP:hk resolve to node-2, got %+v", decision)
	}
}

func TestRoutingEngineDefaultActionReject(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled:       true,
		DefaultAction: "REJECT",
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,node-2",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	decision := decideRouting(engine, M.Socksaddr{Fqdn: "example.com", Port: 443}, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected default action REJECT, got %+v", decision)
	}
}

func TestRoutingEngineRuleSetReject(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,ads,REJECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"ads": {
				Type:     "inline",
				Behavior: "classical",
				Format:   "yaml",
				Payload: []string{
					"DOMAIN-KEYWORD,adservice",
				},
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{Fqdn: "pageadservice.google.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject decision, got %+v", decision)
	}
}

func TestRoutingEngineIPCIDRProvider(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,cn,DIRECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"cn": {
				Type:     "inline",
				Behavior: "ipcidr",
				Format:   "text",
				Payload: []string{
					"1.1.1.0/24",
				},
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{
		Addr: netip.MustParseAddr("1.1.1.8"),
		Port: 443,
	}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionDirect {
		t.Fatalf("expected direct decision, got %+v", decision)
	}
}

func TestRoutingEngineGeoIPRule(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"GEOIP,CN,DIRECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"GeoIP-CN": {
				Type:     "inline",
				Behavior: "ipcidr",
				Format:   "text",
				Payload: []string{
					"1.1.1.0/24",
				},
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{
		Addr: netip.MustParseAddr("1.1.1.8"),
		Port: 443,
	}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionDirect {
		t.Fatalf("expected direct decision, got %+v", decision)
	}

	other := M.Socksaddr{
		Addr: netip.MustParseAddr("8.8.8.8"),
		Port: 443,
	}
	decision = decideRouting(engine, other, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("expected default node decision, got %+v", decision)
	}
}

func TestRoutingEngineGeoIPRuleWithDomainIPHints(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"GEOIP,CN,DIRECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"GeoIP-CN": {
				Type:     "inline",
				Behavior: "ipcidr",
				Format:   "text",
				Payload: []string{
					"1.1.1.0/24",
				},
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{
		Fqdn: "www.baidu.com",
		Port: 443,
	}
	decision := decideRoutingWithDomainHintsAndIPHints(
		engine,
		dest,
		"node-1",
		nil,
		[]netip.Addr{netip.MustParseAddr("1.1.1.8")},
	)
	if decision.action.kind != routeActionDirect {
		t.Fatalf("expected geoip direct decision by domain ip hints, got %+v", decision)
	}

	decision = decideRoutingWithDomainHintsAndIPHints(
		engine,
		dest,
		"node-1",
		nil,
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
	)
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("expected default node decision for non-cn hint ip, got %+v", decision)
	}
}

func TestCompileClassicalRuleGeoIPProviderNotFound(t *testing.T) {
	_, err := compileClassicalRule("GEOIP,CN,DIRECT", map[string]providerDefinition{}, routeAction{kind: routeActionInvalid}, true)
	if err == nil {
		t.Fatalf("expected compile error for missing geoip provider")
	}
	if !strings.Contains(err.Error(), "geoip provider not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompileClassicalRuleGeoIPWithResolverInjected(t *testing.T) {
	providers := map[string]providerDefinition{}
	injectGeoIPProviders(providers, []string{"GEOIP,CN,DIRECT"}, func(ip netip.Addr) (string, bool) {
		if ip == netip.MustParseAddr("1.1.1.8") {
			return "cn", true
		}
		return "", false
	})
	rule, err := compileClassicalRule("GEOIP,CN,DIRECT", providers, routeAction{kind: routeActionInvalid}, true)
	if err != nil {
		t.Fatalf("compile geoip rule failed: %v", err)
	}
	if !rule.match(routeMatchContext{ip: netip.MustParseAddr("1.1.1.8")}) {
		t.Fatalf("expected geoip rule matched for cn ip")
	}
	if rule.match(routeMatchContext{ip: netip.MustParseAddr("8.8.8.8")}) {
		t.Fatalf("expected geoip rule not matched for non-cn ip")
	}
}

func TestBuildRoutingEngineFastGeoIPHTTPNoCompileError(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"GEOIP,CN,DIRECT",
			"MATCH,node-1",
		},
		GeoIP: &clientRoutingGeoIPConfig{
			Type: "http",
			URL:  "https://static-sg.529851.xyz/GeoLite2-Country.mmdb",
		},
	}
	if _, err := buildRoutingEngineFastWithContext(context.Background(), cfg, filepath.Join(t.TempDir(), "client.json")); err != nil {
		t.Fatalf("build routing engine fast failed: %v", err)
	}
}

func TestRoutingEngineProviderActionRulesWithoutRuleSet(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules:   []string{},
		RuleProviders: map[string]clientRuleProvider{
			"ads": {
				Type:     "inline",
				Behavior: "classical",
				Format:   "text",
				Payload: []string{
					"DOMAIN-SUFFIX,example.com,REJECT",
				},
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}
	if !engine.enabled {
		t.Fatalf("expected routing engine enabled with provider action rules")
	}

	dest := M.Socksaddr{Fqdn: "cdn.example.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject decision, got %+v", decision)
	}
}

func TestRoutingEngineRuleSetWithoutActionUsesProviderRules(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,ads",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"ads": {
				Type:     "inline",
				Behavior: "classical",
				Format:   "text",
				Payload: []string{
					"DOMAIN-SUFFIX,example.com,REJECT",
				},
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{Fqdn: "cdn.example.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject decision, got %+v", decision)
	}
}

func TestCompileClassicalRuleRuleSetWithoutActionNoProviderRules(t *testing.T) {
	providers := map[string]providerDefinition{
		"ads": {
			matcher: func(routeMatchContext) bool { return true },
		},
	}
	_, err := compileClassicalRule("RULE-SET,ads", providers, routeAction{kind: routeActionInvalid}, true)
	if err == nil {
		t.Fatalf("expected compile error for ruleset without action and empty provider action rules")
	}
	if !strings.Contains(err.Error(), "provider has no action rules") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoutingEngineDomainHintByIP(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"DOMAIN-SUFFIX,ipw.cn,DIRECT",
			"MATCH,node-1",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{
		Addr: netip.MustParseAddr("1.2.3.4"),
		Port: 443,
	}
	decision := decideRoutingWithDomainHints(engine, dest, "node-1", []string{"4.ipw.cn"})
	if decision.action.kind != routeActionDirect {
		t.Fatalf("expected direct decision from domain hint, got %+v", decision)
	}
}

func TestParseHTTPHost(t *testing.T) {
	raw := []byte("CONNECT 4.ipw.cn:443 HTTP/1.1\r\nHost: 4.ipw.cn:443\r\nUser-Agent: test\r\n\r\n")
	hosts := parseHTTPHost(raw)
	if len(hosts) != 1 || hosts[0] != "4.ipw.cn" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}

func TestSniffConnHostsKeepsPrefetchedData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	payload := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = clientConn.Write([]byte(payload))
		_ = clientConn.Close()
	}()

	hosts, wrapped := sniffConnHosts(serverConn)
	if len(hosts) != 1 || hosts[0] != "example.com" {
		t.Fatalf("unexpected sniff hosts: %#v", hosts)
	}
	data, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatalf("read wrapped conn failed: %v", err)
	}
	if string(data) != payload {
		t.Fatalf("wrapped conn data mismatch: %q", string(data))
	}
	<-done
}

func TestRoutingEngineMRSDomainProvider(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "google.mrs")

	plain := buildSingleDomainSetBinary(t, "+.google.com")
	mrs := buildMRSFile(t, mrsBehaviorDomain, 1, plain)
	if err := os.WriteFile(providerPath, mrs, 0644); err != nil {
		t.Fatalf("write mrs provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,google,node-2",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"google": {
				Type:   "file",
				Format: "mrs",
				Path:   providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	matchDest := M.Socksaddr{Fqdn: "www.google.com", Port: 443}
	decision := decideRouting(engine, matchDest, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-2" {
		t.Fatalf("unexpected decision for google: %+v", decision)
	}

	otherDest := M.Socksaddr{Fqdn: "example.com", Port: 443}
	decision = decideRouting(engine, otherDest, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("unexpected default decision: %+v", decision)
	}
}

func TestRoutingEngineMRSIPCIDRProvider(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "cn.mrs")

	plain := buildSingleIPCIDRSetBinary(t, "1.1.1.0", "1.1.1.255")
	mrs := buildMRSFile(t, mrsBehaviorIPCIDR, 1, plain)
	if err := os.WriteFile(providerPath, mrs, 0644); err != nil {
		t.Fatalf("write mrs provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,cn,DIRECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"cn": {
				Type:   "file",
				Format: "mrs",
				Path:   providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{
		Addr: netip.MustParseAddr("1.1.1.8"),
		Port: 443,
	}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionDirect {
		t.Fatalf("expected direct decision, got %+v", decision)
	}
}

func TestRoutingEngineMRSBehaviorMismatch(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "cn.mrs")

	plain := buildSingleIPCIDRSetBinary(t, "1.1.1.0", "1.1.1.255")
	mrs := buildMRSFile(t, mrsBehaviorIPCIDR, 1, plain)
	if err := os.WriteFile(providerPath, mrs, 0644); err != nil {
		t.Fatalf("write mrs provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,cn,DIRECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"cn": {
				Type:     "file",
				Format:   "mrs",
				Behavior: "domain",
				Path:     providerPath,
			},
		},
	}
	if _, err := buildRoutingEngine(cfg, configPath); err == nil {
		t.Fatalf("expected mrs behavior mismatch error")
	}
}

func TestRoutingEngineSurgeModuleProvider(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "adblock.sgmodule")
	content := `
#!name=adblock
[General]
skip-proxy=localhost
[Rule]
AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-SUFFIX,zijieapi.com)),DIRECT
DOMAIN-SUFFIX,example.com,REJECT,extended-matching,pre-matching
IP-CIDR,203.0.113.0/24,REJECT,no-resolve
URL-REGEX,^http://ads.example.com,REJECT
`
	if err := os.WriteFile(providerPath, []byte(content), 0644); err != nil {
		t.Fatalf("write sgmodule provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,adblock,REJECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"adblock": {
				Type:     "file",
				Format:   "sgmodule",
				Behavior: "classical",
				Path:     providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{Fqdn: "cdn.example.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject decision, got %+v", decision)
	}
}

func TestRoutingEngineLogicalRulesInProvider(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,logic,REJECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"logic": {
				Type:     "inline",
				Behavior: "classical",
				Format:   "text",
				Payload: []string{
					"AND,((DOMAIN-KEYWORD,tnc,extended-matching),(OR,((DOMAIN-SUFFIX,zijieapi.com,extended-matching),(DOMAIN-SUFFIX,snssdk.com,extended-matching)))),DIRECT",
				},
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	matchDest := M.Socksaddr{Fqdn: "api-tnc.zijieapi.com", Port: 443}
	decision := decideRouting(engine, matchDest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject decision for logical match, got %+v", decision)
	}

	noMatchDest := M.Socksaddr{Fqdn: "api.zijieapi.com", Port: 443}
	decision = decideRouting(engine, noMatchDest, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("expected default node decision, got %+v", decision)
	}
}

func TestRoutingEngineNotRule(t *testing.T) {
	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"NOT,(DOMAIN-SUFFIX,example.com),REJECT",
			"MATCH,node-1",
		},
	}
	engine, err := buildRoutingEngine(cfg, filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest1 := M.Socksaddr{Fqdn: "www.example.com", Port: 443}
	decision := decideRouting(engine, dest1, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("expected pass-through for example.com, got %+v", decision)
	}

	dest2 := M.Socksaddr{Fqdn: "www.google.com", Port: 443}
	decision = decideRouting(engine, dest2, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject for NOT rule, got %+v", decision)
	}
}

func TestRoutingEngineSurgeURLRewriteReject(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "rewrite.sgmodule")
	content := `
[URL Rewrite]
^https:\/\/video-dsp\.pddpic\.com\/market-dsp-video\/ - reject
^https:\/\/t-dsp\.pinduoduo\.com\/dspcb\/i\/mrk_ - reject

[MITM]
hostname = %APPEND% video-dsp.pddpic.com, t-dsp.pinduoduo.com
`
	if err := os.WriteFile(providerPath, []byte(content), 0644); err != nil {
		t.Fatalf("write sgmodule provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,rewrite,REJECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"rewrite": {
				Type:     "file",
				Format:   "sgmodule",
				Behavior: "classical",
				Path:     providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{Fqdn: "video-dsp.pddpic.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject from URL Rewrite rule, got %+v", decision)
	}

	other := M.Socksaddr{Fqdn: "example.com", Port: 443}
	decision = decideRouting(engine, other, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-1" {
		t.Fatalf("expected default node, got %+v", decision)
	}
}

func TestRoutingEngineSurgeMITMMetadata(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "mitm.sgmodule")
	content := `
[Rule]
DOMAIN-SUFFIX,example.com,REJECT
[URL Rewrite]
^https:\/\/video-dsp\.pddpic\.com\/market-dsp-video\/ - reject
[MITM]
hostname = %APPEND% video-dsp.pddpic.com, *.example.com
`
	if err := os.WriteFile(providerPath, []byte(content), 0644); err != nil {
		t.Fatalf("write sgmodule provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: false,
		RuleProviders: map[string]clientRuleProvider{
			"mitm": {
				Type:     "file",
				Format:   "sgmodule",
				Behavior: "classical",
				Path:     providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}
	if engine.enabled {
		t.Fatalf("expected disabled routing engine")
	}
	if len(engine.mitmHosts) == 0 {
		t.Fatalf("expected mitm hosts metadata")
	}
	if len(engine.mitmURLRejectRegex) == 0 {
		t.Fatalf("expected mitm url reject metadata")
	}
}

func TestRoutingEngineProviderAutoFormatMRS(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "google.bin")

	plain := buildSingleDomainSetBinary(t, "+.google.com")
	mrs := buildMRSFile(t, mrsBehaviorDomain, 1, plain)
	if err := os.WriteFile(providerPath, mrs, 0644); err != nil {
		t.Fatalf("write provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,google,node-2",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"google": {
				Type:   "file",
				Format: "auto",
				Path:   providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{Fqdn: "www.google.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionNode || decision.action.node != "node-2" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestRoutingEngineProviderAutoFormatSGModule(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "adblock.txt")
	content := `
[Rule]
DOMAIN-SUFFIX,example.com,REJECT
`
	if err := os.WriteFile(providerPath, []byte(content), 0644); err != nil {
		t.Fatalf("write provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,adblock,REJECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"adblock": {
				Type:   "file",
				Format: "auto",
				Path:   providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{Fqdn: "cdn.example.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject decision, got %+v", decision)
	}
}

func TestRoutingEngineProviderAutoFormatYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	providerPath := filepath.Join(dir, "ads.dat")
	content := `
payload:
  - DOMAIN-SUFFIX,example.com
`
	if err := os.WriteFile(providerPath, []byte(content), 0644); err != nil {
		t.Fatalf("write provider failed: %v", err)
	}

	cfg := &clientRoutingConfig{
		Enabled: true,
		Rules: []string{
			"RULE-SET,ads,REJECT",
			"MATCH,node-1",
		},
		RuleProviders: map[string]clientRuleProvider{
			"ads": {
				Type:   "file",
				Format: "auto",
				Path:   providerPath,
			},
		},
	}
	engine, err := buildRoutingEngine(cfg, configPath)
	if err != nil {
		t.Fatalf("build routing engine failed: %v", err)
	}

	dest := M.Socksaddr{Fqdn: "img.example.com", Port: 443}
	decision := decideRouting(engine, dest, "node-1")
	if decision.action.kind != routeActionReject {
		t.Fatalf("expected reject decision, got %+v", decision)
	}
}

func buildMRSFile(t *testing.T, behavior byte, count int64, payload []byte) []byte {
	t.Helper()
	var plain bytes.Buffer
	plain.Write(mrsMagicBytes[:])
	plain.WriteByte(behavior)
	if err := binary.Write(&plain, binary.BigEndian, count); err != nil {
		t.Fatalf("write mrs count failed: %v", err)
	}
	if err := binary.Write(&plain, binary.BigEndian, int64(0)); err != nil {
		t.Fatalf("write mrs extra length failed: %v", err)
	}
	if _, err := plain.Write(payload); err != nil {
		t.Fatalf("write mrs payload failed: %v", err)
	}

	var out bytes.Buffer
	encoder, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatalf("create zstd encoder failed: %v", err)
	}
	if _, err := encoder.Write(plain.Bytes()); err != nil {
		t.Fatalf("encode mrs failed: %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("close zstd encoder failed: %v", err)
	}
	return out.Bytes()
}

func buildSingleIPCIDRSetBinary(t *testing.T, from, to string) []byte {
	t.Helper()
	fromAddr := netip.MustParseAddr(from)
	toAddr := netip.MustParseAddr(to)

	var payload bytes.Buffer
	payload.WriteByte(1) // version
	if err := binary.Write(&payload, binary.BigEndian, int64(1)); err != nil {
		t.Fatalf("write ip range length failed: %v", err)
	}
	if err := binary.Write(&payload, binary.BigEndian, fromAddr.As16()); err != nil {
		t.Fatalf("write ip range from failed: %v", err)
	}
	if err := binary.Write(&payload, binary.BigEndian, toAddr.As16()); err != nil {
		t.Fatalf("write ip range to failed: %v", err)
	}
	return payload.Bytes()
}

func buildSingleDomainSetBinary(t *testing.T, domainRule string) []byte {
	t.Helper()
	key := []byte(strings.ToLower(reverseRunes(domainRule)))
	labels := append([]byte(nil), key...)
	leaves := make([]uint64, 0, 1)
	labelBitmap := make([]uint64, 0, 1)
	setBit := func(bitmap *[]uint64, index int) {
		for index>>6 >= len(*bitmap) {
			*bitmap = append(*bitmap, 0)
		}
		(*bitmap)[index>>6] |= 1 << uint(index&63)
	}
	setBit(&leaves, len(key))
	for i := 0; i < len(key); i++ {
		setBit(&labelBitmap, 2*i+1)
	}
	setBit(&labelBitmap, 2*len(key))

	var payload bytes.Buffer
	payload.WriteByte(1) // version
	if err := binary.Write(&payload, binary.BigEndian, int64(len(leaves))); err != nil {
		t.Fatalf("write domain leaves length failed: %v", err)
	}
	for _, word := range leaves {
		if err := binary.Write(&payload, binary.BigEndian, word); err != nil {
			t.Fatalf("write domain leaves failed: %v", err)
		}
	}
	if err := binary.Write(&payload, binary.BigEndian, int64(len(labelBitmap))); err != nil {
		t.Fatalf("write domain bitmap length failed: %v", err)
	}
	for _, word := range labelBitmap {
		if err := binary.Write(&payload, binary.BigEndian, word); err != nil {
			t.Fatalf("write domain bitmap failed: %v", err)
		}
	}
	if err := binary.Write(&payload, binary.BigEndian, int64(len(labels))); err != nil {
		t.Fatalf("write domain labels length failed: %v", err)
	}
	if _, err := payload.Write(labels); err != nil {
		t.Fatalf("write domain labels failed: %v", err)
	}
	return payload.Bytes()
}
