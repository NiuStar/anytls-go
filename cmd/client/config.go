package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultControlAddr = "127.0.0.1:18990"
const configBackupMaxKeep = 20

type clientProfileConfig struct {
	Listen         string                `json:"listen"`
	MinIdleSession int                   `json:"min_idle_session"`
	Control        string                `json:"control"`
	WebUsername    string                `json:"web_username,omitempty"`
	WebPassword    string                `json:"web_password,omitempty"`
	DefaultNode    string                `json:"default_node"`
	Nodes          []clientNodeConfig    `json:"nodes"`
	Subscriptions  []clientSubscription  `json:"subscriptions,omitempty"`
	Routing        *clientRoutingConfig  `json:"routing,omitempty"`
	Tun            *clientTunConfig      `json:"tun,omitempty"`
	MITM           *clientMITMConfig     `json:"mitm,omitempty"`
	Failover       *clientFailoverConfig `json:"failover,omitempty"`
}

type clientNodeConfig struct {
	Name       string   `json:"name"`
	Server     string   `json:"server"`
	Password   string   `json:"password"`
	SNI        string   `json:"sni,omitempty"`
	EgressIP   string   `json:"egress_ip,omitempty"`
	EgressRule string   `json:"egress_rule,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	SourceID   string   `json:"source_id,omitempty"`
	URI        string   `json:"uri,omitempty"`
}

type clientSubscription struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	URL               string   `json:"url"`
	Enabled           bool     `json:"enabled"`
	UpdateIntervalSec int      `json:"update_interval_sec,omitempty"`
	NodePrefix        string   `json:"node_prefix,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

type clientRoutingConfig struct {
	Enabled       bool                          `json:"enabled"`
	Rules         []string                      `json:"rules,omitempty"`
	RuleProviders map[string]clientRuleProvider `json:"rule_providers,omitempty"`
	GeoIP         *clientRoutingGeoIPConfig     `json:"geoip,omitempty"`
	GroupEgress   map[string]string             `json:"group_egress,omitempty"`
	DefaultAction string                        `json:"default_action,omitempty"`
}

type clientRuleProvider struct {
	Type        string              `json:"type,omitempty"`
	Behavior    string              `json:"behavior,omitempty"`
	Format      string              `json:"format,omitempty"`
	URL         string              `json:"url,omitempty"`
	Path        string              `json:"path,omitempty"`
	Payload     []string            `json:"payload,omitempty"`
	IntervalSec int                 `json:"interval_sec,omitempty"`
	Header      map[string][]string `json:"header,omitempty"`
}

type clientRoutingGeoIPConfig struct {
	Type        string              `json:"type,omitempty"`
	URL         string              `json:"url,omitempty"`
	Path        string              `json:"path,omitempty"`
	IntervalSec int                 `json:"interval_sec,omitempty"`
	Header      map[string][]string `json:"header,omitempty"`
}

type clientTunConfig struct {
	Enabled             bool   `json:"enabled"`
	Name                string `json:"name,omitempty"`
	MTU                 int    `json:"mtu,omitempty"`
	Address             string `json:"address,omitempty"`
	AutoRoute           bool   `json:"auto_route,omitempty"`
	DisableOtherProxies bool   `json:"disable_other_proxies,omitempty"`
}

type clientMITMConfig struct {
	Enabled       bool                    `json:"enabled"`
	Listen        string                  `json:"listen,omitempty"`
	Hosts         []string                `json:"hosts,omitempty"`
	URLReject     []string                `json:"url_reject,omitempty"`
	DoHDoT        *clientMITMDoHDoTConfig `json:"doh_dot,omitempty"`
	CACertPath    string                  `json:"ca_cert_path,omitempty"`
	CAKeyPath     string                  `json:"ca_key_path,omitempty"`
	AllowInsecure bool                    `json:"allow_insecure,omitempty"`
}

type clientMITMDoHDoTConfig struct {
	Enabled  bool     `json:"enabled"`
	DoHHosts []string `json:"doh_hosts,omitempty"`
	DoTHosts []string `json:"dot_hosts,omitempty"`
}

type clientFailoverConfig struct {
	Enabled            bool   `json:"enabled"`
	CheckIntervalSec   int    `json:"check_interval_sec,omitempty"`
	FailureThreshold   int    `json:"failure_threshold,omitempty"`
	ProbeTarget        string `json:"probe_target,omitempty"`
	ProbeTimeoutMS     int    `json:"probe_timeout_ms,omitempty"`
	BestLatencyEnabled bool   `json:"best_latency_enabled,omitempty"`
}

type configBackupInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

func defaultClientConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "anytls", "client.json"), nil
}

func loadClientConfig(path string) (*clientProfileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg clientProfileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	if err := normalizeAndValidateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveClientConfig(path string, cfg *clientProfileConfig) error {
	if err := normalizeAndValidateConfig(cfg); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if _, err := backupCurrentConfig(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0644)
}

func normalizeAndValidateConfig(cfg *clientProfileConfig) error {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	if cfg.MinIdleSession <= 0 {
		cfg.MinIdleSession = 5
	}
	if cfg.Control == "" {
		cfg.Control = defaultControlAddr
	}
	cfg.WebUsername = strings.TrimSpace(cfg.WebUsername)
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return fmt.Errorf("invalid listen address %q: %w", cfg.Listen, err)
	}
	if _, _, err := net.SplitHostPort(cfg.Control); err != nil {
		return fmt.Errorf("invalid control address %q: %w", cfg.Control, err)
	}
	if len(cfg.Nodes) == 0 {
		return fmt.Errorf("no nodes in config")
	}
	if cfg.Tun != nil {
		if err := normalizeTunConfig(cfg.Tun); err != nil {
			return err
		}
	}
	if cfg.MITM != nil {
		if err := normalizeMITMConfig(cfg.MITM); err != nil {
			return err
		}
	}
	if cfg.Failover == nil {
		cfg.Failover = &clientFailoverConfig{Enabled: true}
	}
	normalizeFailoverConfig(cfg.Failover)

	seen := make(map[string]struct{}, len(cfg.Nodes))
	for i := range cfg.Nodes {
		node := &cfg.Nodes[i]
		if err := normalizeNode(node); err != nil {
			return fmt.Errorf("node[%d] %q: %w", i, node.Name, err)
		}
		if _, ok := seen[node.Name]; ok {
			return fmt.Errorf("duplicated node name: %s", node.Name)
		}
		seen[node.Name] = struct{}{}
	}
	subSeen := make(map[string]struct{}, len(cfg.Subscriptions))
	for i := range cfg.Subscriptions {
		sub := &cfg.Subscriptions[i]
		if err := normalizeSubscription(sub); err != nil {
			return fmt.Errorf("subscription[%d]: %w", i, err)
		}
		if _, ok := subSeen[sub.ID]; ok {
			return fmt.Errorf("duplicated subscription id: %s", sub.ID)
		}
		subSeen[sub.ID] = struct{}{}
	}
	if cfg.Routing != nil {
		if err := normalizeRoutingConfig(cfg.Routing); err != nil {
			return err
		}
		for group, node := range cfg.Routing.GroupEgress {
			if _, ok := seen[node]; !ok {
				return fmt.Errorf("routing group_egress %q target node %q not found", group, node)
			}
		}
	}

	if cfg.DefaultNode == "" {
		cfg.DefaultNode = cfg.Nodes[0].Name
	}
	if _, ok := seen[cfg.DefaultNode]; !ok {
		return fmt.Errorf("default_node %q not found", cfg.DefaultNode)
	}
	return nil
}

func normalizeRoutingConfig(cfg *clientRoutingConfig) error {
	cfg.Rules = normalizeRuleLines(cfg.Rules)
	cfg.GroupEgress = normalizeRoutingGroupEgress(cfg.GroupEgress)
	defaultAction, err := normalizeRoutingDefaultAction(cfg.DefaultAction)
	if err != nil {
		return err
	}
	cfg.DefaultAction = defaultAction
	if cfg.GeoIP != nil {
		if err := normalizeRoutingGeoIPConfig(cfg.GeoIP); err != nil {
			return err
		}
		ensureRoutingGeoIPDefaultRule(cfg)
	}
	if len(cfg.RuleProviders) == 0 {
		return nil
	}
	next := make(map[string]clientRuleProvider, len(cfg.RuleProviders))
	for rawName, provider := range cfg.RuleProviders {
		name := strings.TrimSpace(rawName)
		if name == "" {
			return fmt.Errorf("routing: rule provider name cannot be empty")
		}
		if err := normalizeRuleProvider(&provider); err != nil {
			return fmt.Errorf("routing: provider %q: %w", name, err)
		}
		next[name] = provider
	}
	cfg.RuleProviders = next
	return nil
}

func normalizeRoutingGeoIPConfig(cfg *clientRoutingGeoIPConfig) error {
	if cfg == nil {
		return nil
	}
	cfg.Type = strings.ToLower(strings.TrimSpace(cfg.Type))
	cfg.URL = strings.TrimSpace(cfg.URL)
	cfg.Path = strings.TrimSpace(cfg.Path)

	if cfg.Type == "" {
		if cfg.URL != "" {
			cfg.Type = "http"
		} else if cfg.Path != "" {
			cfg.Type = "file"
		}
	}
	switch cfg.Type {
	case "http", "file":
	default:
		return fmt.Errorf("routing: geoip unsupported type %q (expect http/file)", cfg.Type)
	}

	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = 3600
	}

	switch cfg.Type {
	case "http":
		if cfg.URL == "" {
			return fmt.Errorf("routing: geoip url is required when type=http")
		}
		u, err := url.Parse(cfg.URL)
		if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("routing: geoip invalid url %q", cfg.URL)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("routing: geoip unsupported url scheme %q", u.Scheme)
		}
	case "file":
		if cfg.Path == "" {
			return fmt.Errorf("routing: geoip path is required when type=file")
		}
	}
	// GEOIP download headers are no longer configurable in UI.
	cfg.Header = nil
	return nil
}

func ensureRoutingGeoIPDefaultRule(cfg *clientRoutingConfig) {
	if cfg == nil || cfg.GeoIP == nil {
		return
	}
	for _, line := range cfg.Rules {
		parts := splitRuleCSV(line)
		if len(parts) < 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "GEOIP") &&
			strings.EqualFold(strings.TrimSpace(parts[1]), "CN") {
			return
		}
	}
	cfg.Rules = append([]string{"GEOIP,CN,DIRECT"}, cfg.Rules...)
}

func normalizeRoutingDefaultAction(raw string) (string, error) {
	action := strings.TrimSpace(raw)
	if action == "" {
		return "", nil
	}
	parsed, err := parseRouteAction(action)
	if err != nil {
		return "", fmt.Errorf("routing: invalid default_action: %w", err)
	}
	switch parsed.kind {
	case routeActionGroup:
		return "GROUP:" + strings.TrimSpace(parsed.group), nil
	case routeActionDirect:
		return "DIRECT", nil
	case routeActionReject:
		return "REJECT", nil
	case routeActionProxy:
		// PROXY keeps backward compatibility: fallback to current default node.
		return "PROXY", nil
	default:
		return "", fmt.Errorf("routing: default_action only supports GROUP:<name>/DIRECT/REJECT/PROXY")
	}
}

func normalizeRoutingGroupEgress(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for rawGroup, rawNode := range in {
		group := strings.TrimSpace(rawGroup)
		node := strings.TrimSpace(rawNode)
		if group == "" || node == "" {
			continue
		}
		out[group] = node
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeRuleProvider(p *clientRuleProvider) error {
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	if p.Type == "" {
		if strings.TrimSpace(p.URL) != "" {
			p.Type = "http"
		} else if strings.TrimSpace(p.Path) != "" {
			p.Type = "file"
		} else if len(p.Payload) > 0 {
			p.Type = "inline"
		}
	}
	switch p.Type {
	case "http", "file", "inline":
	default:
		return fmt.Errorf("unsupported type %q (expect http/file/inline)", p.Type)
	}

	p.URL = strings.TrimSpace(p.URL)
	p.Path = strings.TrimSpace(p.Path)
	p.Format = strings.ToLower(strings.TrimSpace(p.Format))
	if p.Format == "" {
		if strings.Contains(strings.ToLower(p.URL), ".sgmodule") || strings.Contains(strings.ToLower(p.Path), ".sgmodule") {
			p.Format = "sgmodule"
		} else if strings.HasSuffix(strings.ToLower(p.URL), ".mrs") || strings.HasSuffix(strings.ToLower(p.Path), ".mrs") {
			p.Format = "mrs"
		} else {
			p.Format = "yaml"
		}
	}
	switch p.Format {
	case "yaml", "text", "mrs", "sgmodule", "auto":
	default:
		return fmt.Errorf("unsupported format %q (expect yaml/text/mrs/sgmodule/auto)", p.Format)
	}

	p.Behavior = strings.ToLower(strings.TrimSpace(p.Behavior))
	if p.Behavior == "" && p.Format != "mrs" {
		if p.Format == "auto" && (p.Type == "http" || p.Type == "file") {
			// Auto format for remote/local files: defer behavior decision until content sniffing.
		} else {
			p.Behavior = "classical"
		}
	}
	if p.Behavior != "" {
		switch p.Behavior {
		case "classical", "domain", "ipcidr":
		default:
			return fmt.Errorf("unsupported behavior %q (expect classical/domain/ipcidr)", p.Behavior)
		}
	}

	p.Payload = normalizeRuleLines(p.Payload)
	if p.IntervalSec <= 0 {
		p.IntervalSec = 3600
	}

	switch p.Type {
	case "http":
		if p.URL == "" {
			return fmt.Errorf("url is required when type=http")
		}
		u, err := url.Parse(p.URL)
		if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid url %q", p.URL)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("unsupported url scheme %q", u.Scheme)
		}
	case "file":
		if p.Path == "" {
			return fmt.Errorf("path is required when type=file")
		}
	case "inline":
		if len(p.Payload) == 0 {
			return fmt.Errorf("payload cannot be empty when type=inline")
		}
	}
	if p.Format == "mrs" && p.Type == "inline" {
		return fmt.Errorf("mrs format does not support inline type")
	}
	return nil
}

func normalizeRuleLines(lines []string) []string {
	if len(lines) == 0 {
		return nil
	}
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		line := stripRuleComment(raw)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func stripRuleComment(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}

func normalizeFailoverConfig(cfg *clientFailoverConfig) {
	if cfg.CheckIntervalSec <= 0 {
		cfg.CheckIntervalSec = 15
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 2
	}
	if strings.TrimSpace(cfg.ProbeTarget) == "" {
		cfg.ProbeTarget = defaultLatencyTarget
	} else {
		cfg.ProbeTarget = strings.TrimSpace(cfg.ProbeTarget)
	}
	if cfg.ProbeTimeoutMS <= 0 {
		cfg.ProbeTimeoutMS = 2500
	}
}

func normalizeTunConfig(cfg *clientTunConfig) error {
	cfg.Name = normalizeTunDeviceNameForOS(runtime.GOOS, cfg.Name)
	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}
	if cfg.Address == "" {
		cfg.Address = "198.18.0.1/15"
	}
	if _, _, err := net.ParseCIDR(cfg.Address); err != nil {
		return fmt.Errorf("invalid tun address %q: %w", cfg.Address, err)
	}
	return nil
}

func normalizeMITMConfig(cfg *clientMITMConfig) error {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1090"
	}
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return fmt.Errorf("invalid mitm listen address %q: %w", cfg.Listen, err)
	}

	cfg.Hosts = normalizeMITMHosts(cfg.Hosts)
	cfg.URLReject = normalizeMITMURLReject(cfg.URLReject)
	for _, pattern := range cfg.URLReject {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid mitm url_reject regex %q: %w", pattern, err)
		}
	}

	if strings.TrimSpace(cfg.CACertPath) == "" || strings.TrimSpace(cfg.CAKeyPath) == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("resolve user config dir for mitm ca path: %w", err)
		}
		caDir := filepath.Join(base, "anytls")
		if strings.TrimSpace(cfg.CACertPath) == "" {
			cfg.CACertPath = filepath.Join(caDir, "mitm_ca.crt")
		}
		if strings.TrimSpace(cfg.CAKeyPath) == "" {
			cfg.CAKeyPath = filepath.Join(caDir, "mitm_ca.key")
		}
	}
	cfg.CACertPath = strings.TrimSpace(cfg.CACertPath)
	cfg.CAKeyPath = strings.TrimSpace(cfg.CAKeyPath)
	if cfg.DoHDoT != nil {
		normalizeMITMDoHDoTConfig(cfg.DoHDoT)
	}
	return nil
}

func normalizeMITMDoHDoTConfig(cfg *clientMITMDoHDoTConfig) {
	if cfg == nil {
		return
	}
	cfg.DoHHosts = normalizeMITMHosts(cfg.DoHHosts)
	cfg.DoTHosts = normalizeMITMHosts(cfg.DoTHosts)
}

func normalizeMITMHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		host := normalizeMITMHostPattern(raw)
		if host == "" {
			continue
		}
		out = append(out, host)
	}
	return dedupAndSortStrings(out)
}

func normalizeMITMURLReject(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return dedupAndSortStrings(out)
}

func normalizeTunDeviceNameForOS(goos, name string) string {
	name = strings.TrimSpace(name)
	if goos != "darwin" {
		if name == "" {
			return "anytls0"
		}
		return name
	}
	if isValidDarwinTunName(name) {
		return name
	}
	// Darwin only accepts utun[0-9]* names. Keep it auto-alloc by default.
	return "utun"
}

func isValidDarwinTunName(name string) bool {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "utun") {
		return false
	}
	if len(name) == len("utun") {
		return true
	}
	for _, r := range name[len("utun"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func normalizeNode(node *clientNodeConfig) error {
	node.Name = strings.TrimSpace(node.Name)
	node.Server = strings.TrimSpace(node.Server)
	node.SNI = strings.TrimSpace(node.SNI)
	node.EgressIP = strings.TrimSpace(node.EgressIP)
	node.EgressRule = strings.TrimSpace(node.EgressRule)
	node.Groups = normalizeNodeGroups(node.Groups)
	node.SourceID = strings.TrimSpace(node.SourceID)
	node.URI = strings.TrimSpace(node.URI)

	if node.Name == "" {
		return fmt.Errorf("name is required")
	}

	if node.URI != "" {
		if hasAnyTLSScheme(node.URI) {
			server, password, sni, egressIP, egressRule, err := parseAnyTLSURI(node.URI)
			if err != nil {
				return fmt.Errorf("invalid uri: %w", err)
			}
			if node.Server == "" {
				node.Server = server
			}
			if node.Password == "" {
				node.Password = password
			} else if decoded, ok := decodePasswordCompat(node.Password); ok && decoded == password {
				// Compatibility: older versions could persist URI-escaped password (for example %40).
				// If it decodes to the same value as URI password, normalize to decoded form.
				node.Password = decoded
			}
			if node.SNI == "" {
				node.SNI = sni
			}
			if node.EgressIP == "" {
				node.EgressIP = egressIP
			}
			if node.EgressRule == "" {
				node.EgressRule = egressRule
			}
		} else if spec, ok, err := parseSOCKSBridgeNodeURI(node.URI); ok {
			if err != nil {
				return fmt.Errorf("invalid uri: %w", err)
			}
			if node.Server == "" {
				node.Server = spec.Server
			}
			if node.Password == "" {
				node.Password = "__socks_bridge__"
			}
		} else if err != nil {
			return fmt.Errorf("invalid uri: %w", err)
		} else if spec, ok, err := parseExternalCoreNodeURI(node.URI); ok {
			if err != nil {
				return fmt.Errorf("invalid uri: %w", err)
			}
			if node.Server == "" {
				node.Server = spec.SOCKS.Server
			}
			if node.Password == "" {
				node.Password = "__external_core__"
			}
		} else if err != nil {
			return fmt.Errorf("invalid uri: %w", err)
		} else if native, ok, err := parseNativeProxyNodeURI(node.URI); ok {
			if err != nil {
				return fmt.Errorf("invalid uri: %w", err)
			}
			if node.Server == "" {
				node.Server = native.Server
			}
			if node.Password == "" {
				node.Password = "__external_core__"
			}
			if node.Name == "" && strings.TrimSpace(native.NameHint) != "" {
				node.Name = strings.TrimSpace(native.NameHint)
			}
		} else if err != nil {
			return fmt.Errorf("invalid uri: %w", err)
		} else {
			return fmt.Errorf("unsupported uri scheme")
		}
	}

	if node.Server == "" {
		return fmt.Errorf("server is required")
	}
	if node.Password == "" {
		return fmt.Errorf("password is required")
	}
	if _, _, err := net.SplitHostPort(node.Server); err != nil {
		return fmt.Errorf("invalid server address %q: %w", node.Server, err)
	}
	if node.EgressIP != "" {
		ip := net.ParseIP(node.EgressIP)
		if ip == nil {
			return fmt.Errorf("invalid egress_ip: %s", node.EgressIP)
		}
		node.EgressIP = ip.String()
	}
	return nil
}

func normalizeNodeGroups(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		group := strings.TrimSpace(raw)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		out = append(out, group)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func normalizeSubscription(sub *clientSubscription) error {
	sub.ID = strings.TrimSpace(sub.ID)
	sub.Name = strings.TrimSpace(sub.Name)
	sub.URL = strings.TrimSpace(sub.URL)
	sub.NodePrefix = strings.TrimSpace(sub.NodePrefix)
	sub.Groups = normalizeNodeGroups(sub.Groups)
	if sub.URL == "" {
		return fmt.Errorf("url is required")
	}
	u, err := url.Parse(sub.URL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https")
	}
	if sub.ID == "" {
		sub.ID = stableSubscriptionID(sub.URL)
	}
	if sub.Name == "" {
		sub.Name = sub.ID
	}
	if sub.UpdateIntervalSec <= 0 {
		sub.UpdateIntervalSec = 3600
	}
	if sub.UpdateIntervalSec < 60 {
		sub.UpdateIntervalSec = 60
	}
	if sub.NodePrefix == "" {
		sub.NodePrefix = sanitizeNodeName(sub.Name)
	}
	if sub.NodePrefix == "" {
		sub.NodePrefix = "sub-" + sub.ID
	}
	return nil
}

func stableSubscriptionID(seed string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(seed)))
	return "sub-" + hex.EncodeToString(sum[:4])
}

func parseAnyTLSURI(raw string) (server, password, sni, egressIP, egressRule string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", "", "", err
	}
	if u.Scheme != "anytls" {
		return "", "", "", "", "", fmt.Errorf("scheme must be anytls")
	}
	server = u.Host
	if u.User != nil {
		// URI userinfo is percent-encoded on wire; store decoded password in config.
		password = u.User.Username()
	}
	q := u.Query()
	sni = q.Get("sni")
	egressIP = q.Get("egress-ip")
	egressRule = q.Get("egress-rule")
	return
}

func parseNodeURI(rawURI string) (server, password, sni, egressIP, egressRule string, err error) {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		err = fmt.Errorf("uri is required")
		return
	}
	if hasAnyTLSScheme(rawURI) {
		return parseAnyTLSURI(rawURI)
	}
	if spec, ok, parseErr := parseSOCKSBridgeNodeURI(rawURI); ok {
		if parseErr != nil {
			err = parseErr
			return
		}
		server = spec.Server
		password = "__socks_bridge__"
		return
	} else if parseErr != nil {
		err = parseErr
		return
	}
	if spec, ok, parseErr := parseExternalCoreNodeURI(rawURI); ok {
		if parseErr != nil {
			err = parseErr
			return
		}
		server = spec.SOCKS.Server
		password = "__external_core__"
		return
	} else if parseErr != nil {
		err = parseErr
		return
	}
	if native, ok, parseErr := parseNativeProxyNodeURI(rawURI); ok {
		if parseErr != nil {
			err = parseErr
			return
		}
		server = native.Server
		password = "__external_core__"
		return
	} else if parseErr != nil {
		err = parseErr
		return
	}
	err = fmt.Errorf("unsupported uri scheme")
	return
}

func buildAnyTLSURIFromNode(node clientNodeConfig) (string, error) {
	if raw := strings.TrimSpace(node.URI); raw != "" && !hasAnyTLSScheme(raw) {
		return raw, nil
	}
	server := strings.TrimSpace(node.Server)
	password := strings.TrimSpace(node.Password)
	if server == "" || password == "" {
		return "", fmt.Errorf("server/password is required")
	}
	u := &url.URL{
		Scheme: "anytls",
		Host:   server,
		User:   url.User(password),
	}
	q := url.Values{}
	if sni := strings.TrimSpace(node.SNI); sni != "" {
		q.Set("sni", sni)
	}
	if egressIP := strings.TrimSpace(node.EgressIP); egressIP != "" {
		q.Set("egress-ip", egressIP)
	}
	if egressRule := strings.TrimSpace(node.EgressRule); egressRule != "" {
		q.Set("egress-rule", egressRule)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func decodePasswordCompat(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, "%") {
		return "", false
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", false
	}
	if decoded == raw {
		return "", false
	}
	return decoded, true
}

func findNodeByName(nodes []clientNodeConfig, name string) (clientNodeConfig, bool) {
	for _, n := range nodes {
		if n.Name == name {
			return n, true
		}
	}
	return clientNodeConfig{}, false
}

func upsertNodeFromURI(cfg *clientProfileConfig, nodeName, rawURI string) (string, error) {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return "", fmt.Errorf("uri is required")
	}

	server, password, sni, egressIP, egressRule, err := parseNodeURI(rawURI)
	if err != nil {
		return "", err
	}

	name := strings.TrimSpace(nodeName)
	if name == "" {
		name = generateUniqueNodeName(cfg.Nodes, server)
	}

	node := clientNodeConfig{
		Name:       name,
		Server:     server,
		Password:   password,
		SNI:        sni,
		EgressIP:   egressIP,
		EgressRule: egressRule,
		URI:        rawURI,
	}

	updated := false
	for i := range cfg.Nodes {
		if cfg.Nodes[i].Name == name {
			cfg.Nodes[i] = node
			updated = true
			break
		}
	}
	if !updated {
		// First import usually replaces the template placeholder node.
		if len(cfg.Nodes) == 1 && isTemplatePlaceholderNode(cfg.Nodes[0]) {
			cfg.Nodes[0] = node
			cfg.DefaultNode = name
		} else {
			cfg.Nodes = append(cfg.Nodes, node)
		}
	}

	if cfg.DefaultNode == "" {
		cfg.DefaultNode = name
	}

	if err := normalizeAndValidateConfig(cfg); err != nil {
		return "", err
	}
	return name, nil
}

func generateUniqueNodeName(nodes []clientNodeConfig, server string) string {
	base := sanitizeNodeName(hostFromServerAddr(server))
	if base == "" {
		base = "node"
	}

	exists := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		exists[n.Name] = struct{}{}
	}

	if _, ok := exists[base]; !ok {
		return base
	}
	for i := 1; ; i++ {
		candidate := base + "-" + strconv.Itoa(i)
		if _, ok := exists[candidate]; !ok {
			return candidate
		}
	}
}

func hostFromServerAddr(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return server
	}
	return strings.Trim(host, "[]")
}

func sanitizeNodeName(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range in {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "node"
	}
	return out
}

func isTemplatePlaceholderNode(node clientNodeConfig) bool {
	return strings.TrimSpace(node.Name) == "node-1" &&
		strings.TrimSpace(node.Server) == "example.com:8443" &&
		strings.TrimSpace(node.Password) == "change-me"
}

func configBackupDir(path string) string {
	base := filepath.Base(path)
	return filepath.Join(filepath.Dir(path), "."+base+".bak")
}

func backupCurrentConfig(path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()

	backupDir := configBackupDir(path)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s.%s.bak", filepath.Base(path), time.Now().Format("20060102-150405.000000000"))
	backupPath := filepath.Join(backupDir, name)

	dst, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return "", err
	}
	if err := dst.Close(); err != nil {
		return "", err
	}

	_ = pruneConfigBackups(path, configBackupMaxKeep)
	return backupPath, nil
}

func listClientConfigBackups(path string) ([]configBackupInfo, error) {
	backupDir := configBackupDir(path)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	backups := make([]configBackupInfo, 0, len(entries))
	prefix := filepath.Base(path) + "."
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".bak") {
			continue
		}
		full := filepath.Join(backupDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backups = append(backups, configBackupInfo{
			Name:    name,
			Path:    full,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].ModTime.After(backups[j].ModTime)
	})
	return backups, nil
}

func rollbackClientConfig(path, backupName string) (string, error) {
	backups, err := listClientConfigBackups(path)
	if err != nil {
		return "", err
	}
	if len(backups) == 0 {
		return "", fmt.Errorf("no config backups found")
	}

	var selected *configBackupInfo
	if strings.TrimSpace(backupName) == "" {
		selected = &backups[0]
	} else {
		target := strings.TrimSpace(backupName)
		for i := range backups {
			if backups[i].Name == target || backups[i].Path == target {
				selected = &backups[i]
				break
			}
		}
		if selected == nil {
			return "", fmt.Errorf("backup not found: %s", target)
		}
	}

	raw, err := os.ReadFile(selected.Path)
	if err != nil {
		return "", err
	}
	var cfg clientProfileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("invalid backup config: %w", err)
	}
	if err := normalizeAndValidateConfig(&cfg); err != nil {
		return "", fmt.Errorf("invalid backup config: %w", err)
	}
	if err := saveClientConfig(path, &cfg); err != nil {
		return "", err
	}
	return selected.Name, nil
}

func pruneConfigBackups(path string, maxKeep int) error {
	if maxKeep <= 0 {
		return nil
	}
	backups, err := listClientConfigBackups(path)
	if err != nil {
		return err
	}
	if len(backups) <= maxKeep {
		return nil
	}
	for i := maxKeep; i < len(backups); i++ {
		_ = os.Remove(backups[i].Path)
	}
	return nil
}
