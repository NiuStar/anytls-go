package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/oschwald/maxminddb-golang"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sirupsen/logrus"
)

var errRouteRejected = errors.New("routing rejected by rule")

type routeWarnLogger struct {
	mu         sync.Mutex
	nextLogAt  time.Time
	suppressed int
	lastMsg    string
}

func (l *routeWarnLogger) log(prefix string, err error) {
	if err == nil {
		return
	}
	now := time.Now()
	msg := err.Error()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Before(l.nextLogAt) {
		l.suppressed++
		l.lastMsg = msg
		return
	}

	if l.suppressed > 0 {
		logrus.Warnf("%s: %s (suppressed %d repeats)", prefix, l.lastMsg, l.suppressed)
	}
	logrus.Warnf("%s: %v", prefix, err)
	l.lastMsg = msg
	l.nextLogAt = now.Add(2 * time.Second)
	l.suppressed = 0
}

var prepareDirectBypassWarnLogger routeWarnLogger

type routeActionKind uint8

const (
	routeActionInvalid routeActionKind = iota
	routeActionNode
	routeActionGroup
	routeActionDirect
	routeActionReject
	routeActionProxy
)

type routeAction struct {
	kind  routeActionKind
	node  string
	group string
}

type routeMatchContext struct {
	destination M.Socksaddr
	host        string
	port        uint16
	ip          netip.Addr
}

type compiledRouteRule struct {
	raw           string
	action        routeAction
	match         func(routeMatchContext) bool
	resolveAction func(routeMatchContext) (routeAction, bool)
}

type routingEngine struct {
	enabled            bool
	rules              []compiledRouteRule
	groupEgress        map[string]string
	defaultAction      routeAction
	mitmHosts          []string
	mitmURLRejectRegex []*regexp.Regexp
}

type routeDecision struct {
	action      routeAction
	matchedRule string
}

type prefixedConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if c == nil || c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}

func formatRouteDecisionAction(action routeAction) (actionName, node string) {
	switch action.kind {
	case routeActionReject:
		return "REJECT", ""
	case routeActionDirect:
		return "DIRECT", ""
	case routeActionProxy:
		return "PROXY", ""
	case routeActionNode:
		return "NODE", strings.TrimSpace(action.node)
	case routeActionGroup:
		return "GROUP", strings.TrimSpace(action.group)
	default:
		return "UNKNOWN", strings.TrimSpace(action.node)
	}
}

const (
	mrsBehaviorDomain    = byte(0)
	mrsBehaviorIPCIDR    = byte(1)
	mrsBehaviorClassical = byte(2)
)

var mrsMagicBytes = [4]byte{'M', 'R', 'S', 1}

type providerMatcher func(routeMatchContext) bool
type geoipCountryResolver func(netip.Addr) (string, bool)
type providerDefinition struct {
	matcher     providerMatcher
	actionRules []compiledRouteRule
}
type providerCompileResult struct {
	matcher            providerMatcher
	actionRules        []compiledRouteRule
	mitmHosts          []string
	mitmURLRejectRules []string
}

type providerProbePreview struct {
	Format         string
	Behavior       string
	EntryCount     int
	MITMHosts      []string
	URLRejectCount int
	Samples        []string
}

type geoIPCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	RepresentedCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"represented_country"`
}

type geoIPCompileResult struct {
	AttemptAt time.Time
	Attempted bool
	Success   bool
	Skipped   bool
	Error     string
}

type compileRuleOptions struct {
	skipHTTPFetch bool
	onGeoIPResult func(geoIPCompileResult)
}

func buildRoutingEngine(cfg *clientRoutingConfig, configPath string) (*routingEngine, error) {
	return buildRoutingEngineWithContext(context.Background(), cfg, configPath)
}

func buildRoutingEngineWithContext(ctx context.Context, cfg *clientRoutingConfig, configPath string) (*routingEngine, error) {
	return buildRoutingEngineWithOptions(ctx, cfg, configPath, compileRuleOptions{})
}

func buildRoutingEngineFastWithContext(ctx context.Context, cfg *clientRoutingConfig, configPath string) (*routingEngine, error) {
	return buildRoutingEngineWithOptions(ctx, cfg, configPath, compileRuleOptions{skipHTTPFetch: true})
}

func buildRoutingEngineWithOptions(ctx context.Context, cfg *clientRoutingConfig, configPath string, opts compileRuleOptions) (*routingEngine, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		return &routingEngine{enabled: false}, nil
	}
	providers, mitmHosts, mitmURLRejectRegex, err := compileRuleProviders(ctx, cfg.RuleProviders, filepath.Dir(configPath), opts)
	if err != nil {
		return nil, err
	}
	geoipResolver, err := compileRoutingGeoIPResolver(ctx, cfg.GeoIP, filepath.Dir(configPath), opts)
	if err != nil {
		return nil, err
	}
	if geoipResolver != nil {
		injectGeoIPProviders(providers, cfg.Rules, geoipResolver)
	}

	defaultAction := routeAction{kind: routeActionProxy}
	if cfg != nil {
		if raw := strings.TrimSpace(cfg.DefaultAction); raw != "" {
			parsed, err := parseRouteAction(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid routing default_action: %w", err)
			}
			defaultAction = parsed
		}
	}

	engine := &routingEngine{
		enabled:            cfg.Enabled,
		rules:              make([]compiledRouteRule, 0, len(cfg.Rules)),
		groupEgress:        normalizeRoutingGroupEgress(cfg.GroupEgress),
		defaultAction:      defaultAction,
		mitmHosts:          mitmHosts,
		mitmURLRejectRegex: mitmURLRejectRegex,
	}
	if !cfg.Enabled {
		return engine, nil
	}
	for _, line := range cfg.Rules {
		rule, err := compileClassicalRule(line, providers, routeAction{kind: routeActionInvalid}, true)
		if err != nil {
			logrus.Warnf("[Client] skip invalid routing rule %q: %v", line, err)
			continue
		}
		engine.rules = append(engine.rules, rule)
	}
	if len(providers) > 0 {
		providerNames := make([]string, 0, len(providers))
		for name := range providers {
			providerNames = append(providerNames, name)
		}
		sort.Strings(providerNames)
		for _, name := range providerNames {
			provider := providers[name]
			for _, providerRule := range provider.actionRules {
				if providerRule.match == nil {
					continue
				}
				cloned := providerRule
				if strings.TrimSpace(cloned.raw) == "" {
					cloned.raw = fmt.Sprintf("RULE-SET,%s", name)
				} else {
					cloned.raw = fmt.Sprintf("RULE-SET,%s => %s", name, cloned.raw)
				}
				engine.rules = append(engine.rules, cloned)
			}
		}
	}
	if len(engine.rules) == 0 {
		logrus.Warnln("[Client] routing enabled but no valid rules, fallback to default node")
		engine.enabled = false
	}
	return engine, nil
}

func compileRoutingGeoIPResolver(ctx context.Context, cfg *clientRoutingGeoIPConfig, configDir string, opts compileRuleOptions) (geoipCountryResolver, error) {
	if cfg == nil {
		return nil, nil
	}
	notifyGeoIPResult := func(result geoIPCompileResult) {
		if opts.onGeoIPResult != nil {
			opts.onGeoIPResult(result)
		}
	}
	source := clientRuleProvider{
		Type:   cfg.Type,
		URL:    cfg.URL,
		Path:   cfg.Path,
		Header: cfg.Header,
	}
	attemptAt := time.Now()
	if opts.skipHTTPFetch && strings.EqualFold(strings.TrimSpace(source.Type), "http") {
		// Keep GEOIP rule compilation stable during fast startup path.
		// Real mmdb data will be loaded in normal build path.
		notifyGeoIPResult(geoIPCompileResult{
			AttemptAt: attemptAt,
			Skipped:   true,
		})
		return func(netip.Addr) (string, bool) {
			return "", false
		}, nil
	}
	raw, err := loadProviderRaw(ctx, source, configDir)
	if err != nil {
		notifyGeoIPResult(geoIPCompileResult{
			AttemptAt: attemptAt,
			Attempted: true,
			Success:   false,
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("routing geoip: load mmdb: %w", err)
	}
	reader, err := maxminddb.FromBytes(raw)
	if err != nil {
		notifyGeoIPResult(geoIPCompileResult{
			AttemptAt: attemptAt,
			Attempted: true,
			Success:   false,
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("routing geoip: parse mmdb: %w", err)
	}
	notifyGeoIPResult(geoIPCompileResult{
		AttemptAt: attemptAt,
		Attempted: true,
		Success:   true,
	})
	return func(ip netip.Addr) (string, bool) {
		if !ip.IsValid() {
			return "", false
		}
		lookupIP := net.IP(ip.Unmap().AsSlice())
		if len(lookupIP) == 0 {
			return "", false
		}
		var record geoIPCountryRecord
		if err := reader.Lookup(lookupIP, &record); err != nil {
			return "", false
		}
		code := strings.TrimSpace(record.Country.ISOCode)
		if code == "" {
			code = strings.TrimSpace(record.RegisteredCountry.ISOCode)
		}
		if code == "" {
			code = strings.TrimSpace(record.RepresentedCountry.ISOCode)
		}
		if code == "" {
			return "", false
		}
		return strings.ToLower(code), true
	}, nil
}

func collectGeoIPRuleCountries(rules []string) []string {
	if len(rules) == 0 {
		return nil
	}
	set := make(map[string]struct{})
	for _, line := range rules {
		parts := splitRuleCSV(line)
		if len(parts) < 2 {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(parts[0])) != "GEOIP" {
			continue
		}
		country := strings.ToLower(strings.TrimSpace(parts[1]))
		if country == "" {
			continue
		}
		set[country] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for country := range set {
		out = append(out, country)
	}
	sort.Strings(out)
	return out
}

func injectGeoIPProviders(providers map[string]providerDefinition, rules []string, resolver geoipCountryResolver) {
	if providers == nil || resolver == nil {
		return
	}
	for _, country := range collectGeoIPRuleCountries(rules) {
		countryCode := country
		matcher := func(ctx routeMatchContext) bool {
			if !ctx.ip.IsValid() {
				return false
			}
			resolved, ok := resolver(ctx.ip)
			return ok && resolved == countryCode
		}
		for _, alias := range buildGeoIPProviderNameCandidates(countryCode) {
			if _, ok := providers[alias]; ok {
				continue
			}
			providers[alias] = providerDefinition{matcher: matcher}
		}
	}
}

func compileRuleProviders(ctx context.Context, in map[string]clientRuleProvider, configDir string, opts compileRuleOptions) (map[string]providerDefinition, []string, []*regexp.Regexp, error) {
	if len(in) == 0 {
		return map[string]providerDefinition{}, nil, nil, nil
	}
	keys := make([]string, 0, len(in))
	for name := range in {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	out := make(map[string]providerDefinition, len(in))
	mitmHostSet := make(map[string]struct{})
	urlRejectSet := make(map[string]struct{})
	for _, name := range keys {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		provider := in[name]
		if opts.skipHTTPFetch && strings.EqualFold(strings.TrimSpace(provider.Type), "http") {
			// Startup/config-save path: avoid blocking on remote provider download.
			// The provider will be fetched asynchronously by routing warm-up scheduler.
			out[name] = providerDefinition{
				matcher: func(routeMatchContext) bool { return false },
			}
			continue
		}
		result, err := compileSingleProviderMatcher(ctx, provider, configDir)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("provider %q: %w", name, err)
		}
		out[name] = providerDefinition{
			matcher:     result.matcher,
			actionRules: result.actionRules,
		}
		for _, host := range result.mitmHosts {
			host = normalizeMITMHostPattern(host)
			if host == "" {
				continue
			}
			mitmHostSet[host] = struct{}{}
		}
		for _, pattern := range result.mitmURLRejectRules {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			urlRejectSet[pattern] = struct{}{}
		}
	}

	mitmHosts := make([]string, 0, len(mitmHostSet))
	for host := range mitmHostSet {
		mitmHosts = append(mitmHosts, host)
	}
	sort.Strings(mitmHosts)

	urlRejectKeys := make([]string, 0, len(urlRejectSet))
	for pattern := range urlRejectSet {
		urlRejectKeys = append(urlRejectKeys, pattern)
	}
	sort.Strings(urlRejectKeys)
	compiledRejectRegex := make([]*regexp.Regexp, 0, len(urlRejectKeys))
	for _, pattern := range urlRejectKeys {
		re, err := compileSurgeURLRegexPattern(pattern)
		if err != nil {
			logrus.Warnf("[Client] skip invalid sgmodule URL rewrite regex %q: %v", pattern, err)
			continue
		}
		compiledRejectRegex = append(compiledRejectRegex, re)
	}

	return out, mitmHosts, compiledRejectRegex, nil
}

func compileSingleProviderMatcher(ctx context.Context, provider clientRuleProvider, configDir string) (providerCompileResult, error) {
	format := strings.ToLower(strings.TrimSpace(provider.Format))
	behavior := strings.ToLower(strings.TrimSpace(provider.Behavior))

	if provider.Type == "inline" {
		if format == "mrs" {
			return providerCompileResult{}, fmt.Errorf("mrs format does not support inline provider")
		}
		if behavior == "" {
			behavior = "classical"
		}
		entries := normalizeRuleLines(provider.Payload)
		matcher, err := compileProviderMatcher(behavior, entries)
		if err != nil {
			return providerCompileResult{}, fmt.Errorf("compile matcher: %w", err)
		}
		result := providerCompileResult{matcher: matcher}
		if behavior == "classical" {
			result.actionRules = compileClassicalProviderActionRules(entries)
		}
		return result, nil
	}

	raw, err := loadProviderRaw(ctx, provider, configDir)
	if err != nil {
		return providerCompileResult{}, err
	}
	if format == "auto" {
		detected, err := detectRuleProviderFormat(raw)
		if err != nil {
			return providerCompileResult{}, err
		}
		format = detected
	}

	switch format {
	case "mrs":
		matcher, err := compileMRSProviderMatcherFromRaw(raw, behavior)
		if err != nil {
			return providerCompileResult{}, err
		}
		return providerCompileResult{matcher: matcher}, nil
	case "sgmodule":
		parsed, err := parseSurgeModule(string(raw))
		if err != nil {
			return providerCompileResult{}, err
		}
		if behavior == "" {
			behavior = "classical"
		}
		matcher, err := compileProviderMatcher(behavior, parsed.rules)
		if err != nil {
			return providerCompileResult{}, fmt.Errorf("compile matcher: %w", err)
		}
		result := providerCompileResult{
			matcher:            matcher,
			mitmHosts:          parsed.mitmHosts,
			mitmURLRejectRules: parsed.urlRewriteRejectRules,
		}
		if behavior == "classical" {
			result.actionRules = compileClassicalProviderActionRules(parsed.rules)
		}
		return result, nil
	case "yaml", "text":
		entries, err := decodeProviderPayload(raw, format)
		if err != nil {
			return providerCompileResult{}, fmt.Errorf("load entries: %w", err)
		}
		if behavior == "" {
			behavior = "classical"
		}
		matcher, err := compileProviderMatcher(behavior, entries)
		if err != nil {
			return providerCompileResult{}, fmt.Errorf("compile matcher: %w", err)
		}
		result := providerCompileResult{matcher: matcher}
		if behavior == "classical" {
			result.actionRules = compileClassicalProviderActionRules(entries)
		}
		return result, nil
	default:
		return providerCompileResult{}, fmt.Errorf("unsupported provider format %q", format)
	}
}

func loadProviderRaw(ctx context.Context, provider clientRuleProvider, configDir string) ([]byte, error) {
	switch provider.Type {
	case "file":
		path := provider.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(configDir, path)
		}
		return os.ReadFile(path)
	case "http":
		if ctx == nil {
			ctx = context.Background()
		}
		client := newRuntimeHTTPClient(25 * time.Second)
		requestURLs := runtimeRequestURLCandidates(provider.URL)
		var lastErr error
		for idx, requestURL := range requestURLs {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
			if err != nil {
				return nil, err
			}
			for key, values := range provider.Header {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
			req.Header.Set("User-Agent", "anytls-client-routing/1.0")
			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				if idx == 0 && len(requestURLs) > 1 {
					continue
				}
				return nil, err
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				_ = resp.Body.Close()
				lastErr = fmt.Errorf("http status %d", resp.StatusCode)
				if idx == 0 && len(requestURLs) > 1 {
					continue
				}
				return nil, lastErr
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				lastErr = readErr
				if idx == 0 && len(requestURLs) > 1 {
					continue
				}
				return nil, readErr
			}
			return body, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no request url candidate")
		}
		return nil, lastErr
	default:
		return nil, fmt.Errorf("unsupported provider type %q for binary loading", provider.Type)
	}
}

func decodeProviderPayload(raw []byte, format string) ([]string, error) {
	content := string(raw)
	switch format {
	case "text":
		return normalizeRuleLines(strings.Split(content, "\n")), nil
	case "yaml":
		return parseYAMLPayload(content)
	case "sgmodule":
		return parseSurgeModulePayload(content)
	default:
		return nil, fmt.Errorf("unsupported provider format %q", format)
	}
}

func detectRuleProviderFormat(raw []byte) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", fmt.Errorf("provider payload is empty")
	}
	if isMRSProviderRaw(raw) {
		return "mrs", nil
	}
	content := string(raw)
	if looksLikeSurgeModule(content) {
		if _, err := parseSurgeModule(content); err == nil {
			return "sgmodule", nil
		}
	}
	if _, err := parseYAMLPayload(content); err == nil {
		return "yaml", nil
	}
	return "text", nil
}

func isMRSProviderRaw(raw []byte) bool {
	decoder, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	defer decoder.Close()
	var magic [4]byte
	if _, err := io.ReadFull(decoder, magic[:]); err != nil {
		return false
	}
	return magic == mrsMagicBytes
}

func looksLikeSurgeModule(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "[rule]") || strings.Contains(lower, "[url rewrite]") || strings.Contains(lower, "[mitm]")
}

func probeRuleProviderSource(ctx context.Context, provider clientRuleProvider, configDir string) (providerProbePreview, error) {
	format := strings.ToLower(strings.TrimSpace(provider.Format))
	behavior := strings.ToLower(strings.TrimSpace(provider.Behavior))
	if format == "" {
		format = "auto"
	}

	var raw []byte
	switch provider.Type {
	case "inline":
		raw = []byte(strings.Join(provider.Payload, "\n"))
	case "file", "http":
		var err error
		raw, err = loadProviderRaw(ctx, provider, configDir)
		if err != nil {
			return providerProbePreview{}, err
		}
	default:
		return providerProbePreview{}, fmt.Errorf("unsupported provider type %q", provider.Type)
	}

	if format == "auto" {
		detected, err := detectRuleProviderFormat(raw)
		if err != nil {
			return providerProbePreview{}, err
		}
		format = detected
	}

	switch format {
	case "mrs":
		meta, err := parseMRSMetadata(raw)
		if err != nil {
			return providerProbePreview{}, err
		}
		if behavior != "" && behavior != meta.Behavior {
			return providerProbePreview{}, fmt.Errorf("mrs behavior mismatch: provider=%s mrs=%s", behavior, meta.Behavior)
		}
		if behavior == "" {
			behavior = meta.Behavior
		}
		return providerProbePreview{
			Format:     "mrs",
			Behavior:   behavior,
			EntryCount: meta.Count,
		}, nil
	case "sgmodule":
		parsed, err := parseSurgeModule(string(raw))
		if err != nil {
			return providerProbePreview{}, err
		}
		if behavior == "" {
			behavior = "classical"
		}
		return providerProbePreview{
			Format:         "sgmodule",
			Behavior:       behavior,
			EntryCount:     len(parsed.rules),
			MITMHosts:      limitStringSlice(parsed.mitmHosts, 20),
			URLRejectCount: len(parsed.urlRewriteRejectRules),
			Samples:        limitStringSlice(parsed.rules, 5),
		}, nil
	case "yaml", "text":
		entries, err := decodeProviderPayload(raw, format)
		if err != nil {
			return providerProbePreview{}, err
		}
		if behavior == "" {
			behavior = inferBehaviorFromEntries(entries)
		}
		return providerProbePreview{
			Format:     format,
			Behavior:   behavior,
			EntryCount: len(entries),
			Samples:    limitStringSlice(entries, 5),
		}, nil
	default:
		return providerProbePreview{}, fmt.Errorf("unsupported provider format %q", format)
	}
}

func limitStringSlice(in []string, max int) []string {
	if len(in) == 0 {
		return nil
	}
	if max <= 0 || len(in) <= max {
		out := make([]string, len(in))
		copy(out, in)
		return out
	}
	out := make([]string, max)
	copy(out, in[:max])
	return out
}

func inferBehaviorFromEntries(entries []string) string {
	if len(entries) == 0 {
		return "classical"
	}
	allDomain := true
	allIPCIDR := true
	for _, entry := range entries {
		if !isLikelyDomainEntry(entry) {
			allDomain = false
		}
		if !isLikelyIPCIDREntry(entry) {
			allIPCIDR = false
		}
		if !allDomain && !allIPCIDR {
			break
		}
	}
	switch {
	case allDomain:
		return "domain"
	case allIPCIDR:
		return "ipcidr"
	default:
		return "classical"
	}
}

func isLikelyDomainEntry(entry string) bool {
	_, _, err := normalizeDomainProviderEntry(entry)
	return err == nil
}

func isLikelyIPCIDREntry(entry string) bool {
	payload := strings.TrimSpace(entry)
	parts := splitRuleCSV(payload)
	if len(parts) >= 2 {
		switch strings.ToUpper(parts[0]) {
		case "IP-CIDR", "IP-CIDR6":
			payload = parts[1]
		}
	}
	_, err := netip.ParsePrefix(strings.TrimSpace(payload))
	return err == nil
}

type mrsPreviewMetadata struct {
	Behavior string
	Count    int
}

func parseMRSMetadata(raw []byte) (mrsPreviewMetadata, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		return mrsPreviewMetadata{}, err
	}
	defer decoder.Close()

	var magic [4]byte
	if _, err := io.ReadFull(decoder, magic[:]); err != nil {
		return mrsPreviewMetadata{}, fmt.Errorf("read mrs header: %w", err)
	}
	if magic != mrsMagicBytes {
		return mrsPreviewMetadata{}, fmt.Errorf("invalid mrs header")
	}

	var behavior [1]byte
	if _, err := io.ReadFull(decoder, behavior[:]); err != nil {
		return mrsPreviewMetadata{}, fmt.Errorf("read mrs behavior: %w", err)
	}
	behaviorName, err := mrsBehaviorName(behavior[0])
	if err != nil {
		return mrsPreviewMetadata{}, err
	}

	var count int64
	if err := binary.Read(decoder, binary.BigEndian, &count); err != nil {
		return mrsPreviewMetadata{}, fmt.Errorf("read mrs count: %w", err)
	}
	if count < 0 {
		return mrsPreviewMetadata{}, fmt.Errorf("invalid mrs count %d", count)
	}
	return mrsPreviewMetadata{
		Behavior: behaviorName,
		Count:    int(count),
	}, nil
}

type mrsDomainSet struct {
	leaves      []uint64
	labelBitmap []uint64
	labels      []byte
	zeroPrefix  []int
	onePos      []int
}

type mrsIPRange struct {
	from netip.Addr
	to   netip.Addr
}

func compileMRSProviderMatcher(ctx context.Context, provider clientRuleProvider, configDir string) (providerMatcher, error) {
	if provider.Type == "inline" {
		return nil, fmt.Errorf("mrs format does not support inline provider")
	}
	raw, err := loadProviderRaw(ctx, provider, configDir)
	if err != nil {
		return nil, err
	}
	return compileMRSProviderMatcherFromRaw(raw, provider.Behavior)
}

func compileMRSProviderMatcherFromRaw(raw []byte, expectedBehavior string) (providerMatcher, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	var magic [4]byte
	if _, err := io.ReadFull(decoder, magic[:]); err != nil {
		return nil, fmt.Errorf("read mrs header: %w", err)
	}
	if magic != mrsMagicBytes {
		return nil, fmt.Errorf("invalid mrs header")
	}

	var behavior [1]byte
	if _, err := io.ReadFull(decoder, behavior[:]); err != nil {
		return nil, fmt.Errorf("read mrs behavior: %w", err)
	}
	behaviorName, err := mrsBehaviorName(behavior[0])
	if err != nil {
		return nil, err
	}
	if expectedBehavior != "" && expectedBehavior != behaviorName {
		return nil, fmt.Errorf("mrs behavior mismatch: provider=%s mrs=%s", expectedBehavior, behaviorName)
	}

	var count int64
	if err := binary.Read(decoder, binary.BigEndian, &count); err != nil {
		return nil, fmt.Errorf("read mrs count: %w", err)
	}
	if count <= 0 {
		return nil, fmt.Errorf("invalid mrs count %d", count)
	}

	var extraLen int64
	if err := binary.Read(decoder, binary.BigEndian, &extraLen); err != nil {
		return nil, fmt.Errorf("read mrs extra length: %w", err)
	}
	if extraLen < 0 {
		return nil, fmt.Errorf("invalid mrs extra length %d", extraLen)
	}
	if extraLen > 0 {
		if _, err := io.CopyN(io.Discard, decoder, extraLen); err != nil {
			return nil, fmt.Errorf("read mrs extra: %w", err)
		}
	}

	switch behavior[0] {
	case mrsBehaviorDomain:
		set, err := readMRSDomainSet(decoder)
		if err != nil {
			return nil, err
		}
		return func(ctx routeMatchContext) bool {
			return ctx.host != "" && set.Has(ctx.host)
		}, nil
	case mrsBehaviorIPCIDR:
		ranges, err := readMRSIPRanges(decoder)
		if err != nil {
			return nil, err
		}
		return buildMRSIPMatcher(ranges), nil
	case mrsBehaviorClassical:
		return nil, fmt.Errorf("mrs classical behavior is not supported yet")
	default:
		return nil, fmt.Errorf("unsupported mrs behavior %d", behavior[0])
	}
}

func mrsBehaviorName(v byte) (string, error) {
	switch v {
	case mrsBehaviorDomain:
		return "domain", nil
	case mrsBehaviorIPCIDR:
		return "ipcidr", nil
	case mrsBehaviorClassical:
		return "classical", nil
	default:
		return "", fmt.Errorf("unknown mrs behavior %d", v)
	}
}

func readMRSDomainSet(r io.Reader) (*mrsDomainSet, error) {
	version, err := readMRSByte(r)
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("invalid mrs domain set version %d", version)
	}

	leaves, err := readMRSUint64Slice(r)
	if err != nil {
		return nil, fmt.Errorf("read mrs domain leaves: %w", err)
	}
	labelBitmap, err := readMRSUint64Slice(r)
	if err != nil {
		return nil, fmt.Errorf("read mrs domain bitmap: %w", err)
	}

	labelLen, err := readMRSInt64(r)
	if err != nil {
		return nil, fmt.Errorf("read mrs domain labels length: %w", err)
	}
	if labelLen < 1 {
		return nil, fmt.Errorf("invalid mrs domain labels length %d", labelLen)
	}
	labels := make([]byte, labelLen)
	if _, err := io.ReadFull(r, labels); err != nil {
		return nil, fmt.Errorf("read mrs domain labels: %w", err)
	}

	set := &mrsDomainSet{
		leaves:      leaves,
		labelBitmap: labelBitmap,
		labels:      labels,
	}
	set.init()
	return set, nil
}

func readMRSIPRanges(r io.Reader) ([]mrsIPRange, error) {
	version, err := readMRSByte(r)
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("invalid mrs ipcidr set version %d", version)
	}

	length, err := readMRSInt64(r)
	if err != nil {
		return nil, fmt.Errorf("read mrs ipcidr length: %w", err)
	}
	if length < 1 {
		return nil, fmt.Errorf("invalid mrs ipcidr length %d", length)
	}

	out := make([]mrsIPRange, 0, length)
	for i := int64(0); i < length; i++ {
		var from16 [16]byte
		if err := binary.Read(r, binary.BigEndian, &from16); err != nil {
			return nil, fmt.Errorf("read mrs ipcidr from[%d]: %w", i, err)
		}
		var to16 [16]byte
		if err := binary.Read(r, binary.BigEndian, &to16); err != nil {
			return nil, fmt.Errorf("read mrs ipcidr to[%d]: %w", i, err)
		}
		from := netip.AddrFrom16(from16).Unmap()
		to := netip.AddrFrom16(to16).Unmap()
		if !from.IsValid() || !to.IsValid() || from.Compare(to) > 0 {
			return nil, fmt.Errorf("invalid mrs ipcidr range[%d]", i)
		}
		out = append(out, mrsIPRange{from: from, to: to})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].from.Compare(out[j].from) < 0
	})
	return out, nil
}

func buildMRSIPMatcher(ranges []mrsIPRange) providerMatcher {
	return func(ctx routeMatchContext) bool {
		if !ctx.ip.IsValid() {
			return false
		}
		ip := ctx.ip.Unmap()
		idx := sort.Search(len(ranges), func(i int) bool {
			return ranges[i].from.Compare(ip) > 0
		})
		if idx == 0 {
			return false
		}
		candidate := ranges[idx-1]
		return ip.Compare(candidate.to) <= 0
	}
}

func readMRSByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func readMRSInt64(r io.Reader) (int64, error) {
	var value int64
	if err := binary.Read(r, binary.BigEndian, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func readMRSUint64Slice(r io.Reader) ([]uint64, error) {
	length, err := readMRSInt64(r)
	if err != nil {
		return nil, err
	}
	if length < 1 {
		return nil, fmt.Errorf("invalid slice length %d", length)
	}
	out := make([]uint64, length)
	for i := int64(0); i < length; i++ {
		if err := binary.Read(r, binary.BigEndian, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *mrsDomainSet) init() {
	if len(s.labelBitmap) == 0 {
		return
	}
	totalBits := len(s.labelBitmap) * 64
	s.zeroPrefix = make([]int, totalBits+1)
	s.onePos = make([]int, 0, len(s.labels)+1)
	for i := 0; i < totalBits; i++ {
		s.zeroPrefix[i+1] = s.zeroPrefix[i]
		if mrsGetBit(s.labelBitmap, i) == 0 {
			s.zeroPrefix[i+1]++
			continue
		}
		s.onePos = append(s.onePos, i)
	}
}

func (s *mrsDomainSet) countZeros(i int) int {
	if i <= 0 {
		return 0
	}
	if i >= len(s.zeroPrefix) {
		return s.zeroPrefix[len(s.zeroPrefix)-1]
	}
	return s.zeroPrefix[i]
}

func (s *mrsDomainSet) selectIthOne(i int) int {
	if i < 0 || i >= len(s.onePos) {
		return -1
	}
	return s.onePos[i]
}

func (s *mrsDomainSet) Has(key string) bool {
	if s == nil || len(s.labels) == 0 {
		return false
	}
	key = strings.ToLower(reverseRunes(key))
	nodeID, bmIdx := 0, 0
	type wildcardCursor struct {
		bmIdx int
		index int
	}
	stack := make([]wildcardCursor, 0)
	keyBytes := []byte(key)
	maxBit := len(s.labelBitmap) * 64

	for i := 0; i < len(keyBytes); i++ {
	restart:
		c := keyBytes[i]
		for ; ; bmIdx++ {
			if bmIdx < 0 || bmIdx >= maxBit {
				return false
			}
			if mrsGetBit(s.labelBitmap, bmIdx) != 0 {
				if len(stack) > 0 {
					cursor := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					nextNodeID := s.countZeros(cursor.bmIdx + 1)
					nextBmIdx := s.selectIthOne(nextNodeID-1) + 1
					if nextBmIdx < 0 {
						return false
					}
					j := cursor.index
					for ; j < len(keyBytes) && keyBytes[j] != '.'; j++ {
					}
					if j == len(keyBytes) {
						if mrsGetBit(s.leaves, nextNodeID) != 0 {
							return true
						}
						goto restart
					}
					for ; nextBmIdx-nextNodeID < len(s.labels); nextBmIdx++ {
						if s.labels[nextBmIdx-nextNodeID] == '.' {
							bmIdx = nextBmIdx
							nodeID = nextNodeID
							i = j
							goto restart
						}
					}
				}
				return false
			}
			labelIndex := bmIdx - nodeID
			if labelIndex < 0 || labelIndex >= len(s.labels) {
				return false
			}
			switch s.labels[labelIndex] {
			case '+':
				return true
			case '*':
				stack = append(stack, wildcardCursor{bmIdx: bmIdx, index: i})
			case c:
				goto matched
			}
		}
	matched:
		nodeID = s.countZeros(bmIdx + 1)
		next := s.selectIthOne(nodeID - 1)
		if next < 0 {
			return false
		}
		bmIdx = next + 1
	}

	return mrsGetBit(s.leaves, nodeID) != 0
}

func mrsGetBit(bitmap []uint64, i int) uint64 {
	if i < 0 {
		return 0
	}
	word := i >> 6
	if word < 0 || word >= len(bitmap) {
		return 0
	}
	return bitmap[word] & (1 << uint(i&63))
}

func reverseRunes(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func parseYAMLPayload(content string) ([]string, error) {
	lines := strings.Split(content, "\n")
	items := make([]string, 0)

	payloadIndent := -1
	inPayload := false

	for _, raw := range lines {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))

		if strings.HasPrefix(trimmed, "payload:") {
			inPayload = true
			payloadIndent = indent
			continue
		}
		if inPayload {
			if indent <= payloadIndent && !strings.HasPrefix(trimmed, "- ") {
				inPayload = false
				continue
			}
			if strings.HasPrefix(trimmed, "- ") {
				item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				item = strings.Trim(item, `"'`)
				if item != "" {
					items = append(items, item)
				}
			}
			continue
		}
		// Allow bare YAML list files too.
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = strings.Trim(item, `"'`)
			if item != "" {
				items = append(items, item)
			}
		}
	}

	items = normalizeRuleLines(items)
	if len(items) == 0 {
		return nil, fmt.Errorf("no payload entries found")
	}
	return items, nil
}

type surgeModuleParsed struct {
	rules                 []string
	mitmHosts             []string
	urlRewriteRejectRules []string
}

func parseSurgeModulePayload(content string) ([]string, error) {
	parsed, err := parseSurgeModule(content)
	if err != nil {
		return nil, err
	}
	return parsed.rules, nil
}

func parseSurgeModule(content string) (surgeModuleParsed, error) {
	lines := strings.Split(content, "\n")
	items := make([]string, 0)
	mitmHosts := make([]string, 0)
	urlRewriteRejectRules := make([]string, 0)
	section := ""

	for _, raw := range lines {
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			continue
		}
		line = stripRuleComment(line)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch section {
		case "rule":
			ruleType := surgeRuleType(line)
			if !isSupportedSurgeRuleType(ruleType) {
				continue
			}
			items = append(items, line)
		case "url rewrite":
			if pattern, ok := extractSurgeURLRewriteRejectPattern(line); ok {
				urlRewriteRejectRules = append(urlRewriteRejectRules, pattern)
			}
			rule, ok := parseSurgeURLRewriteRejectRule(line)
			if !ok {
				continue
			}
			items = append(items, rule)
		case "mitm":
			mitmHosts = append(mitmHosts, parseSurgeMITMHosts(line)...)
		}
	}

	items = normalizeRuleLines(items)
	if len(items) == 0 && len(mitmHosts) == 0 && len(urlRewriteRejectRules) == 0 {
		return surgeModuleParsed{}, fmt.Errorf("no supported rules found in sgmodule")
	}
	return surgeModuleParsed{
		rules:                 items,
		mitmHosts:             dedupAndSortStrings(mitmHosts),
		urlRewriteRejectRules: dedupAndSortStrings(urlRewriteRejectRules),
	}, nil
}

func parseSurgeURLRewriteRejectRule(line string) (string, bool) {
	parts := strings.SplitN(line, " - ", 2)
	if len(parts) != 2 {
		return "", false
	}
	action := strings.ToLower(strings.TrimSpace(parts[1]))
	if action != "reject" {
		return "", false
	}
	pattern := strings.TrimSpace(parts[0])
	if pattern == "" {
		return "", false
	}
	host, ok := extractHostFromSurgeURLRegex(pattern)
	if !ok {
		return "", false
	}
	return "DOMAIN," + host + ",REJECT", true
}

func extractSurgeURLRewriteRejectPattern(line string) (string, bool) {
	parts := strings.SplitN(line, " - ", 2)
	if len(parts) != 2 {
		return "", false
	}
	action := strings.ToLower(strings.TrimSpace(parts[1]))
	if action != "reject" {
		return "", false
	}
	pattern := strings.TrimSpace(parts[0])
	if pattern == "" {
		return "", false
	}
	return pattern, true
}

func extractHostFromSurgeURLRegex(raw string) (string, bool) {
	p := strings.TrimSpace(strings.Trim(raw, `"'`))
	p = strings.TrimPrefix(p, "^")
	p = strings.ReplaceAll(p, `\/`, "/")
	p = strings.ReplaceAll(p, `\.`, ".")
	p = strings.ReplaceAll(p, `\\`, `\`)
	p = strings.ReplaceAll(p, `\?`, "?")
	p = strings.ReplaceAll(p, `\+`, "+")
	p = strings.ReplaceAll(p, `\*`, "*")
	if strings.HasPrefix(p, "https://") {
		p = strings.TrimPrefix(p, "https://")
	} else if strings.HasPrefix(p, "http://") {
		p = strings.TrimPrefix(p, "http://")
	} else {
		return "", false
	}
	if idx := strings.IndexByte(p, '/'); idx >= 0 {
		p = p[:idx]
	}
	if idx := strings.IndexByte(p, ':'); idx >= 0 {
		p = p[:idx]
	}
	host := strings.ToLower(strings.TrimSpace(p))
	if host == "" {
		return "", false
	}
	if strings.ContainsAny(host, `[](){}|^$*+?`) {
		return "", false
	}
	for _, ch := range host {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
			continue
		}
		return "", false
	}
	return host, true
}

func compileSurgeURLRegexPattern(raw string) (*regexp.Regexp, error) {
	p := strings.TrimSpace(strings.Trim(raw, `"'`))
	p = strings.ReplaceAll(p, `\/`, "/")
	return regexp.Compile(p)
}

func parseSurgeMITMHosts(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	key, value, found := strings.Cut(line, "=")
	if !found {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(key)) != "hostname" {
		return nil
	}
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "%APPEND%", "")
	value = strings.ReplaceAll(value, "%INSERT%", "")
	value = strings.ReplaceAll(value, "%REMOVE%", "")
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		host := normalizeMITMHostPattern(part)
		if host == "" {
			continue
		}
		out = append(out, host)
	}
	return out
}

func normalizeMITMHostPattern(raw string) string {
	host := strings.ToLower(strings.TrimSpace(strings.Trim(raw, `"'`)))
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, ".") {
		host = "*" + host
	}
	if strings.HasPrefix(host, "*.") {
		base := strings.TrimPrefix(host, "*.")
		if base == "" {
			return ""
		}
		for _, ch := range base {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
				continue
			}
			return ""
		}
		return "*." + base
	}
	for _, ch := range host {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
			continue
		}
		return ""
	}
	return host
}

func dedupAndSortStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		set[item] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func surgeRuleType(line string) string {
	if idx := strings.IndexByte(line, ','); idx > 0 {
		return strings.ToUpper(strings.TrimSpace(line[:idx]))
	}
	return strings.ToUpper(strings.TrimSpace(line))
}

func isSupportedSurgeRuleType(ruleType string) bool {
	switch ruleType {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "IP-CIDR", "IP-CIDR6", "GEOIP", "DST-PORT", "MATCH", "AND", "OR", "NOT":
		return true
	default:
		return false
	}
}

func compileProviderMatcher(behavior string, entries []string) (providerMatcher, error) {
	switch behavior {
	case "domain":
		return compileDomainProviderMatcher(entries)
	case "ipcidr":
		return compileIPCIDRProviderMatcher(entries)
	case "classical":
		matchers := make([]func(routeMatchContext) bool, 0, len(entries))
		for _, entry := range entries {
			rule, err := compileClassicalRule(entry, nil, routeAction{kind: routeActionProxy}, false)
			if err != nil {
				logrus.Warnf("[Client] skip invalid classical provider entry %q: %v", entry, err)
				continue
			}
			matchers = append(matchers, rule.match)
		}
		if len(matchers) == 0 {
			return nil, fmt.Errorf("provider has no valid classical rules")
		}
		return func(ctx routeMatchContext) bool {
			for _, m := range matchers {
				if m(ctx) {
					return true
				}
			}
			return false
		}, nil
	default:
		return nil, fmt.Errorf("unsupported behavior %q", behavior)
	}
}

func compileClassicalProviderActionRules(entries []string) []compiledRouteRule {
	if len(entries) == 0 {
		return nil
	}
	rules := make([]compiledRouteRule, 0, len(entries))
	for _, entry := range entries {
		// Provider-side rules are expected to carry explicit actions when used directly.
		rule, err := compileClassicalRule(entry, nil, routeAction{kind: routeActionInvalid}, false)
		if err != nil {
			logrus.Warnf("[Client] skip classical provider action rule %q: %v", entry, err)
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

func compileDomainProviderMatcher(entries []string) (providerMatcher, error) {
	exacts := make(map[string]struct{})
	suffixes := make([]string, 0)
	keywords := make([]string, 0)
	regexes := make([]*regexp.Regexp, 0)

	for _, entry := range entries {
		tp, payload, err := normalizeDomainProviderEntry(entry)
		if err != nil {
			logrus.Warnf("[Client] skip invalid domain provider entry %q: %v", entry, err)
			continue
		}
		switch tp {
		case "domain":
			exacts[payload] = struct{}{}
		case "suffix":
			suffixes = append(suffixes, payload)
		case "keyword":
			keywords = append(keywords, payload)
		case "regex":
			re, err := regexp.Compile(payload)
			if err != nil {
				logrus.Warnf("[Client] skip invalid domain regex %q: %v", entry, err)
				continue
			}
			regexes = append(regexes, re)
		}
	}
	if len(exacts) == 0 && len(suffixes) == 0 && len(keywords) == 0 && len(regexes) == 0 {
		return nil, fmt.Errorf("provider has no valid domain entries")
	}

	return func(ctx routeMatchContext) bool {
		host := ctx.host
		if host == "" {
			return false
		}
		if _, ok := exacts[host]; ok {
			return true
		}
		for _, suffix := range suffixes {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return true
			}
		}
		for _, keyword := range keywords {
			if strings.Contains(host, keyword) {
				return true
			}
		}
		for _, re := range regexes {
			if re.MatchString(host) {
				return true
			}
		}
		return false
	}, nil
}

func normalizeDomainProviderEntry(raw string) (string, string, error) {
	line := stripRuleComment(raw)
	if line == "" {
		return "", "", fmt.Errorf("empty entry")
	}
	parts := splitRuleCSV(line)
	if len(parts) >= 2 {
		switch strings.ToUpper(parts[0]) {
		case "DOMAIN":
			return "domain", normalizeHost(parts[1]), nil
		case "DOMAIN-SUFFIX":
			return "suffix", normalizeHost(strings.TrimPrefix(strings.TrimPrefix(parts[1], "."), "+.")), nil
		case "DOMAIN-KEYWORD":
			return "keyword", strings.ToLower(strings.TrimSpace(parts[1])), nil
		case "DOMAIN-REGEX":
			return "regex", strings.TrimSpace(parts[1]), nil
		}
	}

	line = strings.TrimSpace(strings.Trim(line, `"'`))
	if line == "" {
		return "", "", fmt.Errorf("empty entry")
	}
	if strings.HasPrefix(line, "+.") || strings.HasPrefix(line, ".") {
		return "suffix", normalizeHost(strings.TrimPrefix(strings.TrimPrefix(line, "+."), ".")), nil
	}
	if strings.ContainsAny(line, "*?") {
		rePattern := wildcardDomainToRegex(line)
		return "regex", rePattern, nil
	}
	return "domain", normalizeHost(line), nil
}

func wildcardDomainToRegex(pattern string) string {
	p := regexp.QuoteMeta(strings.ToLower(strings.TrimSpace(pattern)))
	p = strings.ReplaceAll(p, `\*`, ".*")
	p = strings.ReplaceAll(p, `\?`, ".")
	return "^" + p + "$"
}

func compileIPCIDRProviderMatcher(entries []string) (providerMatcher, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		payload := strings.TrimSpace(entry)
		parts := splitRuleCSV(payload)
		if len(parts) >= 2 {
			switch strings.ToUpper(parts[0]) {
			case "IP-CIDR", "IP-CIDR6":
				payload = parts[1]
			}
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(payload))
		if err != nil {
			logrus.Warnf("[Client] skip invalid ipcidr provider entry %q: %v", entry, err)
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("provider has no valid ipcidr entries")
	}
	return func(ctx routeMatchContext) bool {
		if !ctx.ip.IsValid() {
			return false
		}
		ip := ctx.ip.Unmap()
		for _, prefix := range prefixes {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}, nil
}

func findProviderByName(name string, providers map[string]providerDefinition) (providerDefinition, string, bool) {
	if len(providers) == 0 {
		return providerDefinition{}, "", false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return providerDefinition{}, "", false
	}
	if provider, ok := providers[name]; ok {
		return provider, name, true
	}
	lowerName := strings.ToLower(name)
	matches := make([]string, 0, 1)
	for providerName := range providers {
		if strings.ToLower(strings.TrimSpace(providerName)) == lowerName {
			matches = append(matches, providerName)
		}
	}
	if len(matches) == 0 {
		return providerDefinition{}, "", false
	}
	sort.Strings(matches)
	matchedName := matches[0]
	return providers[matchedName], matchedName, true
}

func buildGeoIPProviderNameCandidates(country string) []string {
	country = strings.ToLower(strings.TrimSpace(country))
	if country == "" {
		return nil
	}

	out := make([]string, 0, 10)
	seen := make(map[string]struct{}, 10)
	add := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	add(country)
	if strings.HasPrefix(country, "geoip-") {
		add(strings.TrimPrefix(country, "geoip-"))
	}
	if strings.HasPrefix(country, "geoip_") {
		add(strings.TrimPrefix(country, "geoip_"))
	}
	add("geoip-" + country)
	add("geoip_" + country)
	add(country + "-geoip")
	add(country + "_geoip")
	add(country + "-ip")
	add(country + "_ip")
	add("ip-" + country)
	add("ip_" + country)
	add("geoip:" + country)
	return out
}

func resolveGeoIPProviderMatcher(country string, providers map[string]providerDefinition) (providerMatcher, string, bool) {
	for _, candidate := range buildGeoIPProviderNameCandidates(country) {
		if provider, matchedName, ok := findProviderByName(candidate, providers); ok {
			return provider.matcher, matchedName, true
		}
	}
	return nil, "", false
}

func compileClassicalRule(line string, providers map[string]providerDefinition, fallbackAction routeAction, requireAction bool) (compiledRouteRule, error) {
	parts := splitRuleCSV(line)
	if len(parts) == 0 {
		return compiledRouteRule{}, fmt.Errorf("empty rule")
	}
	ruleType := strings.ToUpper(parts[0])

	parseActionAt := func(index int) (routeAction, error) {
		if len(parts) > index && strings.TrimSpace(parts[index]) != "" {
			return parseRouteAction(parts[index])
		}
		if requireAction || fallbackAction.kind == routeActionInvalid {
			return routeAction{}, fmt.Errorf("missing action")
		}
		return fallbackAction, nil
	}

	rule := compiledRouteRule{raw: strings.TrimSpace(line)}
	switch ruleType {
	case "DOMAIN":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("DOMAIN rule missing payload")
		}
		host := normalizeHost(parts[1])
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(ctx routeMatchContext) bool {
			return ctx.host != "" && ctx.host == host
		}
	case "DOMAIN-SUFFIX":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("DOMAIN-SUFFIX rule missing payload")
		}
		suffix := normalizeHost(strings.TrimPrefix(strings.TrimPrefix(parts[1], "."), "+."))
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(ctx routeMatchContext) bool {
			return ctx.host != "" && (ctx.host == suffix || strings.HasSuffix(ctx.host, "."+suffix))
		}
	case "DOMAIN-KEYWORD":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("DOMAIN-KEYWORD rule missing payload")
		}
		keyword := strings.ToLower(strings.TrimSpace(parts[1]))
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(ctx routeMatchContext) bool {
			return ctx.host != "" && strings.Contains(ctx.host, keyword)
		}
	case "DOMAIN-REGEX":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("DOMAIN-REGEX rule missing payload")
		}
		re, err := regexp.Compile(strings.TrimSpace(parts[1]))
		if err != nil {
			return compiledRouteRule{}, fmt.Errorf("invalid DOMAIN-REGEX: %w", err)
		}
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(ctx routeMatchContext) bool {
			return ctx.host != "" && re.MatchString(ctx.host)
		}
	case "IP-CIDR", "IP-CIDR6":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("%s rule missing payload", ruleType)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(parts[1]))
		if err != nil {
			return compiledRouteRule{}, err
		}
		prefix = prefix.Masked()
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(ctx routeMatchContext) bool {
			return ctx.ip.IsValid() && prefix.Contains(ctx.ip.Unmap())
		}
	case "GEOIP":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("GEOIP rule missing country code")
		}
		if providers == nil {
			return compiledRouteRule{}, fmt.Errorf("GEOIP is not allowed in provider classical rules")
		}
		country := strings.TrimSpace(parts[1])
		if country == "" {
			return compiledRouteRule{}, fmt.Errorf("GEOIP rule missing country code")
		}
		provider, _, ok := resolveGeoIPProviderMatcher(country, providers)
		if !ok {
			candidates := buildGeoIPProviderNameCandidates(country)
			return compiledRouteRule{}, fmt.Errorf("geoip provider not found for %q (tried: %s)", country, strings.Join(candidates, ", "))
		}
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(ctx routeMatchContext) bool {
			return provider(ctx)
		}
	case "DST-PORT":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("DST-PORT rule missing payload")
		}
		from, to, err := parsePortRange(parts[1])
		if err != nil {
			return compiledRouteRule{}, err
		}
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(ctx routeMatchContext) bool {
			if ctx.port == 0 {
				return false
			}
			p := int(ctx.port)
			return p >= from && p <= to
		}
	case "RULE-SET":
		if len(parts) < 2 {
			return compiledRouteRule{}, fmt.Errorf("RULE-SET rule missing provider name")
		}
		if providers == nil {
			return compiledRouteRule{}, fmt.Errorf("RULE-SET is not allowed in provider classical rules")
		}
		providerName := strings.TrimSpace(parts[1])
		provider, _, ok := findProviderByName(providerName, providers)
		if !ok {
			return compiledRouteRule{}, fmt.Errorf("rule provider not found: %s", providerName)
		}
		if provider.matcher == nil {
			return compiledRouteRule{}, fmt.Errorf("rule provider is not ready: %s", providerName)
		}
		if len(parts) > 2 && strings.TrimSpace(parts[2]) != "" {
			action, err := parseActionAt(2)
			if err != nil {
				return compiledRouteRule{}, err
			}
			rule.action = action
			rule.match = func(ctx routeMatchContext) bool {
				return provider.matcher(ctx)
			}
			break
		}
		if len(provider.actionRules) == 0 {
			return compiledRouteRule{}, fmt.Errorf("RULE-SET rule missing action and provider has no action rules: %s", providerName)
		}
		providerActionRules := append([]compiledRouteRule(nil), provider.actionRules...)
		rule.action = routeAction{kind: routeActionInvalid}
		rule.match = func(ctx routeMatchContext) bool {
			return provider.matcher(ctx)
		}
		rule.resolveAction = func(ctx routeMatchContext) (routeAction, bool) {
			for _, providerRule := range providerActionRules {
				if providerRule.match != nil && providerRule.match(ctx) {
					return providerRule.action, true
				}
			}
			return routeAction{}, false
		}
	case "MATCH":
		action, err := parseActionAt(1)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = func(routeMatchContext) bool { return true }
	case "AND", "OR", "NOT":
		matcher, err := compileLogicalMatcher(ruleType, parts, providers)
		if err != nil {
			return compiledRouteRule{}, err
		}
		action, err := parseActionAt(2)
		if err != nil {
			return compiledRouteRule{}, err
		}
		rule.action = action
		rule.match = matcher
	default:
		return compiledRouteRule{}, fmt.Errorf("unsupported rule type %q", ruleType)
	}
	return rule, nil
}

func splitRuleCSV(line string) []string {
	line = stripRuleComment(line)
	if line == "" {
		return nil
	}
	parts := make([]string, 0, 8)
	var token strings.Builder
	depth := 0
	var quote rune
	for _, ch := range line {
		switch {
		case quote != 0:
			token.WriteRune(ch)
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
			token.WriteRune(ch)
		case ch == '(':
			depth++
			token.WriteRune(ch)
		case ch == ')':
			if depth > 0 {
				depth--
			}
			token.WriteRune(ch)
		case ch == ',' && depth == 0:
			part := strings.TrimSpace(token.String())
			if part != "" {
				parts = append(parts, part)
			}
			token.Reset()
		default:
			token.WriteRune(ch)
		}
	}
	part := strings.TrimSpace(token.String())
	if part != "" {
		parts = append(parts, part)
	}
	return parts
}

func compileLogicalMatcher(ruleType string, parts []string, providers map[string]providerDefinition) (func(routeMatchContext) bool, error) {
	if len(parts) < 2 {
		return nil, fmt.Errorf("%s rule missing expression", ruleType)
	}

	if ruleType == "NOT" {
		child := unwrapOuterParentheses(strings.TrimSpace(parts[1]))
		if child == "" {
			return nil, fmt.Errorf("NOT rule has empty child expression")
		}
		rule, err := compileClassicalRule(child, providers, routeAction{kind: routeActionProxy}, false)
		if err != nil {
			return nil, fmt.Errorf("NOT child %q: %w", child, err)
		}
		return func(ctx routeMatchContext) bool {
			return !rule.match(ctx)
		}, nil
	}

	children := parseLogicalChildren(parts[1])
	if len(children) == 0 {
		return nil, fmt.Errorf("%s rule has no valid child expression", ruleType)
	}
	matchers := make([]func(routeMatchContext) bool, 0, len(children))
	for _, child := range children {
		rule, err := compileClassicalRule(child, providers, routeAction{kind: routeActionProxy}, false)
		if err != nil {
			return nil, fmt.Errorf("%s child %q: %w", ruleType, child, err)
		}
		matchers = append(matchers, rule.match)
	}

	switch ruleType {
	case "AND":
		return func(ctx routeMatchContext) bool {
			for _, m := range matchers {
				if !m(ctx) {
					return false
				}
			}
			return true
		}, nil
	case "OR":
		return func(ctx routeMatchContext) bool {
			for _, m := range matchers {
				if m(ctx) {
					return true
				}
			}
			return false
		}, nil
	default:
		return nil, fmt.Errorf("unsupported logical rule type %q", ruleType)
	}
}

func parseLogicalChildren(raw string) []string {
	raw = unwrapOuterParentheses(raw)
	if raw == "" {
		return nil
	}
	parts := splitRuleCSV(raw)
	if len(parts) == 0 {
		return nil
	}
	if looksLikeSingleRuleExpression(parts) {
		return []string{raw}
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := unwrapOuterParentheses(strings.TrimSpace(part))
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func looksLikeSingleRuleExpression(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
	if ruleType == "" {
		return false
	}
	return isSupportedSurgeRuleType(ruleType)
}

func unwrapOuterParentheses(raw string) string {
	s := strings.TrimSpace(raw)
	for hasWrappingParentheses(s) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func hasWrappingParentheses(s string) bool {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	depth := 0
	var quote rune
	for i, ch := range s {
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '(':
			depth++
		case ch == ')':
			depth--
			if depth == 0 && i != len(s)-1 {
				return false
			}
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func parsePortRange(raw string) (int, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, 0, fmt.Errorf("empty port")
	}
	if !strings.Contains(raw, "-") {
		p, err := strconv.Atoi(raw)
		if err != nil || p <= 0 || p > 65535 {
			return 0, 0, fmt.Errorf("invalid port %q", raw)
		}
		return p, p, nil
	}
	parts := strings.SplitN(raw, "-", 2)
	from, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || from <= 0 || from > 65535 {
		return 0, 0, fmt.Errorf("invalid start port %q", raw)
	}
	to, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || to <= 0 || to > 65535 || to < from {
		return 0, 0, fmt.Errorf("invalid end port %q", raw)
	}
	return from, to, nil
}

func parseRouteAction(raw string) (routeAction, error) {
	action := strings.TrimSpace(raw)
	if action == "" {
		return routeAction{}, fmt.Errorf("empty action")
	}
	if strings.HasPrefix(strings.ToUpper(action), "GROUP:") {
		group := strings.TrimSpace(action[len("GROUP:"):])
		if group == "" {
			return routeAction{}, fmt.Errorf("group action missing group name")
		}
		return routeAction{kind: routeActionGroup, group: group}, nil
	}
	switch strings.ToUpper(action) {
	case "REJECT", "REJECT-DROP":
		return routeAction{kind: routeActionReject}, nil
	case "DIRECT":
		return routeAction{kind: routeActionDirect}, nil
	case "PROXY":
		return routeAction{kind: routeActionProxy}, nil
	default:
		return routeAction{kind: routeActionNode, node: action}, nil
	}
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func appendUniqueHosts(base []string, extra ...string) []string {
	out := append([]string(nil), base...)
	seen := make(map[string]struct{}, len(out)+len(extra))
	for _, item := range out {
		host := normalizeHost(item)
		if host == "" {
			continue
		}
		seen[host] = struct{}{}
	}
	for _, item := range extra {
		host := normalizeHost(item)
		if host == "" {
			continue
		}
		if net.ParseIP(host) != nil {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func sniffConnHosts(conn net.Conn) ([]string, net.Conn) {
	if conn == nil {
		return nil, conn
	}
	const (
		sniffBytes   = 4096
		sniffTimeout = 180 * time.Millisecond
	)
	buffer := make([]byte, sniffBytes)
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	n, err := conn.Read(buffer)
	_ = conn.SetReadDeadline(time.Time{})
	if n <= 0 {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, conn
		}
		return nil, conn
	}
	firstPacket := append([]byte(nil), buffer[:n]...)
	hints := appendUniqueHosts(nil, parseTLSClientHelloSNI(firstPacket)...)
	hints = appendUniqueHosts(hints, parseHTTPHost(firstPacket)...)
	return hints, &prefixedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(firstPacket), conn),
	}
}

func parseHTTPHost(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	chunk := data
	if idx := bytes.Index(chunk, []byte("\r\n\r\n")); idx >= 0 {
		chunk = chunk[:idx+4]
	}
	text := string(chunk)
	lineEnd := strings.Index(text, "\r\n")
	if lineEnd <= 0 {
		return nil
	}
	requestLine := strings.TrimSpace(text[:lineEnd])
	if requestLine == "" {
		return nil
	}
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return nil
	}
	out := make([]string, 0, 2)
	method := strings.ToUpper(parts[0])
	if method == "CONNECT" {
		if host := parseHostOnly(parts[1]); host != "" {
			out = append(out, host)
		}
	}
	headers := strings.Split(text[lineEnd+2:], "\r\n")
	for _, line := range headers {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(key), "host") {
			continue
		}
		if host := parseHostOnly(value); host != "" {
			out = append(out, host)
		}
		break
	}
	return appendUniqueHosts(nil, out...)
}

func parseHostOnly(raw string) string {
	host := strings.TrimSpace(strings.Trim(raw, "'\""))
	if host == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(host), "http://") || strings.HasPrefix(strings.ToLower(host), "https://") {
		if idx := strings.Index(host, "://"); idx >= 0 {
			host = host[idx+3:]
		}
		if idx := strings.Index(host, "/"); idx >= 0 {
			host = host[:idx]
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if idx := strings.Index(host, "]"); idx > 1 {
			host = host[1:idx]
		}
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.Count(host, ":") == 1 {
		if h, _, found := strings.Cut(host, ":"); found {
			host = h
		}
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return normalizeHost(host)
}

func parseTLSClientHelloSNI(data []byte) []string {
	if len(data) < 5 {
		return nil
	}
	if data[0] != 0x16 {
		return nil
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen <= 0 {
		return nil
	}
	if recordLen > len(data)-5 {
		recordLen = len(data) - 5
	}
	if recordLen < 4 {
		return nil
	}
	record := data[5 : 5+recordLen]
	if record[0] != 0x01 {
		return nil
	}
	handshakeLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if handshakeLen <= 0 {
		return nil
	}
	if handshakeLen > len(record)-4 {
		handshakeLen = len(record) - 4
	}
	body := record[4 : 4+handshakeLen]
	if len(body) < 34 {
		return nil
	}
	offset := 0
	offset += 2  // version
	offset += 32 // random
	if offset >= len(body) {
		return nil
	}
	sessionIDLen := int(body[offset])
	offset++
	if offset+sessionIDLen > len(body) {
		return nil
	}
	offset += sessionIDLen
	if offset+2 > len(body) {
		return nil
	}
	cipherSuiteLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+cipherSuiteLen > len(body) {
		return nil
	}
	offset += cipherSuiteLen
	if offset >= len(body) {
		return nil
	}
	compressLen := int(body[offset])
	offset++
	if offset+compressLen > len(body) {
		return nil
	}
	offset += compressLen
	if offset+2 > len(body) {
		return nil
	}
	extensionLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extensionLen > len(body) {
		extensionLen = len(body) - offset
	}
	extensions := body[offset : offset+extensionLen]

	out := make([]string, 0, 1)
	for i := 0; i+4 <= len(extensions); {
		extType := binary.BigEndian.Uint16(extensions[i : i+2])
		extLen := int(binary.BigEndian.Uint16(extensions[i+2 : i+4]))
		i += 4
		if i+extLen > len(extensions) {
			break
		}
		if extType != 0 {
			i += extLen
			continue
		}
		serverNameData := extensions[i : i+extLen]
		if len(serverNameData) < 2 {
			break
		}
		nameListLen := int(binary.BigEndian.Uint16(serverNameData[:2]))
		if nameListLen > len(serverNameData)-2 {
			nameListLen = len(serverNameData) - 2
		}
		j := 2
		limit := 2 + nameListLen
		for j+3 <= limit && j+3 <= len(serverNameData) {
			nameType := serverNameData[j]
			nameLen := int(binary.BigEndian.Uint16(serverNameData[j+1 : j+3]))
			j += 3
			if j+nameLen > limit || j+nameLen > len(serverNameData) {
				break
			}
			if nameType == 0 {
				host := normalizeHost(string(serverNameData[j : j+nameLen]))
				if host != "" && net.ParseIP(host) == nil {
					out = append(out, host)
				}
			}
			j += nameLen
		}
		break
	}
	return appendUniqueHosts(nil, out...)
}

func decideRouting(engine *routingEngine, destination M.Socksaddr, defaultNode string) routeDecision {
	return decideRoutingWithDomainHintsAndIPHints(engine, destination, defaultNode, nil, nil)
}

func resolveRouteAction(action routeAction, groupEgress map[string]string, defaultNode string) routeAction {
	switch action.kind {
	case routeActionProxy:
		return routeAction{kind: routeActionNode, node: defaultNode}
	case routeActionGroup:
		if node := resolveGroupEgressNode(action.group, groupEgress); node != "" {
			return routeAction{kind: routeActionNode, node: node}
		}
		return routeAction{kind: routeActionNode, node: defaultNode}
	default:
		return action
	}
}

func resolveGroupEgressNode(group string, groupEgress map[string]string) string {
	group = strings.TrimSpace(group)
	if group == "" || len(groupEgress) == 0 {
		return ""
	}
	// Fast path for exact key.
	if node := strings.TrimSpace(groupEgress[group]); node != "" {
		return node
	}
	// Fallback to case-insensitive lookup so GROUP:HK can match map key "hk".
	for key, node := range groupEgress {
		if strings.EqualFold(strings.TrimSpace(key), group) {
			return strings.TrimSpace(node)
		}
	}
	return ""
}

func decideRoutingWithDomainHints(engine *routingEngine, destination M.Socksaddr, defaultNode string, hintedHosts []string) routeDecision {
	return decideRoutingWithDomainHintsAndIPHints(engine, destination, defaultNode, hintedHosts, nil)
}

func decideRoutingWithDomainHintsAndIPHints(
	engine *routingEngine,
	destination M.Socksaddr,
	defaultNode string,
	hintedHosts []string,
	hintedIPs []netip.Addr,
) routeDecision {
	decision := routeDecision{
		action:      routeAction{kind: routeActionNode, node: defaultNode},
		matchedRule: "DEFAULT",
	}
	if engine == nil || !engine.enabled {
		return decision
	}
	decision.action = resolveRouteAction(engine.defaultAction, engine.groupEgress, defaultNode)

	ctx := routeMatchContext{
		destination: destination,
		port:        destination.Port,
	}
	if destination.IsFqdn() {
		ctx.host = normalizeHost(destination.Fqdn)
	}
	if destination.IsIP() {
		ctx.ip = destination.Addr.Unmap()
	}

	hostCandidates := make([]string, 0, 4)
	addHostCandidate := func(raw string) {
		host := normalizeHost(raw)
		if host == "" {
			return
		}
		for _, item := range hostCandidates {
			if item == host {
				return
			}
		}
		hostCandidates = append(hostCandidates, host)
	}
	addHostCandidate(ctx.host)
	if ctx.host == "" {
		for _, host := range hintedHosts {
			addHostCandidate(host)
		}
	}
	ipCandidates := make([]netip.Addr, 0, len(hintedIPs)+1)
	ipSeen := make(map[string]struct{}, len(hintedIPs)+1)
	addIPCandidate := func(addr netip.Addr) {
		if !addr.IsValid() {
			return
		}
		addr = addr.Unmap()
		key := addr.String()
		if key == "" {
			return
		}
		if _, ok := ipSeen[key]; ok {
			return
		}
		ipSeen[key] = struct{}{}
		ipCandidates = append(ipCandidates, addr)
	}
	if ctx.ip.IsValid() {
		addIPCandidate(ctx.ip)
	}
	if !ctx.ip.IsValid() {
		for _, addr := range hintedIPs {
			addIPCandidate(addr)
		}
	}

	for _, rule := range engine.rules {
		matched := false
		matchedCtx := ctx
		switch {
		case len(hostCandidates) > 0 && len(ipCandidates) > 0:
			for _, host := range hostCandidates {
				for _, ip := range ipCandidates {
					ctx2 := ctx
					ctx2.host = host
					ctx2.ip = ip
					if rule.match(ctx2) {
						matched = true
						matchedCtx = ctx2
						break
					}
				}
				if matched {
					break
				}
			}
		case len(hostCandidates) > 0:
			for _, host := range hostCandidates {
				ctx2 := ctx
				ctx2.host = host
				if rule.match(ctx2) {
					matched = true
					matchedCtx = ctx2
					break
				}
			}
		case len(ipCandidates) > 0:
			for _, ip := range ipCandidates {
				ctx2 := ctx
				ctx2.ip = ip
				if rule.match(ctx2) {
					matched = true
					matchedCtx = ctx2
					break
				}
			}
		default:
			matched = rule.match(ctx)
			matchedCtx = ctx
		}
		if !matched {
			continue
		}
		action := rule.action
		if rule.resolveAction != nil {
			resolvedAction, ok := rule.resolveAction(matchedCtx)
			if !ok {
				continue
			}
			action = resolvedAction
		}
		action = resolveRouteAction(action, engine.groupEgress, defaultNode)
		return routeDecision{
			action:      action,
			matchedRule: rule.raw,
		}
	}
	return decision
}

type routingInbound struct {
	manager       *runtimeClientManager
	decide        func(M.Socksaddr, []string) routeDecision
	prepareDirect func(M.Socksaddr) error
	observe       func(network string, source, destination M.Socksaddr, decision routeDecision, hintedHosts []string)
	handleDNS     func(context.Context, network.PacketConn, M.Metadata) error
	handleDNSTCP  func(context.Context, net.Conn, M.Metadata) error
	handleDoHDoT  func(context.Context, net.Conn, M.Metadata, []string) (bool, error)
	handleHTTPS   func(context.Context, net.Conn, M.Metadata, []string) (bool, error)
	handleQUIC    func(context.Context, network.PacketConn, M.Metadata) (bool, error)
}

func newRoutingInbound(manager *runtimeClientManager, engine *routingEngine, mitm *mitmRuntime) *routingInbound {
	inbound := &routingInbound{
		manager: manager,
		decide: func(destination M.Socksaddr, hintedHosts []string) routeDecision {
			return decideRoutingWithDomainHints(engine, destination, manager.CurrentNodeName(), hintedHosts)
		},
	}
	if mitm != nil {
		inbound.handleHTTPS = func(ctx context.Context, conn net.Conn, metadata M.Metadata, hintedHosts []string) (bool, error) {
			return mitm.HandleTransparentHTTPSConnection(ctx, conn, metadata, hintedHosts)
		}
		inbound.handleQUIC = func(ctx context.Context, conn network.PacketConn, metadata M.Metadata) (bool, error) {
			_ = ctx
			_ = conn
			if metadata.Destination.Port != 443 {
				return false, nil
			}
			if !mitm.ShouldBlockQUIC(metadata.Destination, nil) {
				return false, nil
			}
			logrus.Debugf("[Client] quic blocked for mitm host: dst=%s", metadata.Destination.String())
			return false, fmt.Errorf("%w: quic blocked for mitm host", errRouteRejected)
		}
	}
	return inbound
}

func newDynamicRoutingInbound(
	manager *runtimeClientManager,
	decide func(M.Socksaddr, []string) routeDecision,
	prepareDirect func(M.Socksaddr) error,
	observe func(network string, source, destination M.Socksaddr, decision routeDecision, hintedHosts []string),
	handleDNS func(context.Context, network.PacketConn, M.Metadata) error,
	handleDNSTCP func(context.Context, net.Conn, M.Metadata) error,
	handleDoHDoT func(context.Context, net.Conn, M.Metadata, []string) (bool, error),
	handleHTTPS func(context.Context, net.Conn, M.Metadata, []string) (bool, error),
	handleQUIC func(context.Context, network.PacketConn, M.Metadata) (bool, error),
) *routingInbound {
	return &routingInbound{
		manager:       manager,
		decide:        decide,
		prepareDirect: prepareDirect,
		observe:       observe,
		handleDNS:     handleDNS,
		handleDNSTCP:  handleDNSTCP,
		handleDoHDoT:  handleDoHDoT,
		handleHTTPS:   handleHTTPS,
		handleQUIC:    handleQUIC,
	}
}

func newStateRoutingInbound(state *apiState) *routingInbound {
	return newDynamicRoutingInbound(
		state.manager,
		func(destination M.Socksaddr, extraHints []string) routeDecision {
			state.lock.Lock()
			engine := state.routing
			defaultNode := state.manager.CurrentNodeName()
			dnsMap := state.dnsMap
			state.lock.Unlock()
			var hints []string
			var ipHints []netip.Addr
			if dnsMap != nil && destination.IsIP() {
				hints = dnsMap.LookupByIP(destination.Addr.Unmap().String())
			}
			if dnsMap != nil && destination.IsFqdn() {
				ipHints = dnsMap.LookupByDomain(destination.Fqdn)
			}
			hints = appendUniqueHosts(hints, extraHints...)
			if dnsMap != nil && destination.IsIP() && len(extraHints) > 0 {
				dnsMap.Record(extraHints[0], []netip.Addr{destination.Addr.Unmap()}, 10*time.Minute)
			}
			return decideRoutingWithDomainHintsAndIPHints(engine, destination, defaultNode, hints, ipHints)
		},
		func(destination M.Socksaddr) error {
			state.lock.Lock()
			tun := state.tun
			state.lock.Unlock()
			if tun == nil {
				return nil
			}
			return tun.EnsureDirectBypass(destination)
		},
		func(network string, source, destination M.Socksaddr, decision routeDecision, hintedHosts []string) {
			if state.routingHits == nil {
				return
			}
			var hints []string
			if destination.IsIP() {
				state.lock.Lock()
				dnsMap := state.dnsMap
				state.lock.Unlock()
				if dnsMap != nil {
					hints = dnsMap.LookupByIP(destination.Addr.Unmap().String())
				}
			}
			hints = appendUniqueHosts(hints, hintedHosts...)
			sourceClient := ""
			if source.IsValid() {
				sourceClient = resolveRoutingSourceClient(source.String())
			}
			state.routingHits.append("live", network, destination, decision, time.Now(), sourceClient, hints...)
		},
		func(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
			state.lock.Lock()
			hijacker := state.dnsHijacker
			state.lock.Unlock()
			if hijacker == nil {
				return nil
			}
			return hijacker.HandlePacketConnection(ctx, conn, metadata)
		},
		func(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
			state.lock.Lock()
			hijacker := state.dnsHijacker
			state.lock.Unlock()
			if hijacker == nil {
				return nil
			}
			return hijacker.HandleConnection(ctx, conn, metadata)
		},
		func(ctx context.Context, conn net.Conn, metadata M.Metadata, hintedHosts []string) (bool, error) {
			state.lock.Lock()
			hijacker := state.dnsHijacker
			mitm := state.mitm
			var dohdotCfg *clientMITMDoHDoTConfig
			if state.cfg != nil && state.cfg.MITM != nil {
				dohdotCfg = cloneMITMDoHDoTConfig(state.cfg.MITM.DoHDoT)
			}
			state.lock.Unlock()
			if hijacker == nil || mitm == nil || dohdotCfg == nil || !dohdotCfg.Enabled {
				return false, nil
			}
			return mitm.HandleDoHDoTConnection(ctx, conn, metadata, hintedHosts, hijacker, *dohdotCfg)
		},
		func(ctx context.Context, conn net.Conn, metadata M.Metadata, hintedHosts []string) (bool, error) {
			state.lock.Lock()
			mitm := state.mitm
			state.lock.Unlock()
			if mitm == nil {
				return false, nil
			}
			return mitm.HandleTransparentHTTPSConnection(ctx, conn, metadata, hintedHosts)
		},
		func(ctx context.Context, conn network.PacketConn, metadata M.Metadata) (bool, error) {
			_ = ctx
			_ = conn
			state.lock.Lock()
			mitm := state.mitm
			dnsMap := state.dnsMap
			state.lock.Unlock()
			if mitm == nil || metadata.Destination.Port != 443 {
				return false, nil
			}
			var hintedHosts []string
			if dnsMap != nil && metadata.Destination.IsIP() {
				hintedHosts = dnsMap.LookupByIP(metadata.Destination.Addr.Unmap().String())
			}
			if !mitm.ShouldBlockQUIC(metadata.Destination, hintedHosts) {
				return false, nil
			}
			logrus.Debugf("[Client] quic blocked for mitm host: dst=%s hints=%v", metadata.Destination.String(), hintedHosts)
			return false, fmt.Errorf("%w: quic blocked for mitm host", errRouteRejected)
		},
	)
}

func (h *routingInbound) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if metadata.Destination.Port == 53 && h.handleDNSTCP != nil {
		if err := h.handleDNSTCP(ctx, conn, metadata); err == nil {
			return nil
		}
	}
	hintedHosts, wrappedConn := sniffConnHosts(conn)
	conn = wrappedConn
	if (metadata.Destination.Port == 443 || metadata.Destination.Port == 853) && h.handleDoHDoT != nil {
		handled, err := h.handleDoHDoT(ctx, conn, metadata, hintedHosts)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}
	if metadata.Destination.Port == 443 && h.handleHTTPS != nil {
		handled, err := h.handleHTTPS(ctx, conn, metadata, hintedHosts)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}
	decision := h.decide(metadata.Destination, hintedHosts)
	if h.observe != nil && metadata.Destination.IsValid() && metadata.Destination.Port > 0 {
		h.observe("tcp", metadata.Source, metadata.Destination, decision, hintedHosts)
	}
	switch decision.action.kind {
	case routeActionReject:
		return fmt.Errorf("%w: %s", errRouteRejected, decision.matchedRule)
	case routeActionDirect:
		if h.prepareDirect != nil {
			if err := h.prepareDirect(metadata.Destination); err != nil {
				prepareDirectBypassWarnLogger.log("[Client] prepare direct bypass failed", err)
			}
		}
		target := metadata.Destination.String()
		upstream, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", target)
		if err != nil {
			return err
		}
		defer upstream.Close()
		return bufio.CopyConn(ctx, conn, upstream)
	case routeActionNode:
		nodeName := strings.TrimSpace(decision.action.node)
		if nodeName == "" {
			return fmt.Errorf("routing target node is empty")
		}
		client, err := h.manager.ClientForNode(nodeName)
		if err != nil {
			return err
		}
		return client.NewConnection(ctx, conn, metadata)
	case routeActionGroup:
		return fmt.Errorf("unresolved routing group action: %s", decision.action.group)
	default:
		return fmt.Errorf("unsupported route action")
	}
}

func (h *routingInbound) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	if metadata.Destination.Port == 53 && h.handleDNS != nil {
		if err := h.handleDNS(ctx, conn, metadata); err == nil {
			return nil
		}
	}
	if metadata.Destination.Port == 443 && h.handleQUIC != nil {
		handled, err := h.handleQUIC(ctx, conn, metadata)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}
	decision := h.decide(metadata.Destination, nil)
	if h.observe != nil && metadata.Destination.IsValid() && metadata.Destination.Port > 0 {
		h.observe("udp", metadata.Source, metadata.Destination, decision, nil)
	}
	switch decision.action.kind {
	case routeActionReject:
		return fmt.Errorf("%w: %s", errRouteRejected, decision.matchedRule)
	case routeActionDirect:
		return fmt.Errorf("DIRECT for UDP associate is not supported")
	case routeActionNode:
		nodeName := strings.TrimSpace(decision.action.node)
		if nodeName == "" {
			return fmt.Errorf("routing target node is empty")
		}
		client, err := h.manager.ClientForNode(nodeName)
		if err != nil {
			return err
		}
		proxyC, err := client.CreateProxy(ctx, uot.RequestDestination(2))
		if err != nil {
			return err
		}
		defer proxyC.Close()
		request := uot.Request{
			Destination: metadata.Destination,
		}
		uotC := uot.NewLazyConn(proxyC, request)
		return bufio.CopyPacketConn(ctx, conn, uotC)
	case routeActionGroup:
		return fmt.Errorf("unresolved routing group action: %s", decision.action.group)
	default:
		return fmt.Errorf("unsupported route action")
	}
}
