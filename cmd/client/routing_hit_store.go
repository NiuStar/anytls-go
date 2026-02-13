package main

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type routingHitEntry struct {
	ID           int64  `json:"id"`
	Unix         int64  `json:"unix"`
	Time         string `json:"time"`
	Source       string `json:"source"`
	SourceClient string `json:"source_client,omitempty"`
	Network      string `json:"network"`
	Destination  string `json:"destination"`
	Host         string `json:"host,omitempty"`
	IP           string `json:"ip,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Action       string `json:"action"`
	Node         string `json:"node,omitempty"`
	Rule         string `json:"rule"`
}

type routingHitStore struct {
	lock     sync.Mutex
	capacity int
	entries  []routingHitEntry
	nextID   int64
}

type routingHitBucket struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type routingHitStats struct {
	TotalMatched       int                `json:"total_matched"`
	Returned           int                `json:"returned"`
	DefaultRuleHits    int                `json:"default_rule_hits"`
	HostResolvedHits   int                `json:"host_resolved_hits"`
	HostUnresolvedHits int                `json:"host_unresolved_hits"`
	HostResolvedRate   float64            `json:"host_resolved_rate"`
	Actions            map[string]int     `json:"actions"`
	Networks           map[string]int     `json:"networks"`
	Sources            map[string]int     `json:"sources"`
	Clients            map[string]int     `json:"clients"`
	TopRules           []routingHitBucket `json:"top_rules"`
	TopNodes           []routingHitBucket `json:"top_nodes"`
	TopClients         []routingHitBucket `json:"top_clients"`
}

func newRoutingHitStore(capacity int) *routingHitStore {
	if capacity <= 0 {
		capacity = 5000
	}
	return &routingHitStore{
		capacity: capacity,
		entries:  make([]routingHitEntry, 0, capacity),
		nextID:   1,
	}
}

func (s *routingHitStore) append(source, network string, destination M.Socksaddr, decision routeDecision, ts time.Time, sourceClient string, hintedHosts ...string) {
	if s == nil {
		return
	}
	if !destination.IsValid() || destination.Port == 0 {
		return
	}
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = "live"
	}
	sourceClient = normalizeRoutingHitSourceClient(sourceClient)
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = "tcp"
	}
	action, node := formatRouteDecisionAction(decision.action)
	host := normalizeHost(strings.TrimSpace(destination.Fqdn))
	ip := ""
	if destination.IsIP() {
		if destination.Addr.Unmap().IsUnspecified() {
			return
		}
		ip = destination.Addr.Unmap().String()
	}
	if host == "" {
		for _, h := range hintedHosts {
			h = normalizeHost(h)
			if h != "" {
				host = h
				break
			}
		}
	}
	displayDestination := destination.String()
	if host != "" && destination.Port > 0 {
		displayDestination = net.JoinHostPort(host, strconv.Itoa(int(destination.Port)))
	} else if host != "" {
		displayDestination = host
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	item := routingHitEntry{
		ID:           s.nextID,
		Unix:         ts.Unix(),
		Time:         ts.Format("2006-01-02 15:04:05"),
		Source:       source,
		SourceClient: sourceClient,
		Network:      network,
		Destination:  displayDestination,
		Host:         host,
		IP:           ip,
		Port:         destination.Port,
		Action:       action,
		Node:         node,
		Rule:         decision.matchedRule,
	}
	s.nextID++
	s.entries = append(s.entries, item)
	if len(s.entries) > s.capacity {
		trim := len(s.entries) - s.capacity
		s.entries = append([]routingHitEntry(nil), s.entries[trim:]...)
	}
}

func (s *routingHitStore) list(limit int, source, sourceClient, network, action, search, node, rule string, sinceID int64, windowSec int) []routingHitEntry {
	items, _ := s.listWithStats(limit, source, sourceClient, network, action, search, node, rule, sinceID, windowSec)
	return items
}

func (s *routingHitStore) listWithStats(limit int, source, sourceClient, network, action, search, node, rule string, sinceID int64, windowSec int) ([]routingHitEntry, routingHitStats) {
	stats := routingHitStats{
		Actions:  map[string]int{},
		Networks: map[string]int{},
		Sources:  map[string]int{},
		Clients:  map[string]int{},
	}
	if s == nil {
		return nil, stats
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}
	source = strings.ToLower(strings.TrimSpace(source))
	sourceClient = normalizeRoutingHitSourceClient(sourceClient)
	network = strings.ToLower(strings.TrimSpace(network))
	action = strings.ToUpper(strings.TrimSpace(action))
	search = strings.ToLower(strings.TrimSpace(search))
	node = strings.TrimSpace(node)
	rule = strings.TrimSpace(rule)
	if windowSec < 0 {
		windowSec = 0
	}
	sinceUnix := int64(0)
	if windowSec > 0 {
		sinceUnix = time.Now().Unix() - int64(windowSec)
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	ruleCounter := make(map[string]int)
	nodeCounter := make(map[string]int)
	out := make([]routingHitEntry, 0, limit)
	for i := len(s.entries) - 1; i >= 0; i-- {
		item := s.entries[i]
		if sinceID > 0 && item.ID <= sinceID {
			continue
		}
		if sinceUnix > 0 && item.Unix > 0 && item.Unix < sinceUnix {
			continue
		}
		if source != "" && strings.ToLower(item.Source) != source {
			continue
		}
		if sourceClient != "" && normalizeRoutingHitSourceClient(item.SourceClient) != sourceClient {
			continue
		}
		if network != "" && strings.ToLower(item.Network) != network {
			continue
		}
		if action != "" && strings.ToUpper(item.Action) != action {
			continue
		}
		if node != "" && strings.TrimSpace(item.Node) != node {
			continue
		}
		if rule != "" && strings.TrimSpace(item.Rule) != rule {
			continue
		}
		if search != "" {
			blob := strings.ToLower(item.Destination + " " + item.Host + " " + item.IP + " " + item.Action + " " + item.Node + " " + item.Rule + " " + item.SourceClient)
			if !strings.Contains(blob, search) {
				continue
			}
		}
		stats.TotalMatched++
		actionName := strings.ToUpper(strings.TrimSpace(item.Action))
		if actionName == "" {
			actionName = "UNKNOWN"
		}
		stats.Actions[actionName]++
		networkName := strings.ToLower(strings.TrimSpace(item.Network))
		if networkName == "" {
			networkName = "unknown"
		}
		stats.Networks[networkName]++
		sourceName := strings.ToLower(strings.TrimSpace(item.Source))
		if sourceName == "" {
			sourceName = "unknown"
		}
		stats.Sources[sourceName]++
		clientName := normalizeRoutingHitSourceClient(item.SourceClient)
		if clientName == "" {
			clientName = "unknown"
		}
		stats.Clients[clientName]++
		ruleName := strings.TrimSpace(item.Rule)
		if ruleName == "" {
			ruleName = "UNKNOWN"
		}
		ruleCounter[ruleName]++
		if strings.EqualFold(ruleName, "DEFAULT") {
			stats.DefaultRuleHits++
		}
		if actionName == "NODE" {
			nodeName := strings.TrimSpace(item.Node)
			if nodeName == "" {
				nodeName = "(empty)"
			}
			nodeCounter[nodeName]++
		}
		if strings.TrimSpace(item.Host) != "" {
			stats.HostResolvedHits++
		} else {
			stats.HostUnresolvedHits++
		}
		if len(out) < limit {
			out = append(out, item)
		}
	}
	stats.Returned = len(out)
	if stats.TotalMatched > 0 {
		stats.HostResolvedRate = float64(stats.HostResolvedHits) * 100 / float64(stats.TotalMatched)
	}
	stats.TopRules = toTopBuckets(ruleCounter, 10)
	stats.TopNodes = toTopBuckets(nodeCounter, 10)
	stats.TopClients = toTopBuckets(stats.Clients, 10)
	return out, stats
}

func normalizeRoutingHitSourceClient(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if parsed := M.ParseSocksaddr(value); parsed.IsValid() {
		if parsed.IsIP() {
			return parsed.Addr.Unmap().String()
		}
		if parsed.IsFqdn() {
			return strings.ToLower(strings.TrimSpace(parsed.Fqdn))
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		if host != "" {
			return strings.ToLower(host)
		}
	}
	value = strings.Trim(value, "[]")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return strings.ToLower(value)
}

func (s *routingHitStore) clear() {
	if s == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.entries = s.entries[:0]
}

func (s *routingHitStore) latestID() int64 {
	if s == nil {
		return 0
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(s.entries) == 0 {
		return 0
	}
	return s.entries[len(s.entries)-1].ID
}

func toTopBuckets(counter map[string]int, topN int) []routingHitBucket {
	if len(counter) == 0 || topN <= 0 {
		return nil
	}
	out := make([]routingHitBucket, 0, len(counter))
	for name, count := range counter {
		if count <= 0 {
			continue
		}
		out = append(out, routingHitBucket{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}
