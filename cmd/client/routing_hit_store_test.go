package main

import (
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestRoutingHitStoreListWithStats(t *testing.T) {
	store := newRoutingHitStore(16)
	now := time.Now()

	store.append(
		"live",
		"tcp",
		M.Socksaddr{Fqdn: "4.ipw.cn", Port: 443},
		routeDecision{action: routeAction{kind: routeActionDirect}, matchedRule: "DOMAIN-SUFFIX,ipw.cn,DIRECT"},
		now,
		"",
	)
	store.append(
		"live",
		"tcp",
		M.Socksaddr{Addr: netip.MustParseAddr("1.1.1.1"), Port: 443},
		routeDecision{action: routeAction{kind: routeActionNode, node: "node-1"}, matchedRule: "DEFAULT"},
		now,
		"",
	)
	store.append(
		"test",
		"udp",
		M.Socksaddr{Addr: netip.MustParseAddr("2.2.2.2"), Port: 53},
		routeDecision{action: routeAction{kind: routeActionReject}, matchedRule: "RULE-SET,ads,REJECT"},
		now,
		"",
	)

	// unspecified destination should be filtered out
	store.append(
		"live",
		"udp",
		M.Socksaddr{Addr: netip.IPv4Unspecified(), Port: 443},
		routeDecision{action: routeAction{kind: routeActionNode, node: "node-1"}, matchedRule: "DEFAULT"},
		now,
		"",
	)

	items, stats := store.listWithStats(100, "", "", "", "", "", "", "", 0, 0)
	if len(items) != 3 {
		t.Fatalf("unexpected items len: %d", len(items))
	}
	if items[0].ID <= items[1].ID || items[1].ID <= items[2].ID {
		t.Fatalf("items not ordered by latest first: %+v", items)
	}
	if stats.TotalMatched != 3 || stats.Returned != 3 {
		t.Fatalf("unexpected totals: %+v", stats)
	}
	if stats.DefaultRuleHits != 1 {
		t.Fatalf("unexpected default hits: %+v", stats)
	}
	if stats.HostResolvedHits != 1 || stats.HostUnresolvedHits != 2 {
		t.Fatalf("unexpected host stats: %+v", stats)
	}
	if got := stats.Actions["DIRECT"]; got != 1 {
		t.Fatalf("unexpected DIRECT count: %d", got)
	}
	if got := stats.Actions["NODE"]; got != 1 {
		t.Fatalf("unexpected NODE count: %d", got)
	}
	if got := stats.Actions["REJECT"]; got != 1 {
		t.Fatalf("unexpected REJECT count: %d", got)
	}
	if len(stats.TopNodes) != 1 || stats.TopNodes[0].Name != "node-1" || stats.TopNodes[0].Count != 1 {
		t.Fatalf("unexpected top nodes: %+v", stats.TopNodes)
	}

	nodeItems, nodeStats := store.listWithStats(100, "", "", "", "NODE", "", "", "", 0, 0)
	if len(nodeItems) != 1 || nodeStats.TotalMatched != 1 {
		t.Fatalf("unexpected NODE filtered result: len=%d stats=%+v", len(nodeItems), nodeStats)
	}

	ruleItems, ruleStats := store.listWithStats(100, "", "", "", "", "", "", "DEFAULT", 0, 0)
	if len(ruleItems) != 1 || ruleStats.TotalMatched != 1 {
		t.Fatalf("unexpected rule filtered result: len=%d stats=%+v", len(ruleItems), ruleStats)
	}

	windowItems, windowStats := store.listWithStats(100, "", "", "", "", "", "", "", 0, 1)
	if len(windowItems) != 3 || windowStats.TotalMatched != 3 {
		t.Fatalf("unexpected window filtered result: len=%d stats=%+v", len(windowItems), windowStats)
	}
}
