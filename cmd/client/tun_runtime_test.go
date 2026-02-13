package main

import "testing"

func TestParseDarwinRouteGetOutputWithGateway(t *testing.T) {
	out := "route to: default\ninterface: en0\ngateway: 192.168.1.1\nflags: <UP,DONE,STATIC>\n"
	gw, iface := parseDarwinRouteGetOutput(out)
	if gw != "192.168.1.1" {
		t.Fatalf("unexpected gateway: %q", gw)
	}
	if iface != "en0" {
		t.Fatalf("unexpected iface: %q", iface)
	}
}

func TestParseDarwinRouteGetOutputWithoutGateway(t *testing.T) {
	out := "route to: default\ndestination: default\nmask: default\ninterface: utun6\nflags: <UP,DONE>\n"
	gw, iface := parseDarwinRouteGetOutput(out)
	if gw != "" {
		t.Fatalf("expected empty gateway, got %q", gw)
	}
	if iface != "utun6" {
		t.Fatalf("unexpected iface: %q", iface)
	}
}

func TestParseDarwinNetworkServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\niPhone USB\n\n"
	services := parseDarwinNetworkServices(out)
	if len(services) != 2 {
		t.Fatalf("unexpected services len: %d %#v", len(services), services)
	}
	if services[0] != "Wi-Fi" || services[1] != "iPhone USB" {
		t.Fatalf("unexpected services: %#v", services)
	}
}

func TestParsePIDs(t *testing.T) {
	pids := parsePIDs("123\nabc\n456\n123\n\n")
	if len(pids) != 2 {
		t.Fatalf("unexpected pid len: %d %#v", len(pids), pids)
	}
	if pids[0] != 123 || pids[1] != 456 {
		t.Fatalf("unexpected pids: %#v", pids)
	}
}

func TestParseLinuxDefaultRouteOutputIPRoute(t *testing.T) {
	out := "default via 192.168.1.1 dev br-lan proto static metric 1024\n"
	spec, via, dev, ok := parseLinuxDefaultRouteOutput(out)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if spec != "via 192.168.1.1 dev br-lan" {
		t.Fatalf("unexpected spec: %q", spec)
	}
	if via != "192.168.1.1" {
		t.Fatalf("unexpected via: %q", via)
	}
	if dev != "br-lan" {
		t.Fatalf("unexpected dev: %q", dev)
	}
}

func TestParseLinuxDefaultRouteOutputBusyBoxRouteN(t *testing.T) {
	out := "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         192.168.8.1     0.0.0.0         UG    0      0        0 wan\n"
	spec, via, dev, ok := parseLinuxDefaultRouteOutput(out)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if spec != "via 192.168.8.1 dev wan" {
		t.Fatalf("unexpected spec: %q", spec)
	}
	if via != "192.168.8.1" {
		t.Fatalf("unexpected via: %q", via)
	}
	if dev != "wan" {
		t.Fatalf("unexpected dev: %q", dev)
	}
}

func TestParseLinuxDefaultRouteOutputIPRouteWithIPv6Gateway(t *testing.T) {
	out := "default via fe80::1 dev eth1 proto ra metric 1024\n"
	spec, via, dev, ok := parseLinuxDefaultRouteOutput(out)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if spec != "dev eth1" {
		t.Fatalf("unexpected spec: %q", spec)
	}
	if via != "" {
		t.Fatalf("expected empty via for IPv6 gateway in IPv4 route, got %q", via)
	}
	if dev != "eth1" {
		t.Fatalf("unexpected dev: %q", dev)
	}
}

func TestParseLinuxDefaultRouteOutputBusyBoxRouteNWithIPv6Gateway(t *testing.T) {
	out := "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         fe80::1         0.0.0.0         UG    0      0        0 eth1\n"
	spec, via, dev, ok := parseLinuxDefaultRouteOutput(out)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if spec != "dev eth1" {
		t.Fatalf("unexpected spec: %q", spec)
	}
	if via != "" {
		t.Fatalf("expected empty via for IPv6 gateway in IPv4 route, got %q", via)
	}
	if dev != "eth1" {
		t.Fatalf("unexpected dev: %q", dev)
	}
}

func TestParseLinuxDefaultRouteOutputEmpty(t *testing.T) {
	if _, _, _, ok := parseLinuxDefaultRouteOutput(""); ok {
		t.Fatalf("expected parse failure for empty output")
	}
}

func TestResolveServerIPv4SetIPv6OnlyLiteral(t *testing.T) {
	got, err := resolveServerIPv4Set("[240e:6b0:d00:803::a096:b]:10087")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty ipv4 set for ipv6-only server, got: %#v", got)
	}
}

func TestResolveTargetIPv4SetIPv6OnlyLiteral(t *testing.T) {
	got, err := resolveTargetIPv4Set("[240e:6b0:d00:803::a096:b]:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty ipv4 set for ipv6-only target, got: %#v", got)
	}
}

func TestParseOpenWrtWANDefaultRouteSpec(t *testing.T) {
	raw := `{
  "l3_device": "eth1",
  "route": [
    {"target":"0.0.0.0","mask":0,"nexthop":"192.168.100.1"}
  ]
}`
	spec := parseOpenWrtWANDefaultRouteSpec(raw)
	if spec != "via 192.168.100.1 dev eth1" {
		t.Fatalf("unexpected spec: %q", spec)
	}
}

func TestParseOpenWrtWANDefaultRouteSpecWithoutGateway(t *testing.T) {
	raw := `{
  "l3_device": "pppoe-wan",
  "route": [
    {"target":"0.0.0.0","mask":0,"nexthop":""}
  ]
}`
	spec := parseOpenWrtWANDefaultRouteSpec(raw)
	if spec != "dev pppoe-wan" {
		t.Fatalf("unexpected spec: %q", spec)
	}
}

func TestParseOpenWrtWANDefaultRouteSpecSkipTunDevice(t *testing.T) {
	raw := `{
  "l3_device": "tun0",
  "route": [
    {"target":"0.0.0.0","mask":0,"nexthop":"192.168.1.1"}
  ]
}`
	spec := parseOpenWrtWANDefaultRouteSpec(raw)
	if spec != "" {
		t.Fatalf("expected empty spec for tun device, got: %q", spec)
	}
}
