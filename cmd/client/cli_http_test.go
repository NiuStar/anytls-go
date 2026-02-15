package main

import "testing"

func TestNodeDataWithURI_PartialUpdateOnly(t *testing.T) {
	insecure := false
	payload := nodeDataWithURI(clientNodeConfig{
		EgressIP:      "203.0.113.10",
		AllowInsecure: &insecure,
	}, "")
	if got := len(payload); got != 2 {
		t.Fatalf("payload len = %d, want 2; payload=%v", got, payload)
	}
	if got, ok := payload["egress_ip"]; !ok || got != "203.0.113.10" {
		t.Fatalf("egress_ip missing or invalid: %v", payload)
	}
	if _, ok := payload["allow_insecure"]; !ok {
		t.Fatalf("allow_insecure missing: %v", payload)
	}
	if _, ok := payload["server"]; ok {
		t.Fatalf("server should not be present in partial payload: %v", payload)
	}
}

func TestNodeDataWithURI_IncludeURIWhenProvided(t *testing.T) {
	payload := nodeDataWithURI(clientNodeConfig{}, "anytls://a@b:443/?sni=x")
	if got := len(payload); got != 1 {
		t.Fatalf("payload len = %d, want 1; payload=%v", got, payload)
	}
	if got, ok := payload["uri"]; !ok || got != "anytls://a@b:443/?sni=x" {
		t.Fatalf("uri missing or invalid: %v", payload)
	}
}

func TestBuildNodeUpdatePayload_ClearFlags(t *testing.T) {
	payload, err := buildNodeUpdatePayload(clientNodeConfig{}, "", cliNodeUpdateOptions{
		ClearSNI:           true,
		ClearEgressIP:      true,
		ClearEgressRule:    true,
		ClearCACertPath:    true,
		ClearAllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("buildNodeUpdatePayload clear flags error: %v", err)
	}
	for _, key := range []string{"sni", "egress_ip", "egress_rule", "ca_cert_path", "allow_insecure"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("%s missing in payload: %v", key, payload)
		}
	}
}

func TestBuildNodeUpdatePayload_Conflict(t *testing.T) {
	_, err := buildNodeUpdatePayload(clientNodeConfig{
		SNI: "example.com",
	}, "", cliNodeUpdateOptions{ClearSNI: true})
	if err == nil {
		t.Fatalf("expected conflict error but got nil")
	}
}
