package nodeopts

import "testing"

func TestBuildCLIUpdatePayload_ClearAndConflict(t *testing.T) {
	payload, err := BuildCLIUpdatePayload(NodeData{}, "", NodeClearOptions{
		ClearSNI:           true,
		ClearEgressIP:      true,
		ClearEgressRule:    true,
		ClearCACertPath:    true,
		ClearAllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("build payload failed: %v", err)
	}
	for _, key := range []string{"sni", "egress_ip", "egress_rule", "ca_cert_path", "allow_insecure"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("%s missing in payload: %v", key, payload)
		}
	}

	_, err = BuildCLIUpdatePayload(NodeData{SNI: "example.com"}, "", NodeClearOptions{ClearSNI: true})
	if err == nil {
		t.Fatalf("expected conflict error")
	}
}

func TestApplyUpdateToNode(t *testing.T) {
	current := NodeData{
		Server:     "a:443",
		Password:   "p",
		SNI:        "old",
		EgressIP:   "203.0.113.1",
		EgressRule: "default=203.0.113.1",
		CACertPath: "/old/ca.crt",
		Groups:     []string{"g1"},
	}
	vFalse := false
	req := NodeData{
		SNI:           "",
		EgressIP:      "",
		EgressRule:    "",
		AllowInsecure: &vFalse,
		CACertPath:    "",
		Groups:        []string{"g2"},
	}
	fields := map[string]struct{}{
		"sni":            {},
		"egress_ip":      {},
		"egress_rule":    {},
		"allow_insecure": {},
		"ca_cert_path":   {},
	}
	ApplyUpdateToNode(&current, req, fields)
	if current.SNI != "" || current.EgressIP != "" || current.EgressRule != "" || current.CACertPath != "" {
		t.Fatalf("expected cleared string fields, got %+v", current)
	}
	if current.AllowInsecure == nil || *current.AllowInsecure {
		t.Fatalf("allow_insecure apply failed: %+v", current.AllowInsecure)
	}
	if len(current.Groups) != 1 || current.Groups[0] != "g2" {
		t.Fatalf("groups apply failed: %+v", current.Groups)
	}
}

func TestHasDirectUpdateFields(t *testing.T) {
	if HasDirectUpdateFields(map[string]struct{}{"uri": {}}) {
		t.Fatalf("uri should not be considered direct field")
	}
	if !HasDirectUpdateFields(map[string]struct{}{"sni": {}}) {
		t.Fatalf("sni should be considered direct field")
	}
}
