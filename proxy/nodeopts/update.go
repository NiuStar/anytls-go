package nodeopts

import (
	"fmt"
	"strings"
)

type NodeData struct {
	Server        string
	Password      string
	SNI           string
	EgressIP      string
	EgressRule    string
	AllowInsecure *bool
	CACertPath    string
	Groups        []string
}

type NodeClearOptions struct {
	ClearSNI           bool
	ClearEgressIP      bool
	ClearEgressRule    bool
	ClearCACertPath    bool
	ClearAllowInsecure bool
}

func BuildCLIUpdatePayload(node NodeData, uri string, opts NodeClearOptions) (map[string]any, error) {
	payload := nodeDataWithURI(node, uri)

	if opts.ClearSNI {
		if _, exists := payload["sni"]; exists {
			return nil, fmt.Errorf("cannot use -sni and --clear-sni together")
		}
		payload["sni"] = ""
	}
	if opts.ClearEgressIP {
		if _, exists := payload["egress_ip"]; exists {
			return nil, fmt.Errorf("cannot use -egress-ip and --clear-egress-ip together")
		}
		payload["egress_ip"] = ""
	}
	if opts.ClearEgressRule {
		if _, exists := payload["egress_rule"]; exists {
			return nil, fmt.Errorf("cannot use -egress-rule and --clear-egress-rule together")
		}
		payload["egress_rule"] = ""
	}
	if opts.ClearCACertPath {
		if _, exists := payload["ca_cert_path"]; exists {
			return nil, fmt.Errorf("cannot use -ca-cert-path and --clear-ca-cert-path together")
		}
		payload["ca_cert_path"] = ""
	}
	if opts.ClearAllowInsecure {
		if _, exists := payload["allow_insecure"]; exists {
			return nil, fmt.Errorf("cannot use -allow-insecure and --clear-allow-insecure together")
		}
		// explicit null means clear and fallback to runtime default
		payload["allow_insecure"] = nil
	}
	return payload, nil
}

func HasDirectUpdateFields(updateFields map[string]struct{}) bool {
	for _, key := range []string{"server", "password", "sni", "egress_ip", "egress_rule", "allow_insecure", "ca_cert_path", "groups"} {
		if _, ok := updateFields[key]; ok {
			return true
		}
	}
	return false
}

func ApplyUpdateToNode(dst *NodeData, req NodeData, updateFields map[string]struct{}) {
	if dst == nil {
		return
	}
	if v := strings.TrimSpace(req.Server); v != "" {
		dst.Server = v
	}
	if v := strings.TrimSpace(req.Password); v != "" {
		dst.Password = v
	}
	if _, ok := updateFields["sni"]; ok {
		dst.SNI = strings.TrimSpace(req.SNI)
	} else if v := strings.TrimSpace(req.SNI); v != "" {
		dst.SNI = v
	}
	if _, ok := updateFields["egress_ip"]; ok {
		dst.EgressIP = strings.TrimSpace(req.EgressIP)
	} else if v := strings.TrimSpace(req.EgressIP); v != "" {
		dst.EgressIP = v
	}
	if _, ok := updateFields["egress_rule"]; ok {
		dst.EgressRule = strings.TrimSpace(req.EgressRule)
	} else if v := strings.TrimSpace(req.EgressRule); v != "" {
		dst.EgressRule = v
	}
	if _, ok := updateFields["allow_insecure"]; ok {
		dst.AllowInsecure = CloneBoolPtr(req.AllowInsecure)
	} else if req.AllowInsecure != nil {
		dst.AllowInsecure = CloneBoolPtr(req.AllowInsecure)
	}
	if _, ok := updateFields["ca_cert_path"]; ok {
		dst.CACertPath = strings.TrimSpace(req.CACertPath)
	} else if v := strings.TrimSpace(req.CACertPath); v != "" {
		dst.CACertPath = v
	}
	if req.Groups != nil {
		dst.Groups = append([]string(nil), req.Groups...)
	}
}

func nodeDataWithURI(node NodeData, uri string) map[string]any {
	payload := map[string]any{}
	if s := strings.TrimSpace(node.Server); s != "" {
		payload["server"] = s
	}
	if s := strings.TrimSpace(node.Password); s != "" {
		payload["password"] = s
	}
	if s := strings.TrimSpace(node.SNI); s != "" {
		payload["sni"] = s
	}
	if s := strings.TrimSpace(node.EgressIP); s != "" {
		payload["egress_ip"] = s
	}
	if s := strings.TrimSpace(node.EgressRule); s != "" {
		payload["egress_rule"] = s
	}
	if node.AllowInsecure != nil {
		payload["allow_insecure"] = node.AllowInsecure
	}
	if s := strings.TrimSpace(node.CACertPath); s != "" {
		payload["ca_cert_path"] = s
	}
	if node.Groups != nil {
		payload["groups"] = append([]string(nil), node.Groups...)
	}
	if s := strings.TrimSpace(uri); s != "" {
		payload["uri"] = s
	}
	return payload
}
