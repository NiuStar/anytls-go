package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func runCLI(configPath, controlAddr, cmd, nodeName, nodeURI, backupName string, nodeData clientNodeConfig) error {
	command := strings.ToLower(strings.TrimSpace(cmd))
	if command == "" {
		return fmt.Errorf("cli mode requires -cmd")
	}

	addr, authUser, authPass, err := resolveAPIAccess(configPath, controlAddr)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	switch command {
	case "list", "nodes":
		return cliRequest(client, http.MethodGet, apiURL(addr, "/api/v1/nodes"), nil, authUser, authPass)
	case "status":
		return cliRequest(client, http.MethodGet, apiURL(addr, "/api/v1/status"), nil, authUser, authPass)
	case "backups", "backup-list":
		return cliRequest(client, http.MethodGet, apiURL(addr, "/api/v1/config/backups"), nil, authUser, authPass)
	case "diagnose":
		return cliRequest(client, http.MethodGet, apiURL(addr, "/api/v1/diagnose"), nil, authUser, authPass)
	case "current":
		return cliRequest(client, http.MethodGet, apiURL(addr, "/api/v1/current"), nil, authUser, authPass)
	case "switch":
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			return fmt.Errorf("switch requires -node")
		}
		return cliRequest(client, http.MethodPost, apiURL(addr, "/api/v1/switch"), map[string]any{
			"name": nodeName,
		}, authUser, authPass)
	case "import", "add":
		if strings.TrimSpace(nodeURI) == "" {
			return fmt.Errorf("%s requires -uri", command)
		}
		return cliRequest(client, http.MethodPost, apiURL(addr, "/api/v1/nodes/import"), map[string]any{
			"name": nodeName,
			"uri":  nodeURI,
		}, authUser, authPass)
	case "create":
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			return fmt.Errorf("create requires -node")
		}
		nodeData.Name = nodeName
		return cliRequest(client, http.MethodPost, apiURL(addr, "/api/v1/nodes"), nodeData, authUser, authPass)
	case "update", "edit":
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			return fmt.Errorf("%s requires -node", command)
		}
		return cliRequest(client, http.MethodPut, apiURL(addr, "/api/v1/nodes/"+url.PathEscape(nodeName)), nodeDataWithURI(nodeData, nodeURI), authUser, authPass)
	case "delete", "del", "rm":
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			return fmt.Errorf("%s requires -node", command)
		}
		return cliRequest(client, http.MethodDelete, apiURL(addr, "/api/v1/nodes/"+url.PathEscape(nodeName)), nil, authUser, authPass)
	case "rollback":
		return cliRequest(client, http.MethodPost, apiURL(addr, "/api/v1/config/rollback"), map[string]any{
			"backup": strings.TrimSpace(backupName),
		}, authUser, authPass)
	case "stop", "shutdown", "quit":
		return cliRequest(client, http.MethodPost, apiURL(addr, "/api/v1/shutdown"), map[string]any{}, authUser, authPass)
	default:
		return fmt.Errorf("unsupported -cmd: %s", command)
	}
}

func resolveAPIAccess(configPath, controlAddr string) (addr, authUser, authPass string, err error) {
	addr = strings.TrimSpace(controlAddr)
	authUser = strings.TrimSpace(os.Getenv("ANYTLS_API_USER"))
	authPass = strings.TrimSpace(os.Getenv("ANYTLS_API_PASS"))

	if strings.TrimSpace(configPath) != "" {
		cfg, cfgErr := loadClientConfig(configPath)
		if cfgErr == nil {
			if addr == "" && cfg.Control != "" {
				addr = cfg.Control
			}
			if authUser == "" {
				authUser = strings.TrimSpace(cfg.WebUsername)
			}
			if authPass == "" {
				authPass = strings.TrimSpace(cfg.WebPassword)
			}
		}
	}
	if addr == "" {
		addr = defaultControlAddr
	}
	return addr, authUser, authPass, nil
}

func nodeDataWithURI(node clientNodeConfig, uri string) map[string]any {
	return map[string]any{
		"server":      node.Server,
		"password":    node.Password,
		"sni":         node.SNI,
		"egress_ip":   node.EgressIP,
		"egress_rule": node.EgressRule,
		"uri":         uri,
	}
}

func cliRequest(httpClient *http.Client, method, url string, payload any, authUser, authPass string) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(authUser) != "" || strings.TrimSpace(authPass) != "" {
		req.SetBasicAuth(authUser, authPass)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("api request failed (%s %s): %w; 请检查 API 地址并确认 anytls-client API 进程正在运行", method, displayAPIURL(url), err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return formatAPIError(method, url, resp, rawBody)
	}

	var formatted bytes.Buffer
	if json.Valid(rawBody) {
		if err := json.Indent(&formatted, rawBody, "", "  "); err == nil {
			_, _ = fmt.Println(formatted.String())
		} else if len(rawBody) > 0 {
			_, _ = fmt.Println(string(rawBody))
		}
	} else if len(rawBody) > 0 {
		_, _ = fmt.Println(string(rawBody))
	}

	return nil
}

func displayAPIURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.Host == "" {
		return rawURL
	}
	return u.Host + u.Path
}

func formatAPIError(method, rawURL string, resp *http.Response, rawBody []byte) error {
	apiErr := extractAPIError(rawBody)
	prefix := fmt.Sprintf("api request failed (%s %s): HTTP %d %s", method, displayAPIURL(rawURL), resp.StatusCode, http.StatusText(resp.StatusCode))
	if apiErr != "" {
		return fmt.Errorf("%s: %s", prefix, apiErr)
	}
	body := strings.TrimSpace(string(rawBody))
	if body != "" {
		return fmt.Errorf("%s: %s", prefix, body)
	}
	return errors.New(prefix)
}

func extractAPIError(rawBody []byte) string {
	if len(rawBody) == 0 || !json.Valid(rawBody) {
		return ""
	}
	var parsed map[string]any
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return ""
	}
	for _, key := range []string{"error", "message", "detail"} {
		if v, ok := parsed[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
