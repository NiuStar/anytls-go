package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"anytls/proxy"

	M "github.com/sagernet/sing/common/metadata"
	singSocks "github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sirupsen/logrus"
)

const (
	externalCoreStartTimeout = 15 * time.Second
	defaultSingBoxBinaryEnv  = "ANYTLS_SINGBOX_BIN"
	nativeSingBoxConfigDir   = "anytls-singbox-nodes"
	nativeSOCKSPortBase      = 22000
	nativeSOCKSPortSpan      = 18000
)

type socksBridgeSpec struct {
	Server   string
	Username string
	Password string
}

type externalCoreSpec struct {
	Engine    string
	Binary    string
	Config    string
	AutoStart bool
	SOCKS     socksBridgeSpec
}

type externalCoreProcess struct {
	spec  externalCoreSpec
	cmd   *exec.Cmd
	owned bool
}

type nativeProxyNodeSpec struct {
	RawURI   string
	Scheme   string
	Server   string
	NameHint string
	Outbound map[string]any
}

func (p *externalCoreProcess) Close() error {
	if p == nil || !p.owned || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
	return nil
}

func parseSOCKSBridgeNodeURI(raw string) (socksBridgeSpec, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return socksBridgeSpec{}, false, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return socksBridgeSpec{}, false, err
	}
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "socks", "socks5":
	default:
		return socksBridgeSpec{}, false, nil
	}

	server := strings.TrimSpace(u.Host)
	if _, _, err := net.SplitHostPort(server); err != nil {
		return socksBridgeSpec{}, true, fmt.Errorf("invalid socks server %q: %w", server, err)
	}
	spec := socksBridgeSpec{Server: server}
	if u.User != nil {
		spec.Username = strings.TrimSpace(u.User.Username())
		spec.Password, _ = u.User.Password()
		spec.Password = strings.TrimSpace(spec.Password)
	}
	return spec, true, nil
}

func parseExternalCoreNodeURI(raw string) (externalCoreSpec, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return externalCoreSpec{}, false, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return externalCoreSpec{}, false, err
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	engine := ""
	switch scheme {
	case "singbox", "sing-box":
		engine = "sing-box"
	case "mihomo":
		engine = "mihomo"
	default:
		return externalCoreSpec{}, false, nil
	}

	query := u.Query()
	socksAddr := strings.TrimSpace(query.Get("socks"))
	if socksAddr == "" {
		host := strings.TrimSpace(u.Host)
		if _, _, err := net.SplitHostPort(host); err == nil {
			socksAddr = host
		}
	}
	if socksAddr == "" {
		return externalCoreSpec{}, true, fmt.Errorf("missing socks address in uri query: socks=host:port")
	}
	if _, _, err := net.SplitHostPort(socksAddr); err != nil {
		return externalCoreSpec{}, true, fmt.Errorf("invalid socks address %q: %w", socksAddr, err)
	}

	spec := externalCoreSpec{
		Engine: engine,
		SOCKS: socksBridgeSpec{
			Server: strings.TrimSpace(socksAddr),
		},
	}
	if u.User != nil {
		spec.SOCKS.Username = strings.TrimSpace(u.User.Username())
		spec.SOCKS.Password, _ = u.User.Password()
		spec.SOCKS.Password = strings.TrimSpace(spec.SOCKS.Password)
	}
	if v := strings.TrimSpace(query.Get("socks_user")); v != "" {
		spec.SOCKS.Username = v
	}
	if v := strings.TrimSpace(query.Get("socks_pass")); v != "" {
		spec.SOCKS.Password = v
	}
	if v := strings.TrimSpace(query.Get("bin")); v != "" {
		spec.Binary = v
	}
	if v := strings.TrimSpace(query.Get("config")); v != "" {
		spec.Config = normalizeExternalPath(v)
	}
	spec.AutoStart = parseBoolDefault(strings.TrimSpace(query.Get("autostart")), false)
	if spec.Binary == "" {
		if spec.Engine == "sing-box" {
			spec.Binary = "sing-box"
		} else {
			spec.Binary = "mihomo"
		}
	}
	if spec.AutoStart && spec.Config == "" {
		return externalCoreSpec{}, true, fmt.Errorf("autostart requires config path")
	}
	return spec, true, nil
}

func parseNativeProxyNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nativeProxyNodeSpec{}, false, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, false, err
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	switch scheme {
	case "ss":
		return parseNativeSSNodeURI(raw)
	case "vmess":
		return parseNativeVMessNodeURI(raw)
	case "vless":
		return parseNativeVLESSNodeURI(raw)
	case "trojan":
		return parseNativeTrojanNodeURI(raw)
	case "hy2", "hysteria2":
		return parseNativeHysteria2NodeURI(raw)
	case "tuic":
		return parseNativeTUICNodeURI(raw)
	case "wireguard", "wg":
		return parseNativeWireGuardNodeURI(raw)
	case "ssh":
		return parseNativeSSHNodeURI(raw)
	default:
		return nativeProxyNodeSpec{}, false, nil
	}
}

func buildExternalCoreSpecFromNativeNode(nodeName string, native nativeProxyNodeSpec) (externalCoreSpec, error) {
	if strings.TrimSpace(native.Server) == "" {
		return externalCoreSpec{}, fmt.Errorf("native node server is empty")
	}
	if native.Outbound == nil {
		return externalCoreSpec{}, fmt.Errorf("native node outbound config is empty")
	}

	seed := strings.TrimSpace(nodeName)
	if seed == "" {
		seed = strings.TrimSpace(native.RawURI)
	}
	socksPort, err := pickAvailableLocalTCPPort()
	if err != nil {
		// Some restricted environments may disallow bind() in tests/sandbox.
		// Fallback to deterministic high-port assignment.
		socksPort = fallbackNativeSOCKSPort(seed)
	}
	socksServer := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	configPath := filepath.Join(os.TempDir(), nativeSingBoxConfigDir, stableNativeConfigFile(seed))
	if err := writeNativeSingBoxConfig(configPath, socksPort, native.Outbound); err != nil {
		return externalCoreSpec{}, err
	}

	binary := strings.TrimSpace(os.Getenv(defaultSingBoxBinaryEnv))
	if binary == "" {
		binary = "sing-box"
	}
	return externalCoreSpec{
		Engine:    "sing-box",
		Binary:    binary,
		Config:    configPath,
		AutoStart: true,
		SOCKS: socksBridgeSpec{
			Server: socksServer,
		},
	}, nil
}

func pickAvailableLocalTCPPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return 0, fmt.Errorf("invalid listener addr: %v", ln.Addr())
	}
	return addr.Port, nil
}

func fallbackNativeSOCKSPort(seed string) int {
	h := sha1.Sum([]byte(seed))
	v := int(uint16(h[0])<<8 | uint16(h[1]))
	return nativeSOCKSPortBase + (v % nativeSOCKSPortSpan)
}

func stableNativeConfigFile(seed string) string {
	sum := sha1.Sum([]byte(seed))
	return "node-" + hex.EncodeToString(sum[:8]) + ".json"
}

func writeNativeSingBoxConfig(path string, socksPort int, outbound map[string]any) error {
	if socksPort <= 0 || socksPort > 65535 {
		return fmt.Errorf("invalid socks port: %d", socksPort)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	proxyOutbound := cloneMapAnyShallow(outbound)
	proxyOutbound["tag"] = "proxy"
	cfg := map[string]any{
		"log": map[string]any{
			"disabled": true,
		},
		"inbounds": []any{
			map[string]any{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": socksPort,
			},
		},
		"outbounds": []any{
			proxyOutbound,
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		"route": map[string]any{
			"final":                 "proxy",
			"auto_detect_interface": true,
		},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if old, err := os.ReadFile(path); err == nil && string(old) == string(raw) {
		return nil
	}
	return os.WriteFile(path, raw, 0600)
}

func cloneMapAnyShallow(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func parseNativeSSNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	if strings.ToLower(strings.TrimSpace(u.Scheme)) != "ss" {
		return nativeProxyNodeSpec{}, false, nil
	}
	q := u.Query()
	server := strings.TrimSpace(u.Host)
	cred := ""
	if u.User != nil {
		cred = strings.TrimSpace(u.User.Username())
		if pwd, ok := u.User.Password(); ok {
			if cred == "" {
				cred = pwd
			} else {
				cred = cred + ":" + pwd
			}
		}
	}
	if server == "" {
		body := strings.TrimSpace(raw)
		if idx := strings.Index(body, "://"); idx >= 0 {
			body = body[idx+3:]
		}
		if idx := strings.Index(body, "#"); idx >= 0 {
			body = body[:idx]
		}
		if idx := strings.Index(body, "?"); idx >= 0 {
			body = body[:idx]
		}
		decoded, decErr := decodeBase64Loose(body)
		if decErr != nil {
			return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid ss uri body")
		}
		at := strings.LastIndex(decoded, "@")
		if at <= 0 || at >= len(decoded)-1 {
			return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid ss decoded payload")
		}
		cred = decoded[:at]
		server = decoded[at+1:]
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid ss server %q: %w", server, err)
	}
	ssHost, ssPortText, err := net.SplitHostPort(server)
	if err != nil {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid ss server %q: %w", server, err)
	}
	ssPort, err := parseIntStrict(ssPortText, 1, 65535)
	if err != nil {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid ss port: %w", err)
	}
	method, password, err := parseSSCredential(cred)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	outbound := map[string]any{
		"type":        "shadowsocks",
		"server":      strings.TrimSpace(ssHost),
		"server_port": ssPort,
		"method":      method,
		"password":    password,
	}
	if plugin := strings.TrimSpace(q.Get("plugin")); plugin != "" {
		decoded, _ := url.QueryUnescape(plugin)
		parts := strings.SplitN(decoded, ";", 2)
		outbound["plugin"] = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			outbound["plugin_opts"] = strings.TrimSpace(parts[1])
		}
	}
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "ss",
		Server:   server,
		NameHint: decodeFragmentName(u.Fragment),
		Outbound: outbound,
	}, true, nil
}

func parseNativeTrojanNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	if strings.ToLower(strings.TrimSpace(u.Scheme)) != "trojan" {
		return nativeProxyNodeSpec{}, false, nil
	}
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("trojan password is required")
	}
	host, port, err := parseURLHostPort(u)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	q := u.Query()
	password := strings.TrimSpace(u.User.Username())
	outbound := map[string]any{
		"type":        "trojan",
		"server":      host,
		"server_port": port,
		"password":    password,
	}
	applyTLSFromQuery(outbound, q, true)
	applyTransportFromQuery(outbound, q)
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "trojan",
		Server:   net.JoinHostPort(host, strconv.Itoa(port)),
		NameHint: decodeFragmentName(u.Fragment),
		Outbound: outbound,
	}, true, nil
}

func parseNativeVLESSNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	if strings.ToLower(strings.TrimSpace(u.Scheme)) != "vless" {
		return nativeProxyNodeSpec{}, false, nil
	}
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("vless uuid is required")
	}
	host, port, err := parseURLHostPort(u)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	q := u.Query()
	outbound := map[string]any{
		"type":        "vless",
		"server":      host,
		"server_port": port,
		"uuid":        strings.TrimSpace(u.User.Username()),
	}
	if flow := strings.TrimSpace(q.Get("flow")); flow != "" {
		outbound["flow"] = flow
	}
	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	if security != "none" {
		applyTLSFromQuery(outbound, q, security == "" || security == "tls" || security == "reality")
	}
	applyTransportFromQuery(outbound, q)
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "vless",
		Server:   net.JoinHostPort(host, strconv.Itoa(port)),
		NameHint: decodeFragmentName(u.Fragment),
		Outbound: outbound,
	}, true, nil
}

func parseNativeVMessNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "vmess://") {
		return nativeProxyNodeSpec{}, false, nil
	}
	body := strings.TrimSpace(raw)
	if idx := strings.Index(body, "://"); idx >= 0 {
		body = body[idx+3:]
	}
	frag := ""
	if idx := strings.Index(body, "#"); idx >= 0 {
		frag = body[idx+1:]
		body = body[:idx]
	}
	payload, err := decodeBase64Loose(body)
	if err != nil {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid vmess payload: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid vmess json: %w", err)
	}
	host := strings.TrimSpace(firstMapString(m, "add", "address", "server", "host"))
	if host == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("vmess host is required")
	}
	port, err := parseIntStrict(firstMapString(m, "port"), 1, 65535)
	if err != nil {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("invalid vmess port: %w", err)
	}
	uuid := strings.TrimSpace(firstMapString(m, "id", "uuid"))
	if uuid == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("vmess uuid is required")
	}
	outbound := map[string]any{
		"type":        "vmess",
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
	}
	if security := strings.TrimSpace(firstMapString(m, "scy", "security", "cipher")); security != "" {
		outbound["security"] = security
	}
	if aid := strings.TrimSpace(firstMapString(m, "aid", "alterId", "alter_id")); aid != "" {
		if n, convErr := parseIntStrict(aid, 0, 65535); convErr == nil {
			outbound["alter_id"] = n
		}
	}
	tlsFlag := strings.ToLower(strings.TrimSpace(firstMapString(m, "tls")))
	if tlsFlag == "tls" || tlsFlag == "1" || tlsFlag == "true" {
		tls := map[string]any{"enabled": true}
		if sni := strings.TrimSpace(firstMapString(m, "sni", "servername", "host")); sni != "" {
			tls["server_name"] = sni
		}
		outbound["tls"] = tls
	}
	netType := strings.ToLower(strings.TrimSpace(firstMapString(m, "net", "network", "type")))
	if transport := buildTransportByType(netType, firstMapString(m, "path"), firstMapString(m, "host"), firstMapString(m, "serviceName", "service_name")); transport != nil {
		outbound["transport"] = transport
	}
	nameHint := decodeFragmentName(frag)
	if nameHint == "" {
		nameHint = strings.TrimSpace(firstMapString(m, "ps", "name", "remark"))
	}
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "vmess",
		Server:   net.JoinHostPort(host, strconv.Itoa(port)),
		NameHint: nameHint,
		Outbound: outbound,
	}, true, nil
}

func parseNativeHysteria2NodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "hy2" && scheme != "hysteria2" {
		return nativeProxyNodeSpec{}, false, nil
	}
	host, port, err := parseURLHostPort(u)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	q := u.Query()
	password := ""
	if u.User != nil {
		password = strings.TrimSpace(u.User.Username())
		if p, ok := u.User.Password(); ok && strings.TrimSpace(p) != "" {
			password = strings.TrimSpace(p)
		}
	}
	if password == "" {
		password = strings.TrimSpace(firstQueryValue(q, "password", "auth"))
	}
	outbound := map[string]any{
		"type":        "hysteria2",
		"server":      host,
		"server_port": port,
	}
	if password != "" {
		outbound["password"] = password
	}
	applyTLSFromQuery(outbound, q, true)
	if obfs := strings.TrimSpace(q.Get("obfs")); obfs != "" {
		outbound["obfs"] = obfs
	}
	if v := strings.TrimSpace(firstQueryValue(q, "obfs-password", "obfs_password")); v != "" {
		outbound["obfs_password"] = v
	}
	if upRaw := strings.TrimSpace(firstQueryValue(q, "upmbps", "up-mbps", "up")); upRaw != "" {
		if up, convErr := parseIntStrict(upRaw, 1, 100000); convErr == nil {
			outbound["up_mbps"] = up
		}
	}
	if downRaw := strings.TrimSpace(firstQueryValue(q, "downmbps", "down-mbps", "down")); downRaw != "" {
		if down, convErr := parseIntStrict(downRaw, 1, 100000); convErr == nil {
			outbound["down_mbps"] = down
		}
	}
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "hysteria2",
		Server:   net.JoinHostPort(host, strconv.Itoa(port)),
		NameHint: decodeFragmentName(u.Fragment),
		Outbound: outbound,
	}, true, nil
}

func parseNativeTUICNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	if strings.ToLower(strings.TrimSpace(u.Scheme)) != "tuic" {
		return nativeProxyNodeSpec{}, false, nil
	}
	host, port, err := parseURLHostPort(u)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("tuic uuid is required")
	}
	password, _ := u.User.Password()
	password = strings.TrimSpace(password)
	if password == "" {
		password = strings.TrimSpace(u.Query().Get("password"))
	}
	outbound := map[string]any{
		"type":        "tuic",
		"server":      host,
		"server_port": port,
		"uuid":        strings.TrimSpace(u.User.Username()),
	}
	if password != "" {
		outbound["password"] = password
	}
	applyTLSFromQuery(outbound, u.Query(), true)
	if cc := strings.TrimSpace(u.Query().Get("congestion_control")); cc != "" {
		outbound["congestion_control"] = cc
	}
	if alpnRaw := strings.TrimSpace(u.Query().Get("alpn")); alpnRaw != "" {
		if values := parseCSVQueryStrings(alpnRaw); len(values) > 0 {
			outbound["alpn"] = values
		}
	}
	if relayMode := strings.TrimSpace(firstQueryValue(u.Query(), "udp_relay_mode", "udp-relay-mode")); relayMode != "" {
		outbound["udp_relay_mode"] = relayMode
	}
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "tuic",
		Server:   net.JoinHostPort(host, strconv.Itoa(port)),
		NameHint: decodeFragmentName(u.Fragment),
		Outbound: outbound,
	}, true, nil
}

func parseNativeWireGuardNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "wireguard" && scheme != "wg" {
		return nativeProxyNodeSpec{}, false, nil
	}
	host, port, err := parseURLHostPort(u)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	privateKey := ""
	if u.User != nil {
		privateKey = strings.TrimSpace(u.User.Username())
	}
	q := u.Query()
	if privateKey == "" {
		privateKey = strings.TrimSpace(firstQueryValue(q, "privatekey", "private_key"))
	}
	if privateKey == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("wireguard private key is required")
	}
	peerPublicKey := strings.TrimSpace(firstQueryValue(q, "publickey", "peer_public_key", "peer-public-key"))
	if peerPublicKey == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("wireguard peer public key is required")
	}
	localAddress := parseCSVQueryStrings(firstQueryValue(q, "address", "local_address", "local-address"))
	outbound := map[string]any{
		"type":            "wireguard",
		"server":          host,
		"server_port":     port,
		"private_key":     privateKey,
		"peer_public_key": peerPublicKey,
	}
	if len(localAddress) > 0 {
		outbound["local_address"] = localAddress
	}
	if psk := strings.TrimSpace(firstQueryValue(q, "presharedkey", "pre_shared_key")); psk != "" {
		outbound["pre_shared_key"] = psk
	}
	if mtuRaw := strings.TrimSpace(q.Get("mtu")); mtuRaw != "" {
		if mtu, convErr := parseIntStrict(mtuRaw, 576, 9200); convErr == nil {
			outbound["mtu"] = mtu
		}
	}
	if reserved := strings.TrimSpace(firstQueryValue(q, "reserved")); reserved != "" {
		if parsed := parseWireGuardReserved(reserved); len(parsed) > 0 {
			outbound["reserved"] = parsed
		}
	}
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "wireguard",
		Server:   net.JoinHostPort(host, strconv.Itoa(port)),
		NameHint: decodeFragmentName(u.Fragment),
		Outbound: outbound,
	}, true, nil
}

func parseNativeSSHNodeURI(raw string) (nativeProxyNodeSpec, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	if strings.ToLower(strings.TrimSpace(u.Scheme)) != "ssh" {
		return nativeProxyNodeSpec{}, false, nil
	}
	host, port, err := parseURLHostPort(u)
	if err != nil {
		return nativeProxyNodeSpec{}, true, err
	}
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nativeProxyNodeSpec{}, true, fmt.Errorf("ssh username is required")
	}
	q := u.Query()
	outbound := map[string]any{
		"type":        "ssh",
		"server":      host,
		"server_port": port,
		"user":        strings.TrimSpace(u.User.Username()),
	}
	if password, ok := u.User.Password(); ok && strings.TrimSpace(password) != "" {
		outbound["password"] = strings.TrimSpace(password)
	}
	if key := strings.TrimSpace(firstQueryValue(q, "private_key", "private-key", "key")); key != "" {
		outbound["private_key"] = normalizeExternalPath(key)
	}
	if hostKey := strings.TrimSpace(firstQueryValue(q, "host_key", "host-key")); hostKey != "" {
		outbound["host_key"] = hostKey
	}
	return nativeProxyNodeSpec{
		RawURI:   strings.TrimSpace(raw),
		Scheme:   "ssh",
		Server:   net.JoinHostPort(host, strconv.Itoa(port)),
		NameHint: decodeFragmentName(u.Fragment),
		Outbound: outbound,
	}, true, nil
}

func parseURLHostPort(u *url.URL) (string, int, error) {
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", 0, fmt.Errorf("host is required")
	}
	port, err := parseIntStrict(strings.TrimSpace(u.Port()), 1, 65535)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %w", err)
	}
	return host, port, nil
}

func mustPort(portRaw, fallbackHostPort string) int {
	if p, err := parseIntStrict(strings.TrimSpace(portRaw), 1, 65535); err == nil {
		return p
	}
	_, portText, err := net.SplitHostPort(strings.TrimSpace(fallbackHostPort))
	if err != nil {
		return 0
	}
	p, _ := parseIntStrict(portText, 1, 65535)
	return p
}

func parseIntStrict(raw string, min, max int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty value")
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if n < min || n > max {
		return 0, fmt.Errorf("out of range")
	}
	return n, nil
}

func parseSSCredential(raw string) (method, password string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("ss credential is empty")
	}
	decoded, decErr := decodeBase64Loose(raw)
	if decErr == nil && strings.Contains(decoded, ":") {
		raw = decoded
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid ss credential")
	}
	method = strings.TrimSpace(parts[0])
	password = strings.TrimSpace(parts[1])
	if method == "" || password == "" {
		return "", "", fmt.Errorf("invalid ss credential")
	}
	return method, password, nil
}

func decodeBase64Loose(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty base64")
	}
	raw = strings.ReplaceAll(raw, " ", "")
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, enc := range encodings {
		if b, err := enc.DecodeString(raw); err == nil {
			return string(b), nil
		}
		if padded := padBase64(raw); padded != raw {
			if b, err := enc.DecodeString(padded); err == nil {
				return string(b), nil
			}
		}
	}
	return "", fmt.Errorf("invalid base64 text")
}

func padBase64(raw string) string {
	if raw == "" {
		return raw
	}
	mod := len(raw) % 4
	if mod == 0 {
		return raw
	}
	return raw + strings.Repeat("=", 4-mod)
}

func decodeFragmentName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(raw)
	if err == nil {
		return strings.TrimSpace(decoded)
	}
	return raw
}

func firstQueryValue(q url.Values, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(q.Get(strings.TrimSpace(key))); v != "" {
			return v
		}
	}
	return ""
}

func parseCSVQueryStrings(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseWireGuardReserved(raw string) []int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		n, err := parseIntStrict(v, 0, 255)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstMapString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func applyTLSFromQuery(outbound map[string]any, q url.Values, enabledByDefault bool) {
	security := strings.ToLower(strings.TrimSpace(firstQueryValue(q, "security", "tls")))
	enabled := enabledByDefault
	if security == "none" || security == "0" || security == "false" {
		enabled = false
	}
	if security == "tls" || security == "reality" || security == "1" || security == "true" {
		enabled = true
	}
	if !enabled {
		return
	}
	tls := map[string]any{"enabled": true}
	if sni := strings.TrimSpace(firstQueryValue(q, "sni", "peer", "servername", "server_name")); sni != "" {
		tls["server_name"] = sni
	}
	if parseBoolDefault(firstQueryValue(q, "insecure", "allowInsecure", "skip-cert-verify", "allow_insecure"), false) {
		tls["insecure"] = true
	}
	if security == "reality" {
		reality := map[string]any{"enabled": true}
		if pbk := strings.TrimSpace(firstQueryValue(q, "pbk", "public-key", "public_key")); pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := strings.TrimSpace(firstQueryValue(q, "sid", "short-id", "short_id")); sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
	}
	outbound["tls"] = tls
}

func applyTransportFromQuery(outbound map[string]any, q url.Values) {
	netType := strings.ToLower(strings.TrimSpace(firstQueryValue(q, "type", "net", "network")))
	if netType == "" {
		return
	}
	if transport := buildTransportByType(netType, firstQueryValue(q, "path"), firstQueryValue(q, "host", "ws-host"), firstQueryValue(q, "serviceName", "service_name")); transport != nil {
		outbound["transport"] = transport
	}
}

func buildTransportByType(netType, pathValue, hostValue, serviceValue string) map[string]any {
	netType = strings.ToLower(strings.TrimSpace(netType))
	pathValue = strings.TrimSpace(pathValue)
	hostValue = strings.TrimSpace(hostValue)
	serviceValue = strings.TrimSpace(serviceValue)
	switch netType {
	case "ws", "websocket":
		transport := map[string]any{"type": "ws"}
		if pathValue != "" {
			transport["path"] = pathValue
		}
		if hostValue != "" {
			transport["headers"] = map[string]any{"Host": hostValue}
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		svc := serviceValue
		if svc == "" {
			svc = strings.TrimPrefix(pathValue, "/")
		}
		if svc != "" {
			transport["service_name"] = svc
		}
		return transport
	case "http", "h2", "http2":
		transport := map[string]any{"type": "http"}
		if hostValue != "" {
			transport["host"] = []string{hostValue}
		}
		if pathValue != "" {
			transport["path"] = pathValue
		}
		return transport
	case "tcp", "raw", "quic":
		return map[string]any{"type": netType}
	default:
		return nil
	}
}

func normalizeExternalPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "file://") {
		if u, err := url.Parse(raw); err == nil {
			if p := strings.TrimSpace(u.Path); p != "" {
				raw = p
			}
		}
	}
	return raw
}

func parseBoolDefault(raw string, fallback bool) bool {
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		if n, err := strconv.Atoi(raw); err == nil {
			return n != 0
		}
		return fallback
	}
}

func startExternalCoreIfNeeded(ctx context.Context, nodeName string, spec externalCoreSpec) (*externalCoreProcess, error) {
	if !spec.AutoStart {
		return &externalCoreProcess{spec: spec}, nil
	}
	if checkTCPReachable(spec.SOCKS.Server, 600*time.Millisecond) {
		return &externalCoreProcess{spec: spec}, nil
	}

	if _, err := exec.LookPath(spec.Binary); err != nil {
		return nil, fmt.Errorf("external core binary not found: %s (%w)", spec.Binary, err)
	}

	args, err := buildExternalCoreArgs(spec)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, spec.Binary, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if spec.Config != "" {
		cmd.Dir = filepath.Dir(spec.Config)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start external core failed: %w", err)
	}

	deadline := time.Now().Add(externalCoreStartTimeout)
	for {
		if checkTCPReachable(spec.SOCKS.Server, 600*time.Millisecond) {
			logrus.Infof("[Client] external core started for node=%s engine=%s socks=%s", nodeName, spec.Engine, spec.SOCKS.Server)
			return &externalCoreProcess{
				spec:  spec,
				cmd:   cmd,
				owned: true,
			}, nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return nil, fmt.Errorf("external core exited before socks is ready")
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return nil, fmt.Errorf("external core startup timeout: %s", spec.SOCKS.Server)
		}
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func buildExternalCoreArgs(spec externalCoreSpec) ([]string, error) {
	switch spec.Engine {
	case "sing-box":
		if spec.Config == "" {
			return nil, fmt.Errorf("sing-box config is required")
		}
		return []string{"run", "-c", spec.Config}, nil
	case "mihomo":
		if spec.Config == "" {
			return nil, fmt.Errorf("mihomo config is required")
		}
		return []string{"-f", spec.Config}, nil
	default:
		return nil, fmt.Errorf("unsupported external engine: %s", spec.Engine)
	}
}

func checkTCPReachable(addr string, timeout time.Duration) bool {
	if strings.TrimSpace(addr) == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func dialSOCKS5Connect(ctx context.Context, spec socksBridgeSpec, destination M.Socksaddr) (net.Conn, error) {
	conn, err := proxy.SystemDialer.DialContext(ctx, "tcp", spec.Server)
	if err != nil {
		return nil, err
	}
	_, err = singSocks.ClientHandshake5(conn, socks5.CommandConnect, destination, spec.Username, spec.Password)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
