package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const defaultServerListen = "0.0.0.0:8443"

type serverEnvConfig struct {
	Listen   string
	Password string
	CertDir  string
}

type exportedNode struct {
	Name       string `json:"name"`
	URI        string `json:"uri"`
	EgressIP   string `json:"egress_ip,omitempty"`
	EgressRule string `json:"egress_rule,omitempty"`
}

type serverExportPreset struct {
	Addrs      []string `json:"addrs"`
	NodePrefix string   `json:"node_prefix"`
	SNI        string   `json:"sni,omitempty"`
	EgressIP   string   `json:"egress_ip,omitempty"`
	EgressRule string   `json:"egress_rule,omitempty"`
}

var stdinReader = bufio.NewReader(os.Stdin)

func runServerConfigCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: anytls-server config <edit|export> [options]")
	}
	switch args[0] {
	case "edit":
		return runServerConfigEdit(args[1:])
	case "export":
		return runServerConfigExport(args[1:])
	default:
		return fmt.Errorf("unknown config subcommand %q, use edit|export", args[0])
	}
}

func runServerConfigEdit(args []string) error {
	fs := flag.NewFlagSet("anytls-server config edit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configPath := fs.String("config", defaultServerConfigPath(), "server env config path")
	listen := fs.String("listen", "", "listen address host:port")
	password := fs.String("password", "", "password")
	certDir := fs.String("cert-dir", "", "TLS cert dir, requires server.crt and server.key")
	autoCert := fs.Bool("auto-cert", false, "clear cert-dir and use auto-generated cert")
	yes := fs.Bool("yes", false, "non-interactive mode")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := serverEnvConfig{
		Listen: defaultServerListen,
	}
	loaded, err := loadServerEnvConfig(*configPath)
	if err == nil {
		cfg = loaded
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load config failed: %w", err)
	}

	if strings.TrimSpace(*listen) != "" {
		cfg.Listen = strings.TrimSpace(*listen)
	}
	if strings.TrimSpace(*password) != "" {
		cfg.Password = strings.TrimSpace(*password)
	}
	if strings.TrimSpace(*certDir) != "" {
		cfg.CertDir = strings.TrimSpace(*certDir)
	}
	if *autoCert {
		cfg.CertDir = ""
	}

	if !*yes {
		reader := stdinReader
		var promptErr error
		cfg.Listen, promptErr = promptInput(reader, "监听地址(host:port)", cfg.Listen)
		if promptErr != nil {
			return promptErr
		}

		if strings.TrimSpace(*password) == "" {
			if cfg.Password != "" {
				needChange, err := promptYesNo(reader, "是否修改密码？", false)
				if err != nil {
					return err
				}
				if needChange {
					cfg.Password, err = promptPassword(reader)
					if err != nil {
						return err
					}
				}
			} else {
				cfg.Password, err = promptPassword(reader)
				if err != nil {
					return err
				}
			}
		}

		if !*autoCert && strings.TrimSpace(*certDir) == "" {
			useAuto, err := promptYesNo(reader, "是否自动生成证书？", cfg.CertDir == "")
			if err != nil {
				return err
			}
			if useAuto {
				cfg.CertDir = ""
			} else {
				cfg.CertDir, err = promptInput(reader, "证书目录(需包含 server.crt 与 server.key)", cfg.CertDir)
				if err != nil {
					return err
				}
			}
		}
	}

	if err := validateListen(cfg.Listen); err != nil {
		return err
	}
	if cfg.Password == "" {
		return fmt.Errorf("password is required")
	}
	if hasControlChars(cfg.Password) {
		return fmt.Errorf("password contains control characters (for example newline/tab), please set a plain text password")
	}
	if err := validateCertDir(cfg.CertDir); err != nil {
		return err
	}
	if err := saveServerEnvConfig(*configPath, cfg); err != nil {
		return err
	}

	fmt.Println("配置已写入:", *configPath)
	fmt.Println("LISTEN:", cfg.Listen)
	if cfg.CertDir != "" {
		fmt.Println("CERT_DIR:", cfg.CertDir)
	} else {
		fmt.Println("CERT_DIR: (auto-generated)")
	}
	return nil
}

func runServerConfigExport(args []string) error {
	fs := flag.NewFlagSet("anytls-server config export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configPath := fs.String("config", defaultServerConfigPath(), "server env config path")
	addrList := fs.String("addr", "", "comma separated host:port list, defaults to detected local IPs")
	nodePrefix := fs.String("node-prefix", "", "node name prefix")
	sni := fs.String("sni", "", "sni")
	egressIP := fs.String("egress-ip", "", "egress-ip")
	egressRule := fs.String("egress-rule", "", "egress-rule")
	yes := fs.Bool("yes", false, "non-interactive mode")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadServerEnvConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}
	if cfg.Password == "" {
		return fmt.Errorf("password is empty in %s", *configPath)
	}
	if hasControlChars(cfg.Password) {
		return fmt.Errorf("password in %s contains control characters (for example newline/tab), please run `anytls-server config edit` to reset it", *configPath)
	}
	port, err := listenPort(cfg.Listen)
	if err != nil {
		return err
	}

	presetPath := defaultServerExportPresetPath(*configPath)
	preset, _ := loadServerExportPreset(presetPath)
	addrs := parseCommaList(*addrList)
	localIPs := detectLocalIPs()
	hasExplicitExportArgs := strings.TrimSpace(*addrList) != "" ||
		strings.TrimSpace(*nodePrefix) != "" ||
		strings.TrimSpace(*sni) != "" ||
		strings.TrimSpace(*egressIP) != "" ||
		strings.TrimSpace(*egressRule) != ""

	useLast := false
	reader := stdinReader
	if !*yes && !hasExplicitExportArgs && preset != nil {
		chooseLast, askErr := promptYesNo(reader, "检测到上次导出配置，是否直接按上次配置导出？", true)
		if askErr != nil {
			return askErr
		}
		useLast = chooseLast
		if useLast {
			if len(preset.Addrs) > 0 {
				addrs = append([]string{}, preset.Addrs...)
			}
			if strings.TrimSpace(*nodePrefix) == "" {
				*nodePrefix = strings.TrimSpace(preset.NodePrefix)
			}
			if strings.TrimSpace(*sni) == "" {
				*sni = strings.TrimSpace(preset.SNI)
			}
			if strings.TrimSpace(*egressIP) == "" {
				*egressIP = strings.TrimSpace(preset.EgressIP)
			}
			if strings.TrimSpace(*egressRule) == "" {
				*egressRule = strings.TrimSpace(preset.EgressRule)
			}
			fmt.Println("已选择：沿用上次导出配置。")
		} else {
			fmt.Println("已选择：重新填写导出配置。")
		}
	}

	if len(addrs) == 0 {
		for _, ip := range localIPs {
			addrs = append(addrs, net.JoinHostPort(ip, port))
		}
	}

	if !*yes && len(addrs) == 0 {
		manual, err := promptInput(reader, "未检测到本机IP，请输入客户端连接地址(host:port)", "example.com:"+port)
		if err != nil {
			return err
		}
		addrs = append(addrs, strings.TrimSpace(manual))
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no server address available, pass --addr host:port")
	}

	if *nodePrefix == "" {
		*nodePrefix = "server-" + port
	}
	if !*yes && !useLast {
		var promptErr error
		*nodePrefix, promptErr = promptInput(reader, "节点名称前缀", *nodePrefix)
		if promptErr != nil {
			return promptErr
		}
		if strings.TrimSpace(*sni) == "" {
			*sni, promptErr = promptInput(reader, "SNI（可留空）", "")
			if promptErr != nil {
				return promptErr
			}
		}
		if strings.TrimSpace(*egressIP) == "" {
			if len(localIPs) > 0 {
				fmt.Println("可选本机IP:")
				for idx, ip := range localIPs {
					fmt.Printf("  %d) %s\n", idx+1, ip)
				}
			}
			*egressIP, promptErr = promptInput(reader, "egress-ip（留空不设置）", "")
			if promptErr != nil {
				return promptErr
			}
		}
		if strings.TrimSpace(*egressRule) == "" {
			fmt.Println("egress-rule 示例: domain:example.com=203.0.113.10;suffix:google.com=203.0.113.11;default=203.0.113.12")
			*egressRule, promptErr = promptInput(reader, "egress-rule（留空不设置）", "")
			if promptErr != nil {
				return promptErr
			}
		}
	}

	*nodePrefix = strings.TrimSpace(*nodePrefix)
	*sni = strings.TrimSpace(*sni)
	*egressIP = strings.TrimSpace(*egressIP)
	*egressRule = strings.TrimSpace(*egressRule)
	if *nodePrefix == "" {
		return fmt.Errorf("node-prefix is empty")
	}
	if *egressIP != "" {
		ip := net.ParseIP(*egressIP)
		if ip == nil {
			return fmt.Errorf("invalid egress-ip: %s", *egressIP)
		}
		*egressIP = ip.String()
	}
	if err := validateEgressRule(*egressRule); err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := validateListen(addr); err != nil {
			return fmt.Errorf("invalid export addr %q: %w", addr, err)
		}
	}
	if err := saveServerExportPreset(presetPath, &serverExportPreset{
		Addrs:      append([]string{}, addrs...),
		NodePrefix: *nodePrefix,
		SNI:        *sni,
		EgressIP:   *egressIP,
		EgressRule: *egressRule,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warn: save last export preset failed: %v\n", err)
	}

	nodes := make([]exportedNode, 0, len(addrs))
	for i, addr := range addrs {
		name := *nodePrefix
		if len(addrs) > 1 {
			name = fmt.Sprintf("%s-%d", *nodePrefix, i+1)
		}
		nodes = append(nodes, exportedNode{
			Name:       name,
			URI:        buildNodeURI(cfg.Password, addr, *sni, *egressIP, *egressRule),
			EgressIP:   *egressIP,
			EgressRule: *egressRule,
		})
	}

	fmt.Println("导出地址:")
	for i, addr := range addrs {
		fmt.Printf("  %d) %s\n", i+1, addr)
	}
	fmt.Println()
	fmt.Println("URI 列表:")
	for _, n := range nodes {
		fmt.Printf("  [%s] %s\n", n.Name, n.URI)
	}
	fmt.Println()
	fmt.Println("JSON 片段（nodes 数组）:")
	jsonBytes, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	fmt.Println()
	fmt.Println("客户端导入命令:")
	for _, n := range nodes {
		fmt.Printf("  anytls-client cli add %q %q\n", n.URI, n.Name)
	}
	return nil
}

func defaultServerExportPresetPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "server_export_last.json")
}

func loadServerExportPreset(path string) (*serverExportPreset, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var preset serverExportPreset
	if err := json.Unmarshal(raw, &preset); err != nil {
		return nil, err
	}
	preset.NodePrefix = strings.TrimSpace(preset.NodePrefix)
	preset.SNI = strings.TrimSpace(preset.SNI)
	preset.EgressIP = strings.TrimSpace(preset.EgressIP)
	preset.EgressRule = strings.TrimSpace(preset.EgressRule)
	for i := range preset.Addrs {
		preset.Addrs[i] = strings.TrimSpace(preset.Addrs[i])
	}
	return &preset, nil
}

func saveServerExportPreset(path string, preset *serverExportPreset) error {
	if preset == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(preset, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func defaultServerConfigPath() string {
	if v := strings.TrimSpace(os.Getenv("ANYTLS_SERVER_CONFIG")); v != "" {
		return v
	}
	return "/etc/anytls/server.env"
}

func loadServerEnvConfig(path string) (serverEnvConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return serverEnvConfig{}, err
	}
	cfg := serverEnvConfig{
		Listen: defaultServerListen,
	}
	for _, rawLine := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := decodeEnvValue(strings.TrimSpace(kv[1]))
		switch key {
		case "LISTEN":
			cfg.Listen = value
		case "PASSWORD":
			cfg.Password = value
		case "CERT_DIR":
			cfg.CertDir = value
		}
	}
	return cfg, nil
}

func decodeEnvValue(raw string) string {
	if raw == "" {
		return ""
	}
	v, err := strconv.Unquote(raw)
	if err == nil {
		return v
	}
	if v, ok := decodeBashAnsiCQuoted(raw); ok {
		return v
	}
	return raw
}

var octalRe = regexp.MustCompile(`^[0-7]$`)

func decodeBashAnsiCQuoted(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "$'") || !strings.HasSuffix(raw, "'") || len(raw) < 3 {
		return "", false
	}
	body := raw[2 : len(raw)-1]
	var out strings.Builder
	for i := 0; i < len(body); {
		ch := body[i]
		if ch != '\\' {
			out.WriteByte(ch)
			i++
			continue
		}
		i++
		if i >= len(body) {
			out.WriteByte('\\')
			break
		}
		esc := body[i]
		i++
		switch esc {
		case 'a':
			out.WriteByte('\a')
		case 'b':
			out.WriteByte('\b')
		case 'e', 'E':
			out.WriteByte(0x1b)
		case 'f':
			out.WriteByte('\f')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'v':
			out.WriteByte('\v')
		case '\\':
			out.WriteByte('\\')
		case '\'':
			out.WriteByte('\'')
		case '"':
			out.WriteByte('"')
		case 'x':
			j := i
			for j < len(body) && j < i+2 && isHex(body[j]) {
				j++
			}
			if j == i {
				out.WriteString(`\x`)
				continue
			}
			n, err := strconv.ParseUint(body[i:j], 16, 8)
			if err != nil {
				out.WriteString(`\x` + body[i:j])
			} else {
				out.WriteByte(byte(n))
			}
			i = j
		case 'u', 'U':
			width := 4
			if esc == 'U' {
				width = 8
			}
			j := i
			for j < len(body) && j < i+width && isHex(body[j]) {
				j++
			}
			if j == i {
				out.WriteByte('\\')
				out.WriteByte(esc)
				continue
			}
			n, err := strconv.ParseUint(body[i:j], 16, 32)
			if err != nil {
				out.WriteString(body[i:j])
			} else if r := rune(n); utf8.ValidRune(r) {
				out.WriteRune(r)
			} else {
				out.WriteRune(utf8.RuneError)
			}
			i = j
		default:
			if octalRe.MatchString(string(esc)) {
				j := i
				for j < len(body) && j < i+2 && octalRe.MatchString(string(body[j])) {
					j++
				}
				num := string(esc) + body[i:j]
				n, err := strconv.ParseUint(num, 8, 8)
				if err != nil {
					out.WriteByte('\\')
					out.WriteString(num)
				} else {
					out.WriteByte(byte(n))
				}
				i = j
				continue
			}
			out.WriteByte(esc)
		}
	}
	return out.String(), true
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func saveServerEnvConfig(path string, cfg serverEnvConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir failed: %w", err)
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "LISTEN=%q\n", cfg.Listen)
	fmt.Fprintf(&buf, "PASSWORD=%q\n", cfg.Password)
	fmt.Fprintf(&buf, "CERT_DIR=%q\n", cfg.CertDir)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write config failed: %w", err)
	}
	return nil
}

func validateListen(listen string) error {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return fmt.Errorf("listen is empty")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	_ = host
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid port in %q", listen)
	}
	return nil
}

func listenPort(listen string) (string, error) {
	if err := validateListen(listen); err != nil {
		return "", err
	}
	_, port, _ := net.SplitHostPort(listen)
	return port, nil
}

func validateCertDir(certDir string) error {
	certDir = strings.TrimSpace(certDir)
	if certDir == "" {
		return nil
	}
	info, err := os.Stat(certDir)
	if err != nil {
		return fmt.Errorf("invalid cert-dir %q: %w", certDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cert-dir is not a directory: %s", certDir)
	}
	if _, err := os.Stat(filepath.Join(certDir, "server.crt")); err != nil {
		return fmt.Errorf("missing cert file: %s", filepath.Join(certDir, "server.crt"))
	}
	if _, err := os.Stat(filepath.Join(certDir, "server.key")); err != nil {
		return fmt.Errorf("missing cert file: %s", filepath.Join(certDir, "server.key"))
	}
	return nil
}

func validateEgressRule(ruleRaw string) error {
	ruleRaw = strings.TrimSpace(ruleRaw)
	if ruleRaw == "" {
		return nil
	}
	entries := splitRuleEntries(ruleRaw)
	if len(entries) == 0 {
		return fmt.Errorf("egress-rule is empty")
	}
	for _, entry := range entries {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		if _, _, ok := parseRuleEntry(entry); !ok {
			return fmt.Errorf("invalid egress-rule entry: %s", entry)
		}
	}
	return nil
}

func parseCommaList(raw string) []string {
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func detectLocalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	set := make(map[string]struct{})
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if !ip.IsGlobalUnicast() {
				continue
			}
			ipText := ip.String()
			if !isPublicIP(ipText) {
				continue
			}
			set[ipText] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

var (
	cgnatPrefix  = netip.MustParsePrefix("100.64.0.0/10")
	benchmarkV4  = netip.MustParsePrefix("198.18.0.0/15")
	docPrefixV4A = netip.MustParsePrefix("192.0.2.0/24")
	docPrefixV4B = netip.MustParsePrefix("198.51.100.0/24")
	docPrefixV4C = netip.MustParsePrefix("203.0.113.0/24")
	docPrefixV6  = netip.MustParsePrefix("2001:db8::/32")
)

func isPublicIP(ipText string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipText))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is4() {
		if cgnatPrefix.Contains(addr) || benchmarkV4.Contains(addr) || docPrefixV4A.Contains(addr) || docPrefixV4B.Contains(addr) || docPrefixV4C.Contains(addr) {
			return false
		}
		return true
	}
	if docPrefixV6.Contains(addr) {
		return false
	}
	return true
}

func buildNodeURI(password, addr, sni, egressIP, egressRule string) string {
	var query []string
	if sni != "" {
		query = append(query, "sni="+uriEncode(sni))
	}
	if egressIP != "" {
		query = append(query, "egress-ip="+uriEncode(egressIP))
	}
	if egressRule != "" {
		query = append(query, "egress-rule="+uriEncode(egressRule))
	}
	uri := "anytls://" + uriEncode(password) + "@" + addr + "/"
	if len(query) > 0 {
		uri += "?" + strings.Join(query, "&")
	}
	return uri
}

func uriEncode(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '~' || c == '_' || c == '-' {
			b.WriteByte(c)
			continue
		}
		b.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return b.String()
}

func promptInput(reader *bufio.Reader, label, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", label, defaultValue)
	} else {
		fmt.Printf("%s: ", label)
	}
	s, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultValue, nil
	}
	return s, nil
}

func promptYesNo(reader *bufio.Reader, label string, defaultYes bool) (bool, error) {
	hint := "y/N"
	if defaultYes {
		hint = "Y/n"
	}
	for {
		fmt.Printf("%s [%s]: ", label, hint)
		s, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		answer := strings.ToLower(strings.TrimSpace(s))
		if answer == "" {
			return defaultYes, nil
		}
		if answer == "y" || answer == "yes" {
			return true, nil
		}
		if answer == "n" || answer == "no" {
			return false, nil
		}
		fmt.Println("请输入 y 或 n")
	}
}

func promptPassword(reader *bufio.Reader) (string, error) {
	fmt.Print("请输入 AnyTLS 密码: ")
	p1, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	fmt.Print("请再次输入密码: ")
	p2, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	p1 = strings.TrimSpace(p1)
	p2 = strings.TrimSpace(p2)
	if p1 == "" {
		return "", fmt.Errorf("密码不能为空")
	}
	if p1 != p2 {
		return "", fmt.Errorf("两次输入密码不一致")
	}
	return p1, nil
}
