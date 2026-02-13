package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func runClientMenu(ctx context.Context) error {
	reader := bufio.NewReader(os.Stdin)
	configPath, err := defaultClientConfigPath()
	if err != nil {
		return fmt.Errorf("resolve default config path failed: %w", err)
	}

	for {
		fmt.Println("AnyTLS Client 菜单")
		fmt.Printf("配置文件: %s\n", configPath)
		fmt.Println()
		fmt.Println("请选择操作:")
		fmt.Println("  1) 设置 Web 用户名密码")
		fmt.Println("  2) 清除 Web 用户名密码")
		fmt.Println("  3) 启动 API 模式")
		fmt.Println("  4) 停止 API 模式")
		fmt.Println("  5) 自动修复 MITM 证书权限")
		fmt.Println("  6) 退出")
		fmt.Print("输入序号 [1-6]: ")

		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		choice := strings.TrimSpace(line)

		switch choice {
		case "1":
			if err := ensureClientConfigExists(configPath); err != nil {
				fmt.Println("初始化配置失败:", err)
				fmt.Println()
				continue
			}
			if err := setWebCredential(configPath, reader); err != nil {
				fmt.Println("设置失败:", err)
			} else {
				fmt.Println("已保存 Web 用户名密码。")
			}
			fmt.Println()
		case "2":
			if err := ensureClientConfigExists(configPath); err != nil {
				fmt.Println("初始化配置失败:", err)
				fmt.Println()
				continue
			}
			if err := clearWebCredential(configPath); err != nil {
				fmt.Println("清除失败:", err)
			} else {
				fmt.Println("已清除 Web 用户名密码。")
			}
			fmt.Println()
		case "3":
			if err := ensureClientConfigExists(configPath); err != nil {
				return err
			}
			cfg, err := loadClientConfig(configPath)
			if err != nil {
				return err
			}
			enableTun := cfg.Tun != nil && cfg.Tun.Enabled
			needAdmin, reason := startupNeedsAdminPrivilege(cfg)
			if needAdmin && os.Geteuid() != 0 {
				fmt.Println()
				fmt.Printf("启动需要管理员权限（%s），正在申请系统授权。\n", reason)
				if err := runAPIModeWithPrivilege(configPath); err != nil {
					return err
				}
				return nil
			}
			if !enableTun {
				fmt.Println()
				fmt.Println("当前配置未启用私有网络(TUN)，将按普通模式启动。可在 Web 面板“基础配置”手动开启。")
			}
			runWithAPI(ctx, configPath, "127.0.0.1:1080", 5, "", "")
			return nil
		case "4":
			if err := ensureClientConfigExists(configPath); err != nil {
				fmt.Println("初始化配置失败:", err)
				fmt.Println()
				continue
			}
			if err := runCLI(configPath, "", "stop", "", "", "", clientNodeConfig{}); err != nil {
				fmt.Println("停止失败:", err)
			} else {
				fmt.Println("已发送停止请求。")
			}
			fmt.Println()
		case "5":
			if err := ensureClientConfigExists(configPath); err != nil {
				fmt.Println("初始化配置失败:", err)
				fmt.Println()
				continue
			}
			if err := autoFixMITMCertPermissions(configPath); err != nil {
				fmt.Println("修复失败:", err)
			} else {
				fmt.Println("MITM 证书权限修复完成。")
			}
			fmt.Println()
		case "6", "q", "quit", "exit":
			return nil
		default:
			fmt.Println("请输入 1-6")
			fmt.Println()
		}
	}
}

func tunNeedsAdminPrivilege() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

func startupNeedsAdminPrivilege(cfg *clientProfileConfig) (bool, string) {
	if cfg == nil {
		return false, ""
	}
	if cfg.Tun != nil && cfg.Tun.Enabled && tunNeedsAdminPrivilege() {
		return true, "启用私有网络(TUN)"
	}
	if cfg.MITM != nil && cfg.MITM.Enabled && mitmPermissionRequiresAdmin(cfg.MITM) {
		return true, "MITM 证书权限不足"
	}
	return false, ""
}

func mitmPermissionRequiresAdmin(cfg *clientMITMConfig) bool {
	if cfg == nil {
		return false
	}
	paths := []string{
		strings.TrimSpace(cfg.CACertPath),
		strings.TrimSpace(cfg.CAKeyPath),
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			// File not exists: no need admin here, runtime can create in normal case.
			if os.IsNotExist(err) {
				continue
			}
			return true
		}
		f, err := os.Open(p)
		if err != nil {
			return true
		}
		_, _ = io.CopyN(io.Discard, f, 1)
		_ = f.Close()
	}
	return false
}

func runAPIModeWithPrivilege(configPath string) error {
	if runtime.GOOS == "darwin" {
		if err := runAPIModeWithAppleScript(configPath); err == nil {
			logPath := filepath.Join(os.TempDir(), "anytls-client-api.log")
			if waitErr := waitAPIReady(configPath, 6*time.Second); waitErr == nil {
				fmt.Printf("已通过图形授权后台启动 AnyTLS Client API，日志: %s\n", logPath)
				return nil
			}
		}
	}
	return runAPIModeWithSudo(configPath)
}

func runAPIModeWithAppleScript(configPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable failed: %w", err)
	}
	logPath := filepath.Join(os.TempDir(), "anytls-client-api.log")
	command := fmt.Sprintf(
		"%s -mode api -config %s >> %s 2>&1 &",
		shellQuote(exe),
		shellQuote(configPath),
		shellQuote(logPath),
	)
	script := fmt.Sprintf("do shell script %q with administrator privileges", command)
	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			return fmt.Errorf("osascript run api failed: %w", err)
		}
		return fmt.Errorf("osascript run api failed: %w (%s)", err, msg)
	}
	return nil
}

func waitAPIReady(configPath string, timeout time.Duration) error {
	cfg, err := loadClientConfig(configPath)
	if err != nil {
		return err
	}
	addr := strings.TrimSpace(cfg.Control)
	if addr == "" {
		addr = defaultControlAddr
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := probeAPIHealth(addr); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("api did not become ready in time")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func runAPIModeWithSudo(configPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable failed: %w", err)
	}
	args := []string{"-E", exe, "-mode", "api", "-config", configPath}
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo run api failed: %w", err)
	}
	return nil
}

func autoFixMITMCertPermissions(configPath string) error {
	cfg, err := loadClientConfig(configPath)
	if err != nil {
		return err
	}
	if cfg.MITM == nil {
		cfg.MITM = &clientMITMConfig{}
	}
	if err := normalizeMITMConfig(cfg.MITM); err != nil {
		return err
	}
	certPath := strings.TrimSpace(cfg.MITM.CACertPath)
	keyPath := strings.TrimSpace(cfg.MITM.CAKeyPath)
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("mitm ca path is empty")
	}

	// First try best-effort local fix without privilege.
	_ = applyMITMPermissionFixLocal(certPath, keyPath)
	if !mitmPermissionRequiresAdmin(cfg.MITM) {
		return nil
	}

	if os.Geteuid() == 0 {
		if err := applyMITMPermissionFixAsRoot(certPath, keyPath); err != nil {
			return err
		}
	} else {
		fmt.Println("检测到需要管理员权限，正在申请系统授权修复证书权限。")
		if err := applyMITMPermissionFixWithPrivilege(certPath, keyPath); err != nil {
			return err
		}
	}

	if mitmPermissionRequiresAdmin(cfg.MITM) {
		return fmt.Errorf("证书权限仍不可读，请检查路径: %s / %s", certPath, keyPath)
	}
	return nil
}

func applyMITMPermissionFixLocal(certPath, keyPath string) error {
	_ = os.MkdirAll(filepath.Dir(certPath), 0700)
	_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
	_ = os.Chmod(filepath.Dir(certPath), 0700)
	_ = os.Chmod(filepath.Dir(keyPath), 0700)
	if _, err := os.Stat(certPath); err == nil {
		_ = os.Chmod(certPath, 0644)
	}
	if _, err := os.Stat(keyPath); err == nil {
		_ = os.Chmod(keyPath, 0600)
	}
	return nil
}

func applyMITMPermissionFixAsRoot(certPath, keyPath string) error {
	uid := os.Getuid()
	gid := os.Getgid()
	paths := []string{
		filepath.Dir(certPath),
		filepath.Dir(keyPath),
		certPath,
		keyPath,
	}
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = os.Chown(p, uid, gid)
	}
	_ = applyMITMPermissionFixLocal(certPath, keyPath)
	return nil
}

func applyMITMPermissionFixWithPrivilege(certPath, keyPath string) error {
	dir1 := filepath.Dir(certPath)
	dir2 := filepath.Dir(keyPath)
	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())
	script := buildMITMPermissionFixShell(dir1, dir2, certPath, keyPath, uid, gid)
	if runtime.GOOS == "darwin" {
		return runPrivilegedShellAppleScript(script)
	}
	return runPrivilegedShellSudo(script)
}

func buildMITMPermissionFixShell(dir1, dir2, certPath, keyPath, uid, gid string) string {
	parts := []string{
		"set -e",
		"mkdir -p " + shellQuote(dir1) + " " + shellQuote(dir2),
		"chown " + uid + ":" + gid + " " + shellQuote(dir1) + " " + shellQuote(dir2) + " 2>/dev/null || true",
		"chmod 700 " + shellQuote(dir1) + " " + shellQuote(dir2) + " 2>/dev/null || true",
		"if [ -f " + shellQuote(certPath) + " ]; then chown " + uid + ":" + gid + " " + shellQuote(certPath) + " 2>/dev/null || true; chmod 644 " + shellQuote(certPath) + "; fi",
		"if [ -f " + shellQuote(keyPath) + " ]; then chown " + uid + ":" + gid + " " + shellQuote(keyPath) + " 2>/dev/null || true; chmod 600 " + shellQuote(keyPath) + "; fi",
	}
	return strings.Join(parts, "; ")
}

func runPrivilegedShellAppleScript(shellCmd string) error {
	script := fmt.Sprintf("do shell script %q with administrator privileges", shellCmd)
	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			return fmt.Errorf("authorization command failed: %w", err)
		}
		return fmt.Errorf("authorization command failed: %w (%s)", err, msg)
	}
	return nil
}

func runPrivilegedShellSudo(shellCmd string) error {
	cmd := exec.Command("sudo", "/bin/sh", "-c", shellCmd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo permission fix failed: %w", err)
	}
	return nil
}

func ensureClientConfigExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	cfg := &clientProfileConfig{
		Listen:         "127.0.0.1:1080",
		MinIdleSession: 5,
		Control:        defaultControlAddr,
		DefaultNode:    "node-1",
		Nodes: []clientNodeConfig{
			{
				Name:     "node-1",
				Server:   "example.com:8443",
				Password: "change-me",
				SNI:      "example.com",
			},
		},
		Routing: &clientRoutingConfig{
			Enabled: false,
		},
		Tun: &clientTunConfig{
			Enabled:             false,
			Name:                "anytls0",
			MTU:                 1500,
			Address:             "198.18.0.1/15",
			AutoRoute:           true,
			DisableOtherProxies: runtime.GOOS == "darwin",
		},
		MITM: &clientMITMConfig{
			Enabled:    false,
			Listen:     "127.0.0.1:1090",
			CACertPath: "",
			CAKeyPath:  "",
		},
		Failover: &clientFailoverConfig{
			Enabled:          true,
			CheckIntervalSec: 15,
			FailureThreshold: 2,
			ProbeTarget:      defaultLatencyTarget,
			ProbeTimeoutMS:   2500,
		},
	}
	return saveClientConfig(path, cfg)
}

func setWebCredential(path string, reader *bufio.Reader) error {
	cfg, err := loadClientConfig(path)
	if err != nil {
		return err
	}
	fmt.Print("请输入 Web 用户名: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	fmt.Print("请输入 Web 密码: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	cfg.WebUsername = username
	cfg.WebPassword = password
	return saveClientConfig(path, cfg)
}

func clearWebCredential(path string) error {
	cfg, err := loadClientConfig(path)
	if err != nil {
		return err
	}
	cfg.WebUsername = ""
	cfg.WebPassword = ""
	return saveClientConfig(path, cfg)
}
