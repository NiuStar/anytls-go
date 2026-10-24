package main

import (
	"context"
	"encoding/base64"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Helper uses the actual CLI/parser without building a second executable.
func TestReviewConfigCLIHelper(t *testing.T) {
	if os.Getenv("REVIEW_CONFIG_HELPER") != "1" {
		return
	}
	i := 0
	for i < len(os.Args) && os.Args[i] != "--" {
		i++
	}
	args := os.Args[i+1:]
	if len(args) > 0 && args[0] == "config" {
		args = args[1:]
	}
	if err := runServerConfigCLI(args); err != nil {
		println(err.Error())
		os.Exit(12)
	}
	os.Exit(0)
}
func TestReviewInstallerLiteralSecrets(t *testing.T) {
	raw := strings.TrimSuffix(readInstallerScript(t), "main \"$@\"\n")
	for index, password := range []string{`$NAME`, `$(printf EXECUTED >&2)secret`, "`printf EXECUTED >&2`secret", `back\slash'"quote`} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			d := t.TempDir()
			config := filepath.Join(d, "server.env")
			if err := saveServerEnvConfig(config, serverEnvConfig{Listen: "127.0.0.1:9555", Password: password}); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(config)
			source := filepath.Join(d, "installer.sh")
			os.WriteFile(source, []byte(raw), 0600)
			exe, _ := os.Executable()
			helper := filepath.Join(d, "anytls-server")
			// This executable invokes the real Go CLI. Arguments are not evaluated.
			os.WriteFile(helper, []byte("#!/bin/bash\nexec \"$REVIEW_TEST_EXE\" -test.run '^TestReviewConfigCLIHelper$' -- \"$@\"\n"), 0700)
			for _, separate := range []bool{false, true} {
				if separate {
					os.WriteFile(filepath.Join(d, "server.password"), []byte(password+"\n"), 0600)
				}
				script := `set -euo pipefail
source "$1"
CONFIG_FILE="$2/server.env"; PASSWORD_FILE="$2/server.password"; INSTALL_BIN_PATH="$2/anytls-server"
DIRECT_PASSWORD=''; DIRECT_LISTEN=''; DIRECT_CERT_DIR=''
validate_direct_install_config
[[ "$DIRECT_PASSWORD" == "$EXPECTED_PASSWORD" && "$DIRECT_LISTEN" == '127.0.0.1:9555' ]]
INSTALL_WORK_DIR="$2/work"; START_SCRIPT="$INSTALL_WORK_DIR/start.sh"
write_start_script
`
				cmd := exec.Command("bash", "-c", script, "test", source, d)
				cmd.Env = append(os.Environ(), "REVIEW_CONFIG_HELPER=1", "REVIEW_TEST_EXE="+exe, "EXPECTED_PASSWORD="+password)
				out, err := cmd.CombinedOutput()
				if err != nil || strings.Contains(string(out), "EXECUTED") {
					t.Errorf("literal preflight separate=%v: %v %s", separate, err, out)
				}
				launcher, _ := os.ReadFile(filepath.Join(d, "work/start.sh"))
				// Redirect fixed production paths only; execute the generated launcher against a recording executable.
				launched := strings.ReplaceAll(string(launcher), "/etc/anytls", d)
				launched = strings.ReplaceAll(launched, "/usr/local/bin/anytls-server", filepath.Join(d, "record"))
				os.WriteFile(filepath.Join(d, "record"), []byte("#!/bin/bash\nprintf '%s\\0' \"$@\" > \"$REVIEW_CAPTURE\"\n"), 0700)
				os.WriteFile(filepath.Join(d, "launch.sh"), []byte(launched), 0700)
				cmd = exec.Command("bash", filepath.Join(d, "launch.sh"))
				cmd.Env = append(os.Environ(), "REVIEW_CAPTURE="+filepath.Join(d, "argv"))
				out, err = cmd.CombinedOutput()
				if err != nil || strings.Contains(string(out), "EXECUTED") {
					t.Errorf("literal launcher: %v %s", err, out)
				}
				argv, _ := os.ReadFile(filepath.Join(d, "argv"))
				if !strings.HasPrefix(string(argv), "config\x00run\x00--config\x00"+config+"\x00") {
					t.Errorf("launcher did not delegate to config parser: %q", argv)
				}
			}
			after, _ := os.ReadFile(config)
			if string(before) != string(after) {
				t.Fatal("preflight changed config")
			}
		})
	}
}
func TestReviewSubscriptionCanonicalPorts(t *testing.T) {
	c := subscriptionConfig{PublicIP: "8.8.8.8", Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), NodeName: "test"}
	for _, port := range []string{"09443", "+9443", "9443", "443", "65535", "1"} {
		c.Listen = ":" + port
		err := saveSubscriptionConfig(filepath.Join(t.TempDir(), "sub.json"), c)
		n, _ := strconv.Atoi(port)
		canonical := strconv.Itoa(n) == port
		if (err == nil) != canonical {
			t.Errorf("port %q accepted=%v", port, err == nil)
		}
		if err == nil {
			u, e := url.Parse(subscriptionURL(c, [32]byte{}))
			if e != nil {
				t.Fatal(e)
			}
			p := u.Port()
			if p != "" {
				n, e := strconv.Atoi(p)
				if e != nil || strconv.Itoa(n) != p {
					t.Errorf("noncanonical advertised authority: %s", u.Host)
				}
			}
		}
	}
}
func TestReviewSubscriptionNumericCollision(t *testing.T) {
	tc, c := subscriptionFixture(t)
	c.Listen = "127.0.0.1:443"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, s, err := startServerListeners(ctx, "127.0.0.1:0443", &c, tc, "test")
	if l != nil {
		l.Close()
	}
	if s != nil {
		s.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "ports must differ") {
		t.Errorf("numeric collision not rejected before bind: %v", err)
	}
	d := t.TempDir()
	config := filepath.Join(d, "server.env")
	saveServerEnvConfig(config, serverEnvConfig{Listen: "127.0.0.1:0443", Password: "test"})
	err = runServerConfigSubscription([]string{"--config", config, "--public-ip", "8.8.8.8", "--subscription-listen", ":443"})
	if err == nil || !strings.Contains(err.Error(), "ports must differ") {
		t.Errorf("CLI numeric collision accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d, "subscription.json")); !os.IsNotExist(err) {
		t.Fatal("collision persisted subscription")
	}
}
