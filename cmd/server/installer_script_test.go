package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallerInfersListenPortFromAddr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("installer script is bash/linux specific")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for installer script regression test")
	}

	script := `
set -euo pipefail
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed 's/^main "\$@"$/: # main skipped for test/' ../../scripts/anytls-install_server.sh > "$tmp"
source "$tmp"
parse_args --install --password 'secret' --addr 0.0.0.0:55555
validate_direct_install_config >/tmp/anytls-installer-test-1.out
[[ "$DIRECT_LISTEN" == '0.0.0.0:55555' ]]
grep -F '已根据 --addr 推导监听地址: 0.0.0.0:55555' /tmp/anytls-installer-test-1.out >/dev/null
DIRECT_ACTION=''
DIRECT_LISTEN=''
DIRECT_PASSWORD=''
DIRECT_CERT_DIR=''
DIRECT_EXPORT_ADDR=''
parse_args --install --password 'secret' --port 44444 --addr example.com:55555
validate_direct_install_config >/tmp/anytls-installer-test-2.out
[[ "$DIRECT_LISTEN" == '0.0.0.0:44444' ]]
`
	cmd := exec.Command("bash", "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installer argument regression failed: %v\n%s", err, string(out))
	}
}

func TestInstallerSecurityHardening(t *testing.T) {
	script := readInstallerScript(t)
	if strings.Contains(script, `EnvironmentFile=$CONFIG_FILE`) {
		t.Fatalf("installer must not expand secrets through systemd EnvironmentFile")
	}
	for _, required := range []string{
		`--password-file "$PASSWORD_FILE"`,
		`sha256sum -c`,
		`NoNewPrivileges=true`,
		`ProtectSystem=strict`,
		`PrivateTmp=true`,
		`CapabilityBoundingSet=`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("installer missing security hardening %q", required)
		}
	}
}

func TestInstallerDoesNotPassPasswordOnCommandLine(t *testing.T) {
	script := readInstallerScript(t)
	for _, forbidden := range []string{
		`args=(-l "$LISTEN" -p "$PASSWORD")`,
		`--password "$password"`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not pass password in process arguments: %q", forbidden)
		}
	}
}

func readInstallerScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "scripts", "anytls-install_server.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read installer script failed: %v", err)
	}
	return string(raw)
}
