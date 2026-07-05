package main

import (
	"os/exec"
	"runtime"
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
