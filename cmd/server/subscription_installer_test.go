package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubscriptionInstallerPrivateHandoffAndPersistence(t *testing.T) {
	raw := readInstallerScript(t)
	raw = strings.TrimSuffix(raw, "main \"$@\"\n")
	dir := t.TempDir()
	source := filepath.Join(dir, "source.sh")
	if err := os.WriteFile(source, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "anytls-server")
	if err := os.WriteFile(helper, []byte("#!/bin/bash\nexec \"$REVIEW_TEST_EXE\" -test.run '^TestReviewConfigCLIHelper$' -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	script := `
set -euo pipefail
source "$1"
INSTALL_BIN_PATH="$2/anytls-server"
CONFIG_FILE="$2/server.env"
PASSWORD_FILE="$2/server.password"
printf 'LISTEN="0.0.0.0:9555"\nPASSWORD="persist"\nCERT_DIR=""\n' > "$CONFIG_FILE"
printf 'persist\n' > "$PASSWORD_FILE"
DIRECT_PASSWORD=''
validate_direct_install_config
[[ "$DIRECT_LISTEN" == '0.0.0.0:9555' && "$DIRECT_PASSWORD" == persist ]]
parse_args --public-ip 8.8.8.8 --subscription-listen :9443
[[ "$DIRECT_PUBLIC_IP" == 8.8.8.8 && "$DIRECT_SUBSCRIPTION_LISTEN" == :9443 ]]
INSTALL_WORK_DIR="$2/work"
START_SCRIPT="$INSTALL_WORK_DIR/start.sh"
write_start_script
bash -n "$START_SCRIPT"
`
	cmd := exec.Command("bash", "-c", script, "test", source, dir)
	cmd.Env = append(os.Environ(), "REVIEW_CONFIG_HELPER=1", "REVIEW_TEST_EXE="+exe)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installer sanity: %v %s", err, out)
	}
	for _, s := range []string{"--subscription-config /etc/anytls/subscription.json", "--check-active", "systemctl restart \"$SERVICE_NAME\"", "--public-ip", "--subscription-listen"} {
		if !strings.Contains(raw, s) {
			t.Fatalf("missing %s", s)
		}
	}
}
