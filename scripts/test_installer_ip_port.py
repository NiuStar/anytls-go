#!/usr/bin/env python3
"""Isolated Bash installer regression tests; no downloads or service operations."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("ANYTLS_INSTALLER_TEST_SOURCE", ROOT / "scripts/anytls-install_server.sh"))


class InstallerEndpointTests(unittest.TestCase):
    def run_shell(self, body, data="", tty=False, success=True):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "installer.sh"
            source.write_text(SCRIPT.read_text().removesuffix('main "$@"\n'))
            prefix = '''source "$1"
CONFIG_FILE="$2/server.env"
PASSWORD_FILE="$2/server.password"
SUBSCRIPTION_CONFIG="$2/subscription.json"
INSTALL_BIN_PATH="$2/missing"
DIRECT_PASSWORD=fixture
'''
            if tty:
                prefix += 'installer_interactive() { return 0; }\n'
            proc = subprocess.run(["bash", "-c", prefix + body, "test", str(source), d], input=data.encode("utf-8"), capture_output=True, timeout=10)
            # Old Bash may emit a partial multibyte read prompt on macOS.
            # Preserve undecodable bytes visibly; never lose the child rc/assertions.
            proc.stdout = proc.stdout.decode("utf-8", errors="backslashreplace")
            proc.stderr = proc.stderr.decode("utf-8", errors="backslashreplace")
            if success:
                self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            else:
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
            return proc

    def test_multiple_ips_ipv6_and_port(self):
        self.run_shell('''collect_local_ips() { printf '8.8.8.8\\n2606:4700:4700::1111\\n'; }
curl() { return 1; }
validate_direct_install_config
select_install_endpoint true
[[ "$DIRECT_PUBLIC_IP" == 2606:4700:4700::1111 ]]
[[ "$DIRECT_LISTEN" == '[::]:9555' ]]
[[ "$DIRECT_EXPORT_ADDR" == '[2606:4700:4700::1111]:9555' ]]
''', "1\n9555\n", tty=True)

    def test_invalid_choice_manual_private_and_port_reprompt(self):
        p = self.run_shell('''collect_local_ips() { echo 8.8.8.8; }
curl() { return 1; }
validate_direct_install_config
select_install_endpoint true
[[ "$DIRECT_PUBLIC_IP" == 1.1.1.1 && "$DIRECT_LISTEN" == 0.0.0.0:65535 ]]
''', "99\n0\n192.168.1.2\n1.1.1.1\n0\n65536\n080\n443\n65535\n", tty=True)
        self.assertIn("1-65535", p.stderr)

    def test_explicit_flags_never_read_input(self):
        self.run_shell('''parse_args --install --public-ip 8.8.8.8 --port 9555
validate_direct_install_config
select_install_endpoint false
[[ "$DIRECT_LISTEN" == 0.0.0.0:9555 && "$DIRECT_EXPORT_ADDR" == 8.8.8.8:9555 ]]
''', tty=True)

    def test_explicit_ipv6_port_uses_ipv6_listener(self):
        self.run_shell('''parse_args --install --public-ip 2606:4700:4700::1111 --port 9555
validate_direct_install_config
select_install_endpoint false
[[ "$DIRECT_LISTEN" == '[::]:9555' && "$DIRECT_EXPORT_ADDR" == '[2606:4700:4700::1111]:9555' ]]
''')

    def test_explicit_bind_is_not_overridden(self):
        self.run_shell('''parse_args --install --public-ip 2606:4700:4700::1111 --listen 0.0.0.0:9555
validate_direct_install_config
select_install_endpoint false
[[ "$DIRECT_LISTEN" == 0.0.0.0:9555 ]]
''')

    def test_non_tty_keeps_bounded_go_discovery_and_default(self):
        self.run_shell('''validate_direct_install_config
select_install_endpoint true
[[ -z "$DIRECT_PUBLIC_IP" && "$DIRECT_LISTEN" == 0.0.0.0:8443 ]]
''')

    def test_public_ip_validation(self):
        self.run_shell('''for ip in 8.8.8.8 2606:4700:4700::1111 2001:4860:4860::8888; do public_ip_tool validate "$ip"; done
for ip in 127.0.0.1 192.168.1.2 100.64.0.1 203.0.113.1 240.0.0.1 :: ::1 ff02::1 ::ffff:8.8.8.8 2001:db8::1 2002::1 3fff::1 2606:invalid 08.8.8.8; do
 if public_ip_tool validate "$ip"; then exit 9; fi
done
''')

    def test_ipv6_canonical_contract(self):
        self.run_shell('''for ip in 2606:4700:4700::1111 2606::1:0:0:1 2606:1:0:1:: 2606:1:2:3:4:5:6:0; do public_ip_tool validate "$ip"; done
for ip in 2606:4700:4700:0:0:0:0:1111 2606:0:0:1::1:1 2606:1::1:0:0:0 2606:1:2:3:4:5:6::; do
 if public_ip_tool validate "$ip"; then exit 9; fi
done
''')

    def test_legacy_addr_and_explicit_port(self):
        self.run_shell('''parse_args --install --addr 0.0.0.0:55555
validate_direct_install_config
[[ "$DIRECT_LISTEN" == 0.0.0.0:55555 ]]
DIRECT_LISTEN=''
parse_args --port 44444
validate_direct_install_config
[[ "$DIRECT_LISTEN" == 0.0.0.0:44444 ]]
''')

    def test_menu_install_uses_subscription_flow(self):
        self.run_shell('''prompt_input() { return 1; }
install_action_direct() { echo subscription-flow; }
[[ "$(install_action)" == subscription-flow ]]
''')

    def test_conflict_rejected_before_write(self):
        self.run_shell('''parse_args --public-ip 8.8.8.8 --port 443
validate_direct_install_config
select_install_endpoint false
''', success=False)

    def test_existing_subscription_preserved_as_default(self):
        self.run_shell('''printf '%s' '{"public_ip":"1.1.1.1","listen":":9443","token":"fixture"}' > "$SUBSCRIPTION_CONFIG"
collect_local_ips() { echo 8.8.8.8; }
curl() { return 1; }
DIRECT_LISTEN=0.0.0.0:9555
select_install_endpoint true
[[ "$DIRECT_PUBLIC_IP" == 1.1.1.1 && "$DIRECT_LISTEN" == 0.0.0.0:9555 ]]
[[ "$(command python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$SUBSCRIPTION_CONFIG")" == fixture ]]
''', "\n\n", tty=True)

    def test_actual_install_flow_with_download_and_systemd_mocked(self):
        self.run_shell('''collect_local_ips() { echo 8.8.8.8; }
curl() { return 1; }
download_latest_binary() { :; }
# Explicitly replace writes and service control; execute the real orchestration.
write_config() { [[ "$1" == 0.0.0.0:9555 && "$2" == fixture ]]; }
write_start_script() { :; }
write_systemd_service() { :; }
systemctl() { printf '%s\\n' "$*" >> "$CONFIG_FILE.events"; }
INSTALL_BIN_PATH="$2/server"
printf '%s\\n' '#!/usr/bin/env bash' 'printf "%s\\n" "$*" >> "${0}.events"' > "$INSTALL_BIN_PATH"
chmod +x "$INSTALL_BIN_PATH"
install_action
[[ "$DIRECT_PUBLIC_IP" == 8.8.8.8 && "$DIRECT_EXPORT_ADDR" == 8.8.8.8:9555 ]]
grep -F -- '--public-ip 8.8.8.8' "$INSTALL_BIN_PATH.events"
grep -F -- '--check-active' "$INSTALL_BIN_PATH.events"
grep -F 'restart anytls-server' "$CONFIG_FILE.events"
''', "1\n9555\n", tty=True)

    def test_discovery_filters_deduplicates_and_uses_bounded_families(self):
        self.run_shell('''collect_local_ips() { printf '192.168.0.1\\n8.8.8.8\\n'; }
curl() {
 [[ "$*" == *'--max-time 5'* && "$*" == *'--connect-timeout 3'* && "$*" == *'--noproxy'* ]]
 case "$1" in -4) printf 8.8.8.8;; -6) printf 2606:4700:4700::1111;; *) exit 8;; esac
}
[[ "$(public_ip_tool candidates)" == $'2606:4700:4700::1111\\n8.8.8.8' ]]
''')

    def test_failed_discovery_requires_manual_public_ip(self):
        self.run_shell('''collect_local_ips() { :; }
curl() { return 1; }
validate_direct_install_config
select_install_endpoint true
[[ "$DIRECT_PUBLIC_IP" == 1.1.1.1 && "$DIRECT_LISTEN" == 0.0.0.0:9555 ]]
''', "0\n1.1.1.1\n9555\n", tty=True)

    def test_existing_config_parser_migration_and_noop_bytes(self):
        self.run_shell('''printf '%s\\n' 'PASSWORD="$(touch SHOULD_NOT_EXIST)"' '# retained comment' > "$CONFIG_FILE"
printf 'fixture\\n' > "$PASSWORD_FILE"
cp "$CONFIG_FILE" "$CONFIG_FILE.before"
INSTALL_BIN_PATH="$2/server"
printf '%s\\n' '#!/usr/bin/env bash' 'case "${*: -1}" in listen) echo 0.0.0.0:9555;; password) echo fixture;; cert-dir) echo "";; *) exit 8;; esac' > "$INSTALL_BIN_PATH"
chmod +x "$INSTALL_BIN_PATH"
DIRECT_PASSWORD=''
validate_direct_install_config
[[ "$DIRECT_PASSWORD" == fixture && "$DIRECT_LISTEN" == 0.0.0.0:9555 ]]
write_config "$DIRECT_LISTEN" "$DIRECT_PASSWORD" "$DIRECT_CERT_DIR"
cmp "$CONFIG_FILE" "$CONFIG_FILE.before"
[[ ! -e SHOULD_NOT_EXIST ]]
''')


if __name__ == "__main__":
    unittest.main(verbosity=2)
