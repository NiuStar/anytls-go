#!/usr/bin/env bash
set -euo pipefail

REPO_DEFAULT="NiuStar/anytls-go"
INSTALL_BIN_DIR="/usr/local/bin"
INSTALL_BIN_PATH="$INSTALL_BIN_DIR/anytls-server"
INSTALL_WORK_DIR="/opt/anytls"
CONFIG_DIR="/etc/anytls"
CONFIG_FILE="$CONFIG_DIR/server.env"
EXPORT_LAST_FILE="$CONFIG_DIR/export_last.env"
START_SCRIPT="$INSTALL_WORK_DIR/start.sh"
SERVICE_NAME="anytls-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_PORT="8443"
MENU_CHOICE=""
LISTEN_VALUE=""
PASSWORD_VALUE=""
CERT_DIR_VALUE=""
GITHUB_MIRROR_PREFIX="${ANYTLS_GITHUB_MIRROR_PREFIX:-}"
GITHUB_MIRROR_PROMPTED="false"
DIRECT_ACTION=""
DIRECT_LISTEN=""
DIRECT_PASSWORD="${ANYTLS_PASSWORD:-}"
DIRECT_CERT_DIR=""
DIRECT_EXPORT_ADDR=""

fail() {
	echo "Error: $*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

install_executable() {
	local src="$1"
	local dst="$2"
	if command -v install >/dev/null 2>&1; then
		install -m 0755 "$src" "$dst"
		return
	fi
	cp "$src" "$dst"
	chmod 0755 "$dst"
}

password_has_control_chars() {
	local text="$1"
	if printf '%s' "$text" | LC_ALL=C grep -q '[[:cntrl:]]'; then
		return 0
	fi
	return 1
}

hosts_has_name() {
	local target_name="$1"
	[[ -f /etc/hosts ]] || return 1
	awk -v target="$target_name" '
		!/^[[:space:]]*#/ {
			for (i = 2; i <= NF; i++) {
				if ($i == target) {
					found = 1
				}
			}
		}
		END { exit(found ? 0 : 1) }
	' /etc/hosts
}

repair_hostname_resolution_if_needed() {
	local current_host=""
	local do_fix=""
	local tmp_file=""

	current_host="$(hostname 2>/dev/null || true)"
	[[ -n "$current_host" ]] || return 0

	if command -v getent >/dev/null 2>&1; then
		if getent hosts "$current_host" >/dev/null 2>&1; then
			return 0
		fi
	elif hosts_has_name "$current_host"; then
		return 0
	fi

	echo
	echo "检测到当前主机名无法解析: $current_host"
	echo "这会导致 sudo 提示: unable to resolve host。"
	do_fix="$(prompt_yes_no "是否自动修复 /etc/hosts（推荐）？" "y")"
	[[ "$do_fix" == "true" ]] || {
		echo "已跳过自动修复。"
		return 0
	}

	[[ -f /etc/hosts ]] || touch /etc/hosts
	tmp_file="$(mktemp)"
	cat /etc/hosts >"$tmp_file"
	printf '\n127.0.1.1 %s\n' "$current_host" >>"$tmp_file"

	if ! hosts_has_name "$current_host"; then
		mv "$tmp_file" /etc/hosts
	else
		rm -f "$tmp_file"
	fi

	if command -v getent >/dev/null 2>&1; then
		if getent hosts "$current_host" >/dev/null 2>&1; then
			echo "已修复主机名解析。"
		else
			echo "已尝试修复 /etc/hosts，但仍无法解析主机名: $current_host"
			echo "请手动检查 /etc/hosts。"
		fi
	else
		echo "已更新 /etc/hosts，请重新执行 sudo 验证。"
	fi
}

systemd_service_exists() {
	local load_state=""
	local unit=""
	[[ -f "$SERVICE_FILE" ]] && return 0
	for unit in "$SERVICE_NAME" "${SERVICE_NAME}.service"; do
		load_state="$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)"
		if [[ -n "$load_state" && "$load_state" != "not-found" ]]; then
			return 0
		fi
	done
	return 1
}

prompt_input() {
	local label="$1"
	local default_value="${2:-}"
	local input=""
	if [[ -n "$default_value" ]]; then
		read -r -p "$label [$default_value]: " input
		if [[ -z "$input" ]]; then
			echo "$default_value"
		else
			echo "$input"
		fi
	else
		read -r -p "$label: " input
		echo "$input"
	fi
}

usage() {
	cat <<'EOF'
Usage:
  anytls-install_server.sh
  anytls-install_server.sh --install --password <password> [--listen 0.0.0.0:8443] [--addr YOUR_SERVER_IP:8443]
  ANYTLS_PASSWORD=<password> anytls-install_server.sh --install [--addr YOUR_SERVER_IP:8443]

Options:
      --install          Non-interactive one-click install/update systemd service
      --listen <addr>    Server listen address, default 0.0.0.0:8443
      --port <port>      Shortcut for --listen 0.0.0.0:<port>
      --password <text>  AnyTLS password; if omitted in --install mode, a random one is generated
      --cert-dir <dir>   Use existing server.crt/server.key directory instead of auto-generated cert
      --addr <addr>      Client-facing export address, for example 1.2.3.4:8443
  -p, --proxy <url>      GitHub mirror prefix (e.g. https://ghfast.top/)
  -h, --help             Show this help
EOF
}

normalize_github_mirror_prefix() {
	local raw="$1"
	local trimmed=""
	trimmed="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
	if [[ -z "$trimmed" ]]; then
		echo ""
		return
	fi
	[[ "$trimmed" =~ ^https?:// ]] || fail "invalid GitHub mirror prefix: $trimmed"
	trimmed="${trimmed%/}/"
	echo "$trimmed"
}

with_github_mirror() {
	local raw_url="$1"
	if [[ "$raw_url" == https://api.github.com/* || "$raw_url" == http://api.github.com/* ]]; then
		echo "$raw_url"
		return
	fi
	if [[ -z "$GITHUB_MIRROR_PREFIX" ]]; then
		echo "$raw_url"
		return
	fi
	echo "${GITHUB_MIRROR_PREFIX}${raw_url}"
}

prompt_github_mirror_once() {
	if [[ "$GITHUB_MIRROR_PROMPTED" == "true" ]]; then
		return
	fi
	GITHUB_MIRROR_PROMPTED="true"
	if [[ -z "$GITHUB_MIRROR_PREFIX" && -t 0 ]]; then
		GITHUB_MIRROR_PREFIX="$(prompt_input "GitHub 加速前缀（如 https://ghfast.top/，留空直连）" "")"
		GITHUB_MIRROR_PREFIX="$(normalize_github_mirror_prefix "$GITHUB_MIRROR_PREFIX")"
	fi
	if [[ -n "$GITHUB_MIRROR_PREFIX" ]]; then
		echo "GitHub 加速前缀已启用: $GITHUB_MIRROR_PREFIX"
	fi
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--install)
			DIRECT_ACTION="install"
			shift
			;;
		--listen)
			[[ $# -ge 2 ]] || fail "$1 requires a value"
			DIRECT_LISTEN="$2"
			shift 2
			;;
		--listen=*)
			DIRECT_LISTEN="${1#*=}"
			shift
			;;
		--port)
			[[ $# -ge 2 ]] || fail "$1 requires a value"
			DIRECT_LISTEN="0.0.0.0:$2"
			shift 2
			;;
		--port=*)
			DIRECT_LISTEN="0.0.0.0:${1#*=}"
			shift
			;;
		--password)
			[[ $# -ge 2 ]] || fail "$1 requires a value"
			DIRECT_PASSWORD="$2"
			shift 2
			;;
		--password=*)
			DIRECT_PASSWORD="${1#*=}"
			shift
			;;
		--cert-dir)
			[[ $# -ge 2 ]] || fail "$1 requires a value"
			DIRECT_CERT_DIR="$2"
			shift 2
			;;
		--cert-dir=*)
			DIRECT_CERT_DIR="${1#*=}"
			shift
			;;
		--addr)
			[[ $# -ge 2 ]] || fail "$1 requires a value"
			DIRECT_EXPORT_ADDR="$2"
			shift 2
			;;
		--addr=*)
			DIRECT_EXPORT_ADDR="${1#*=}"
			shift
			;;
		-p | --proxy)
			[[ $# -ge 2 ]] || fail "$1 requires a value"
			GITHUB_MIRROR_PREFIX="$2"
			shift 2
			;;
		--proxy=*)
			GITHUB_MIRROR_PREFIX="${1#*=}"
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			fail "unknown argument: $1"
			;;
		esac
	done
}

prompt_yes_no() {
	local label="$1"
	local default_value="${2:-y}"
	local hint="y/N"
	local answer=""
	if [[ "$default_value" == "y" ]]; then
		hint="Y/n"
	fi
	while true; do
		read -r -p "$label [$hint]: " answer
		answer="$(echo "$answer" | tr '[:upper:]' '[:lower:]')"
		if [[ -z "$answer" ]]; then
			answer="$default_value"
		fi
		case "$answer" in
		y | yes)
			echo "true"
			return
			;;
		n | no)
			echo "false"
			return
			;;
		*)
			echo "Please answer y or n." >&2
			;;
		esac
	done
}

prompt_menu_choice() {
	local choice=""
	while true; do
		echo
		echo "请选择操作:"
		echo "  1) 安装"
		echo "  2) 卸载"
		echo "  3) 更新版本"
		echo "  4) 修改配置"
		echo "  5) 导出节点配置"
		echo "  6) 退出"
		read -r -p "输入序号 [1-6]: " choice
		case "$choice" in
		1 | 2 | 3 | 4 | 5 | 6)
			MENU_CHOICE="$choice"
			return
			;;
		*)
			echo "请输入 1-6。" >&2
			;;
		esac
	done
}

prompt_password() {
	local p1=""
	local p2=""
	while true; do
		read -r -s -p "请输入 AnyTLS 密码: " p1
		echo
		read -r -s -p "请再次输入密码: " p2
		echo
		[[ -n "$p1" ]] || {
			echo "密码不能为空。" >&2
			continue
		}
		[[ "$p1" == "$p2" ]] || {
			echo "两次输入不一致，请重试。" >&2
			continue
		}
		echo "$p1"
		return
	done
}

port_from_listen() {
	local listen="$1"
	if [[ "$listen" =~ :([0-9]+)$ ]]; then
		echo "${BASH_REMATCH[1]}"
	else
		echo "$DEFAULT_PORT"
	fi
}

urlencode() {
	local s="$1"
	local encoded=""
	local i c hex
	for ((i = 0; i < ${#s}; i++)); do
		c="${s:i:1}"
		case "$c" in
		[a-zA-Z0-9.~_-])
			encoded+="$c"
			;;
		*)
			printf -v hex '%%%02X' "'$c"
			encoded+="$hex"
			;;
		esac
	done
	echo "$encoded"
}

host_from_addr() {
	local addr="$1"
	local host="$addr"
	if [[ "$addr" == \[*\]:* ]]; then
		host="${addr%%]*}"
		host="${host#[}"
	else
		host="${addr%:*}"
	fi
	echo "$host"
}

format_host_port() {
	local host="$1"
	local port="$2"
	if [[ "$host" == *:* && "$host" != \[*\] ]]; then
		echo "[$host]:$port"
	else
		echo "${host}:$port"
	fi
}

is_public_ipv4() {
	local ip="$1"
	local a b c d
	IFS='.' read -r a b c d <<<"$ip"
	[[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
	((a <= 255 && b <= 255 && c <= 255 && d <= 255)) || return 1
	((a == 10)) && return 1
	((a == 127)) && return 1
	((a == 0)) && return 1
	((a == 169 && b == 254)) && return 1
	((a == 172 && b >= 16 && b <= 31)) && return 1
	((a == 192 && b == 168)) && return 1
	((a == 100 && b >= 64 && b <= 127)) && return 1
	((a == 198 && (b == 18 || b == 19))) && return 1
	((a == 192 && b == 0 && c == 2)) && return 1
	((a == 198 && b == 51 && c == 100)) && return 1
	((a == 203 && b == 0 && c == 113)) && return 1
	((a >= 224)) && return 1
	return 0
}

is_public_ip() {
	local ip="${1,,}"
	if [[ "$ip" == *:* ]]; then
		[[ "$ip" == "::1" ]] && return 1
		[[ "$ip" == fc* || "$ip" == fd* ]] && return 1
		[[ "$ip" == fe8* || "$ip" == fe9* || "$ip" == fea* || "$ip" == feb* ]] && return 1
		[[ "$ip" == ff* ]] && return 1
		[[ "$ip" == 2001:db8* ]] && return 1
		return 0
	fi
	is_public_ipv4 "$ip"
}

collect_local_ips() {
	local line=""
	local ip=""
	local -A seen=()
	local -a ips=()

	if command -v ip >/dev/null 2>&1; then
		while IFS= read -r line; do
			ip="${line%%/*}"
			[[ -n "$ip" ]] || continue
			[[ "$ip" == "127.0.0.1" ]] && continue
			[[ "$ip" == "::1" ]] && continue
			[[ "$ip" == fe80:* ]] && continue
			is_public_ip "$ip" || continue
			if [[ -z "${seen[$ip]+x}" ]]; then
				seen["$ip"]=1
				ips+=("$ip")
			fi
		done < <(ip -o addr show up scope global | awk '{print $4}')
	elif command -v hostname >/dev/null 2>&1; then
		for ip in $(hostname -I 2>/dev/null || true); do
			[[ -n "$ip" ]] || continue
			[[ "$ip" == "127.0.0.1" ]] && continue
			is_public_ip "$ip" || continue
			if [[ -z "${seen[$ip]+x}" ]]; then
				seen["$ip"]=1
				ips+=("$ip")
			fi
		done
	fi

	printf '%s\n' "${ips[@]}"
}

detect_arch() {
	local m
	m="$(uname -m)"
	case "$m" in
	x86_64 | amd64)
		echo "amd64"
		;;
	aarch64 | arm64)
		echo "arm64"
		;;
	i386 | i686)
		echo "386"
		;;
	armv7l | armv7)
		echo "arm_v7"
		;;
	*)
		fail "unsupported architecture: $m"
		;;
	esac
}

extract_latest_release_tag() {
	local repo="$1"
	local json="$2"
	local tag
	tag="$(printf '%s\n' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
	[[ -n "$tag" ]] || fail "failed to parse latest tag from GitHub API for $repo"
	echo "$tag"
}

pick_asset_url() {
	local release_json="$1"
	local tag="$2"
	local arch="$3"
	local version_no_v="${tag#v}"
	local line=""

	while IFS= read -r line; do
		case "$line" in
		*"anytls-server_${version_no_v}_linux_${arch}.tar.gz" | *"anytls-server_${tag}_linux_${arch}.tar.gz" | \
			*"anytls-server_${version_no_v}_linux_${arch}.zip" | *"anytls-server_${tag}_linux_${arch}.zip" | \
			*"anytls_${version_no_v}_linux_${arch}.tar.gz" | *"anytls_${tag}_linux_${arch}.tar.gz" | \
			*"anytls_${version_no_v}_linux_${arch}.zip" | *"anytls_${tag}_linux_${arch}.zip")
			echo "$line"
			return
			;;
		esac
	done < <(printf '%s\n' "$release_json" | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

	fail "no release asset found for linux/${arch}"
}

install_binary() {
	local archive_file="$1"
	local tmp_dir="$2"
	local extracted_bin=""
	mkdir -p "$tmp_dir"

	case "$archive_file" in
	*.tar.gz)
		tar -xzf "$archive_file" -C "$tmp_dir"
		;;
	*.zip)
		unzip -q "$archive_file" -d "$tmp_dir"
		;;
	*)
		fail "unsupported archive: $archive_file"
		;;
	esac

	extracted_bin="$(find "$tmp_dir" -type f -name anytls-server | head -n1)"
	[[ -n "$extracted_bin" ]] || fail "anytls-server not found in archive"

	install_executable "$extracted_bin" "$INSTALL_BIN_PATH"
}

write_config() {
	local listen_addr="$1"
	local password="$2"
	local cert_dir="$3"
	local args=()

	mkdir -p "$CONFIG_DIR"
	if [[ -x "$INSTALL_BIN_PATH" ]]; then
		args=(config edit --config "$CONFIG_FILE" --listen "$listen_addr" --password "$password" --yes)
		if [[ -n "$cert_dir" ]]; then
			args+=(--cert-dir "$cert_dir")
		else
			args+=(--auto-cert)
		fi
		"$INSTALL_BIN_PATH" "${args[@]}"
		return
	fi

	umask 077
	{
		printf 'LISTEN=%q\n' "$listen_addr"
		printf 'PASSWORD=%q\n' "$password"
		printf 'CERT_DIR=%q\n' "$cert_dir"
	} >"$CONFIG_FILE"
}
write_start_script() {
	mkdir -p "$INSTALL_WORK_DIR"
	cat >"$START_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

source /etc/anytls/server.env

args=(-l "$LISTEN" -p "$PASSWORD")
if [[ -n "${CERT_DIR:-}" ]]; then
	args+=(--cert-dir "$CERT_DIR")
fi

exec /usr/local/bin/anytls-server "${args[@]}"
EOF
	chmod 0755 "$START_SCRIPT"
}

write_systemd_service() {
	cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=AnyTLS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$START_SCRIPT
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

download_latest_binary() {
	local repo="$REPO_DEFAULT"
	local arch=""
	local latest_json=""
	local latest_tag=""
	local asset_url=""
	local tmp_dir=""
	local archive_file=""

	echo
	echo "开始下载安装最新版本..."
	prompt_github_mirror_once
	arch="$(detect_arch)"
	latest_json="$(curl -fsSL "$(with_github_mirror "https://api.github.com/repos/${repo}/releases/latest")")"
	latest_tag="$(extract_latest_release_tag "$repo" "$latest_json")"
	asset_url="$(pick_asset_url "$latest_json" "$latest_tag" "$arch")"
	echo "Latest tag: $latest_tag"
	echo "Asset: $asset_url"

	tmp_dir="$(mktemp -d)"

	archive_file="$tmp_dir/anytls-release-archive"
	case "$asset_url" in
	*.tar.gz)
		archive_file="${archive_file}.tar.gz"
		;;
	*.zip)
		archive_file="${archive_file}.zip"
		;;
	*)
		fail "unsupported asset type: $asset_url"
		;;
	esac

	curl -fL "$(with_github_mirror "$asset_url")" -o "$archive_file"
	install_binary "$archive_file" "$tmp_dir/extract"
	rm -rf "$tmp_dir"
}

collect_install_or_modify_config() {
	local default_port="$1"
	local default_password="$2"
	local default_cert_dir="$3"
	local port=""
	local auto_cert=""
	local change_password=""

	port="$(prompt_input "监听端口" "$default_port")"
	[[ "$port" =~ ^[0-9]+$ ]] || fail "端口必须是数字"
	((port >= 1 && port <= 65535)) || fail "端口必须在 1-65535 之间"
	LISTEN_VALUE="0.0.0.0:${port}"

	if [[ -n "$default_password" ]]; then
		change_password="$(prompt_yes_no "是否修改密码？" "n")"
		if [[ "$change_password" == "true" ]]; then
			PASSWORD_VALUE="$(prompt_password)"
		else
			PASSWORD_VALUE="$default_password"
		fi
	else
		PASSWORD_VALUE="$(prompt_password)"
	fi

	echo
	echo "证书选项:"
	echo "  1) 自动生成证书（不需要额外文件）"
	echo "  2) 使用已有证书目录"
	echo "     命名要求: 目录内必须包含 server.crt 和 server.key"
	if [[ -n "$default_cert_dir" ]]; then
		auto_cert="$(prompt_yes_no "是否自动生成证书？" "n")"
	else
		auto_cert="$(prompt_yes_no "是否自动生成证书？" "y")"
	fi

	if [[ "$auto_cert" == "true" ]]; then
		CERT_DIR_VALUE=""
	else
		CERT_DIR_VALUE="$(prompt_input "请输入证书目录（绝对路径）" "$default_cert_dir")"
		[[ -n "$CERT_DIR_VALUE" ]] || fail "证书目录不能为空"
		[[ -d "$CERT_DIR_VALUE" ]] || fail "证书目录不存在: $CERT_DIR_VALUE"
		[[ -f "$CERT_DIR_VALUE/server.crt" ]] || fail "缺少证书文件: $CERT_DIR_VALUE/server.crt"
		[[ -f "$CERT_DIR_VALUE/server.key" ]] || fail "缺少私钥文件: $CERT_DIR_VALUE/server.key"
	fi
}


generate_random_password() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -base64 24 | tr -d '\n'
		return
	fi
	LC_ALL=C tr -dc 'A-Za-z0-9._~-' </dev/urandom | head -c 32
}

validate_direct_install_config() {
	local port=""
	[[ -n "$DIRECT_LISTEN" ]] || DIRECT_LISTEN="0.0.0.0:${DEFAULT_PORT}"
	port="$(port_from_listen "$DIRECT_LISTEN")"
	[[ "$port" =~ ^[0-9]+$ ]] || fail "listen port must be numeric: $DIRECT_LISTEN"
	((port >= 1 && port <= 65535)) || fail "listen port must be 1-65535: $port"
	if [[ -z "$DIRECT_PASSWORD" ]]; then
		DIRECT_PASSWORD="$(generate_random_password)"
		echo "已生成随机 AnyTLS 密码。"
	fi
	[[ -n "$DIRECT_PASSWORD" ]] || fail "password is required"
	if password_has_control_chars "$DIRECT_PASSWORD"; then
		fail "password contains control characters (for example newline/tab)"
	fi
	if [[ -n "$DIRECT_CERT_DIR" ]]; then
		[[ -d "$DIRECT_CERT_DIR" ]] || fail "cert dir does not exist: $DIRECT_CERT_DIR"
		[[ -f "$DIRECT_CERT_DIR/server.crt" ]] || fail "missing cert file: $DIRECT_CERT_DIR/server.crt"
		[[ -f "$DIRECT_CERT_DIR/server.key" ]] || fail "missing key file: $DIRECT_CERT_DIR/server.key"
	fi
}

install_action_direct() {
	local export_args=()
	echo "AnyTLS Server 非交互一键安装"
	validate_direct_install_config
	download_latest_binary
	write_config "$DIRECT_LISTEN" "$DIRECT_PASSWORD" "$DIRECT_CERT_DIR"
	write_start_script
	write_systemd_service

	systemctl daemon-reload
	systemctl enable --now "$SERVICE_NAME"

	echo
	echo "安装完成并已启动: $SERVICE_NAME"
	echo "监听地址: $DIRECT_LISTEN"
	if [[ -n "$DIRECT_CERT_DIR" ]]; then
		echo "证书目录: $DIRECT_CERT_DIR (server.crt / server.key)"
	else
		echo "证书模式: 自动生成 + cert-sha256 指纹校验"
	fi
	systemctl --no-pager --full status "$SERVICE_NAME" || true

	echo
	echo "================ 客户端导入信息 ================"
	export_args=(config export --config "$CONFIG_FILE" --yes)
	if [[ -n "$DIRECT_EXPORT_ADDR" ]]; then
		export_args+=(--addr "$DIRECT_EXPORT_ADDR")
	fi
	"$INSTALL_BIN_PATH" "${export_args[@]}"
	echo "=============================================="
}

install_action() {
	LISTEN_VALUE=""
	PASSWORD_VALUE=""
	CERT_DIR_VALUE=""

	echo "AnyTLS Server 一键安装"
	echo "GitHub 仓库: $REPO_DEFAULT"
	echo

	collect_install_or_modify_config "$DEFAULT_PORT" "" ""
	download_latest_binary
	write_config "$LISTEN_VALUE" "$PASSWORD_VALUE" "$CERT_DIR_VALUE"
	write_start_script
	write_systemd_service

	systemctl daemon-reload
	systemctl enable --now "$SERVICE_NAME"

	echo
	echo "安装完成并已启动: $SERVICE_NAME"
	echo "监听地址: $LISTEN_VALUE"
	if [[ -n "$CERT_DIR_VALUE" ]]; then
		echo "证书目录: $CERT_DIR_VALUE (server.crt / server.key)"
	else
		echo "证书模式: 自动生成"
	fi
	echo
	systemctl --no-pager --full status "$SERVICE_NAME" || true
}

uninstall_action() {
	local confirm=""
	confirm="$(prompt_yes_no "确认卸载 AnyTLS Server？" "n")"
	[[ "$confirm" == "true" ]] || {
		echo "已取消。"
		return
	}

	if systemd_service_exists; then
		systemctl disable --now "$SERVICE_NAME" || true
	fi
	rm -f "$SERVICE_FILE"
	systemctl daemon-reload

	rm -f "$INSTALL_BIN_PATH"
	rm -rf "$INSTALL_WORK_DIR"
	rm -rf "$CONFIG_DIR"

	echo "已卸载 $SERVICE_NAME。"
}

update_action() {
	download_latest_binary
	if systemd_service_exists; then
		systemctl daemon-reload
		systemctl restart "$SERVICE_NAME"
		echo "已更新并重启 $SERVICE_NAME。"
		systemctl --no-pager --full status "$SERVICE_NAME" || true
	else
		echo "已更新二进制，但未检测到 systemd 服务。"
	fi
}

modify_config_action() {
	local current_listen=""
	local current_port=""
	local current_password=""
	local current_cert_dir=""

	[[ -f "$CONFIG_FILE" ]] || fail "未找到配置文件: $CONFIG_FILE，请先执行安装"
	# shellcheck disable=SC1090
	source "$CONFIG_FILE"

	current_listen="${LISTEN:-0.0.0.0:${DEFAULT_PORT}}"
	current_port="$(port_from_listen "$current_listen")"
	current_password="${PASSWORD:-}"
	current_cert_dir="${CERT_DIR:-}"

	LISTEN_VALUE=""
	PASSWORD_VALUE=""
	CERT_DIR_VALUE=""
	collect_install_or_modify_config "$current_port" "$current_password" "$current_cert_dir"
	write_config "$LISTEN_VALUE" "$PASSWORD_VALUE" "$CERT_DIR_VALUE"

	if systemd_service_exists; then
		systemctl daemon-reload
		systemctl restart "$SERVICE_NAME"
		echo "配置已更新并重启 $SERVICE_NAME。"
		systemctl --no-pager --full status "$SERVICE_NAME" || true
	else
		echo "配置已更新，但未检测到 systemd 服务。"
	fi
}

export_node_config_action() {
	[[ -x "$INSTALL_BIN_PATH" ]] || fail "未找到可执行文件: $INSTALL_BIN_PATH，请先执行安装或更新"
	[[ -f "$CONFIG_FILE" ]] || fail "未找到配置文件: $CONFIG_FILE，请先执行安装"

	echo
	echo "导出节点配置（用于客户端导入）"
	echo "将调用 anytls-server config export 自动生成带 cert-sha256 的安全 URI。"
	echo
	"$INSTALL_BIN_PATH" config export --config "$CONFIG_FILE"
}
main() {
	local action=""

	parse_args "$@"
	GITHUB_MIRROR_PREFIX="$(normalize_github_mirror_prefix "$GITHUB_MIRROR_PREFIX")"
	if [[ -n "$GITHUB_MIRROR_PREFIX" ]]; then
		echo "GitHub 加速前缀: $GITHUB_MIRROR_PREFIX"
	fi

	[[ "$(uname -s)" == "Linux" ]] || fail "this installer currently supports Linux only"
	[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "please run as root"

	require_cmd curl
	require_cmd tar
	require_cmd unzip
	require_cmd systemctl
	require_cmd find

	repair_hostname_resolution_if_needed

	if [[ "$DIRECT_ACTION" == "install" ]]; then
		install_action_direct
		return
	fi

	echo "AnyTLS Server 管理脚本"
	echo "GitHub 仓库: $REPO_DEFAULT"

	prompt_menu_choice
	action="$MENU_CHOICE"
	case "$action" in
	1)
		install_action
		;;
	2)
		uninstall_action
		;;
	3)
		update_action
		;;
	4)
		modify_config_action
		;;
	5)
		export_node_config_action
		;;
	6)
		echo "已退出。"
		;;
	esac
}

main "$@"
