# AnyTLS

一个试图缓解 嵌套的TLS握手指纹(TLS in TLS) 问题的代理协议。`anytls-go` 是该协议的参考实现。

- 灵活的分包和填充策略
- 连接复用，降低代理延迟
- 简洁的配置

[用户常见问题](./docs/faq.md)

[协议文档](./docs/protocol.md)

[URI 格式](./docs/uri_scheme.md)

## 快速食用方法

为了方便，示例服务器和客户端默认采用不安全的配置，该配置假设您不会遭遇 TLS 中间人攻击（这种情况偶尔发生在网络接入层，在骨干网络上几乎不可能实现）；否则，您的通信内容可能会被中间人截获。

### 示例服务器

```
./anytls-server -l 0.0.0.0:8443 -p 密码
```

`0.0.0.0:8443` 为服务器监听的地址和端口。

### 示例客户端

```
./anytls-client -l 127.0.0.1:1080 -s 服务器ip:端口 -p 密码
```

`127.0.0.1:1080` 为本机 Socks5 代理监听地址，理论上支持 TCP 和 UDP(通过 udp over tcp 传输)。

如果需要让服务端使用指定出口 IP 发起代理请求，可增加参数：

```
./anytls-client -l 127.0.0.1:1080 -s 服务器ip:端口 -p 密码 --egress-ip 服务器本机IP
```

v0.0.12 版本起，示例客户端可直接使用 URI 格式:

```
./anytls-client -l 127.0.0.1:1080 -s "anytls://password@host:port"
```

### 查看版本与构建信息

客户端：

```bash
anytls-client version
```

服务端：

```bash
anytls-server version
```

也支持：`-v`、`--version`。输出包含版本号、commit、构建时间。

### sing-box

https://github.com/SagerNet/sing-box

它包含了 anytls 协议的服务器和客户端。

### mihomo

https://github.com/MetaCubeX/mihomo

它包含了 anytls 协议的服务器和客户端。

### Shadowrocket

Shadowrocket 2.2.65+ 实现了 anytls 协议的客户端。

## 客户端一键管理脚本

新增脚本：

- Linux / macOS: `scripts/client_manager.sh`
- Windows (PowerShell): `scripts/client_manager.ps1`
- OpenWrt: `scripts/install_client_openwrt.sh`（支持 x86/arm 架构，自动创建开机自启动服务）

功能：

- 一键安装/更新客户端（从 GitHub 最新 release 下载）
- 安装时指定并固定配置文件路径、API 地址（后续节点维护/切换都写入该配置文件）
- 编辑配置文件（增加/修改节点）
- 启动客户端 API 服务（`-mode api`，同时启动本地代理并连接服务端）
- 一键导入新节点（URI）
- 运行中切换节点（`-mode cli` 通过 HTTP API 调用）
- 查看当前节点

配置文件路径：

- Linux: `~/.config/anytls/client.json`
- macOS: `~/Library/Application Support/anytls/client.json`
- Windows: `%APPDATA%\anytls\client.json`

脚本会自动生成配置模板，节点示例字段：

- `name` 节点名称
- `server` 服务器地址（`host:port`）
- `password` 密码
- `sni` 可选
- `egress_ip` 可选
- `egress_rule` 可选（按目标地址匹配服务端出口 IP，命中优先）
- `tun` 可选（启用后在 `api` 模式下启用 TUN 透明接管）

运行：

```bash
./scripts/client_manager.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\client_manager.ps1
```

从 GitHub Release 一键运行：

```bash
bash <(curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-client_manager.sh)
```

Linux 一键安装（下载后执行，兼容不支持 `<(...)` 的 shell）：

```bash
curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-client_manager.sh -o /tmp/anytls-client_manager.sh && bash /tmp/anytls-client_manager.sh
```

如需通过 GitHub 加速前缀下载（例如 `https://ghfast.top/`）：

```bash
curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-client_manager.sh -o /tmp/anytls-client_manager.sh && bash /tmp/anytls-client_manager.sh -p https://ghfast.top/
```

说明：脚本会对 `github.com` 下载链接应用该前缀；`api.github.com` 查询会自动直连（避免部分加速站返回 403）。

macOS 一键安装：

```bash
curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-client_manager.sh -o /tmp/anytls-client_manager.sh && bash /tmp/anytls-client_manager.sh
```

macOS 代理下载示例：

```bash
curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-client_manager.sh -o /tmp/anytls-client_manager.sh && bash /tmp/anytls-client_manager.sh -p https://ghfast.top/
```

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-client_manager.ps1 | iex"
```

Windows 代理下载示例：

```powershell
irm https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-client_manager.ps1 -OutFile "$env:TEMP\anytls-client_manager.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\anytls-client_manager.ps1" -p "https://ghfast.top/"
```

OpenWrt 一键安装（自动安装/更新客户端并创建 procd 自启动）：

```sh
sh -c "$(wget -qO- https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-install_client_openwrt.sh)"
```

如果有 `curl` 也可以：

```sh
sh -c "$(curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-install_client_openwrt.sh)"
```

OpenWrt 代理下载示例：

```sh
curl -fsSL https://ghfast.top/https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-install_client_openwrt.sh -o /tmp/anytls-install_client_openwrt.sh && sh /tmp/anytls-install_client_openwrt.sh -p https://proxy.199028.xyz/
```

管理脚本新增快捷项：

- 查看运行状态
- 一键诊断
- 查看配置备份
- 回滚配置（支持最近一次或指定备份名）

客户端 API/CLI 模式说明：

- `-mode api`：客户端以 HTTP API 服务方式运行，同时提供本地代理入口并转发到服务端
- 也支持快捷写法：`anytls-client api`（等价于 `-mode api`，默认读取本地配置文件）
- `-mode cli`：客户端命令行工具，不直接建链路，通过 HTTP 调用已运行的 `api` 进程，实现节点维护/切换
- 新增简写命令：`anytls-client cli ...`（本地默认不需要 `-config/-control`）

客户端 Web 管理面板（React + Ant Design）：

- 启动 API 模式后，浏览器打开：`http://<control>/ui/`（默认 `http://127.0.0.1:18990/ui/`）
- 支持节点列表查看、切换、修改、删除
- 支持新增节点：
  - URI 一键导入
  - 按属性手动新增
- 支持修改客户端配置（listen/control/min_idle_session/default_node/tun）
- 支持 mihomo 规则分流（兼容子集）：
  - 按域名/IP/端口分流到不同节点
  - 支持 `REJECT` 广告拦截
  - 支持 `RULE-SET` + `rule_providers`
- 支持单个与批量测速：
  - 延迟测试
  - 带宽测试
- 支持一键诊断与配置回滚：
  - 一键诊断（配置/节点连通/代理握手/TUN/failover）
  - 查看配置备份列表并回滚到指定版本
  - 支持导出诊断报告（JSON/文本）
- 支持日志管理页面：
  - 查看客户端运行日志（级别/关键词过滤）
  - 自动刷新
  - 一键清空
- 支持订阅管理：
  - 新增/编辑/删除订阅链接（HTTP/HTTPS）
  - 手动更新单个订阅或一键更新全部订阅
  - 按 `update_interval_sec` 自动定时更新
  - 订阅节点会标记来源，删除订阅时会同步清理对应节点
- 支持 Web 基础认证（用户名密码）
  - 执行 `anytls-client`（不带参数）进入菜单后可设置/清除
  - 设置后访问 `/api/v1/*` 需要用户名密码
  - `/ui/` 为完整登录页（非浏览器弹窗），支持“记住账号密码”
  - `anytls-client cli ...` 会自动读取本地配置中的认证信息并附带请求
  - API 内置防暴力锁定（连续失败后临时锁定来源 IP）
  - 可通过环境变量调整：`ANYTLS_API_AUTH_MAX_FAILURES`、`ANYTLS_API_AUTH_LOCKOUT_SEC`
  - 运行状态页会显示健康告警（例如 TUN 配置和运行态不一致）

本地快速导入节点（推荐）：

```bash
anytls-client cli add 'anytls://password@example.com:8443/?sni=example.com'
```

也可以指定节点名：

```bash
anytls-client cli add 'anytls://password@example.com:8443/?sni=example.com' 节点名
```

外核桥接节点（支持 sing-box / mihomo 全协议栈）：

```bash
# 直接桥接到已运行的本地 SOCKS5
anytls-client cli add 'socks5://127.0.0.1:1081' 本地SOCKS桥接

# 自动拉起 sing-box（当 socks 不可达时）
anytls-client cli add 'singbox://x?socks=127.0.0.1:1081&config=/etc/sing-box/config.json&autostart=1'

# 自动拉起 mihomo（当 socks 不可达时）
anytls-client cli add 'mihomo://x?socks=127.0.0.1:7890&config=/etc/mihomo/config.yaml&autostart=1'
```

原生协议 URI（自动用 sing-box 侧车拉起，不需要手写 singbox://）：

```bash
anytls-client cli add 'ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ss-node'
anytls-client cli add 'trojan://password@example.com:443?sni=example.com#trojan-node'
anytls-client cli add 'vless://uuid@example.com:443?security=tls&sni=example.com&type=ws&path=%2F#vless-node'
anytls-client cli add 'vmess://<base64-json>'
anytls-client cli add 'hy2://password@example.com:443?sni=example.com#hy2-node'
anytls-client cli add 'tuic://uuid:password@example.com:443?sni=example.com#tuic-node'
anytls-client cli add 'wireguard://<privateKey>@1.2.3.4:51820?publickey=<peerPublicKey>&address=10.0.0.2/32#wg-node'
anytls-client cli add 'ssh://user:pass@example.com:22#ssh-node'
```

说明：

- 未指定 `-control/--control` 时，会读取本地配置文件中的 `control` 地址，然后直接调用本地 API
- 传了 `--control host:port` 时，不读取本地配置，直接调用该地址的 API（适合远程管理）

TUN 透明接管（`api` 模式）：

- 在客户端配置文件中增加/修改 `tun`：

```json
"tun": {
  "enabled": true,
  "name": "anytls0",
  "mtu": 1500,
  "address": "198.18.0.1/15",
  "auto_route": true
}
```

- 启动 `api` 模式后，会同时启动本地代理与 TUN 栈，TUN 流量通过本地 SOCKS5 再转发到 AnyTLS 服务器
- Web 面板中切换 TUN 开关会立即生效：
  - 开启：立即接管全局流量
  - 关闭：立即恢复普通网络
- `auto_route=true` 时，当前实现支持：
  - Linux：自动接管 IPv4 默认路由，并为当前节点服务端地址添加直连旁路
  - macOS：通过 `0.0.0.0/1` + `128.0.0.0/1` 分流实现自动接管，并为当前节点服务端地址添加直连旁路
- 切换节点时会自动更新服务端旁路路由
- 该模式需要系统具备 TUN 能力与路由配置权限（通常需要 root / CAP_NET_ADMIN）

Mihomo 规则分流（兼容子集）：

- 配置字段：`routing`
- 当前支持规则类型：
  - `DOMAIN`
  - `DOMAIN-SUFFIX`
  - `DOMAIN-KEYWORD`
  - `DOMAIN-REGEX`
  - `IP-CIDR`
  - `IP-CIDR6`
  - `GEOIP`（基于 mmdb 国家库）
  - `DST-PORT`
  - `RULE-SET`
  - `MATCH`
- 当前支持策略动作：
  - `节点名`（走指定 AnyTLS 节点）
  - `DIRECT`（客户端直连目标，不走 AnyTLS）
  - `REJECT` / `REJECT-DROP`（直接拒绝，可用于广告拦截）
  - `PROXY`（回落到当前默认节点）

示例（分流 + 广告拦截）：

```json
"routing": {
  "enabled": true,
  "rules": [
    "RULE-SET,ads,REJECT",
    "DOMAIN-SUFFIX,openai.com,node-us",
    "IP-CIDR,8.8.8.0/24,node-us",
    "MATCH,node-main"
  ],
  "rule_providers": {
    "ads": {
      "type": "http",
      "behavior": "classical",
      "format": "yaml",
      "url": "https://example.com/ads.yaml"
    }
  }
}
```

`rule_providers` 支持：

- `type`：`http` / `file` / `inline`
- `behavior`：`classical` / `domain` / `ipcidr`（`mrs` 可留空自动识别）
- `format`：`yaml` / `text` / `mrs` / `sgmodule`
- `interval_sec`：HTTP 规则集自动更新间隔（秒），默认 `3600`
- `classical` 规则集中如果规则本身已带动作（如 `REJECT` / `DIRECT`），会自动生效，不必再额外写一条 `RULE-SET,xxx,动作`
- 也支持 `RULE-SET,xxx`（不带动作）写法，此时按规则集内命中的规则动作执行
- 在 Web「规则分流」页可点击“手动更新规则集”立即拉取并热更新
- Web「规则分流」页会显示每个规则集的最近更新时间、最近错误，并支持单个规则集手动更新

`GEOIP`（mmdb）配置：

- 配置字段：`routing.geoip`
- 支持 `type=http|file`
- `http` 可直接配置 mmdb 下载地址（例如 `https://static-sg.529851.xyz/GeoLite2-Country.mmdb`）

示例：

```json
"routing": {
  "enabled": true,
  "geoip": {
    "type": "http",
    "url": "https://static-sg.529851.xyz/GeoLite2-Country.mmdb",
    "interval_sec": 3600
  },
  "rules": [
    "GEOIP,CN,DIRECT",
    "MATCH,node-main"
  ]
}
```

`mrs` 原生支持（meta-rules-dat）：

- 已支持 `domain` 与 `ipcidr` 行为（可直接使用 `geosite/*.mrs` 与 `geoip/*.mrs`）
- 注意：`geoip/*.mrs` 在这里是 **IP-CIDR 规则集**；`GEOIP,XX` 规则本身使用的是上面的 `routing.geoip` mmdb
- 示例：

```json
"rule_providers": {
  "google": {
    "type": "http",
    "format": "mrs",
    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs"
  },
  "cn_ip": {
    "type": "http",
    "format": "mrs",
    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
  }
}
```

`sgmodule`（Surge 模块）兼容支持：

- 读取 `[Rule]` 段并提取当前支持的规则类型：`DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `DOMAIN-REGEX` / `IP-CIDR` / `IP-CIDR6` / `GEOIP` / `DST-PORT` / `MATCH` / `AND` / `OR` / `NOT`（支持嵌套）
- 支持 `[URL Rewrite]` 中 `- reject` 规则（可按完整 URL 正则拦截；同时会保留主机级拦截能力）
- 支持 `[MITM] hostname = ...` 解析并用于 MITM 主机匹配
- 仍不支持的条目（如 `URL-REGEX`）会自动忽略
- 示例：

```json
"rule_providers": {
  "surge-ad": {
    "type": "http",
    "format": "sgmodule",
    "behavior": "classical",
    "url": "https://raw.githubusercontent.com/QingRex/LoonKissSurge/refs/heads/main/Surge/Beta/%E5%B9%BF%E5%91%8A%E5%B9%B3%E5%8F%B0%E6%8B%A6%E6%88%AA%E5%99%A8.beta.sgmodule"
  }
}
```

自动故障切换（`failover`）：

- 客户端默认启用故障切换（多节点时建议保持开启）
- 当前节点连续探测失败达到阈值后，会自动切换到下一个健康节点
- 自动切换后会自动写回 `default_node`

```json
"failover": {
  "enabled": true,
  "check_interval_sec": 15,
  "failure_threshold": 2,
  "probe_target": "1.1.1.1:443",
  "probe_timeout_ms": 2500
}
```

常见 CLI 操作（需先启动 `api`）：

查看运行状态：

```bash
anytls-client cli status
```

```bash
anytls-client -mode cli -config ~/.config/anytls/client.json -control 127.0.0.1:18990 -cmd switch -node 节点名
```

通过 URI 一键导入新节点：

```bash
anytls-client -mode cli -config ~/.config/anytls/client.json -control 127.0.0.1:18990 -cmd import -node 节点名 -uri 'anytls://password@example.com:8443/?sni=example.com'

# 也支持外核桥接 URI
anytls-client -mode cli -config ~/.config/anytls/client.json -control 127.0.0.1:18990 -cmd import -node singbox-bridge -uri 'singbox://x?socks=127.0.0.1:1081&config=/etc/sing-box/config.json&autostart=1'
```

新增节点（create）：

```bash
anytls-client -mode cli -config ~/.config/anytls/client.json -control 127.0.0.1:18990 -cmd create -node node-2 -s server.example.com:8443 -p password -sni server.example.com
```

编辑节点（update）：

```bash
anytls-client -mode cli -config ~/.config/anytls/client.json -control 127.0.0.1:18990 -cmd update -node node-2 -egress-ip 203.0.113.10
```

删除节点（delete）：

```bash
anytls-client -mode cli -config ~/.config/anytls/client.json -control 127.0.0.1:18990 -cmd delete -node node-2
```

一键诊断：

```bash
anytls-client cli diagnose
```

查看配置备份列表：

```bash
anytls-client cli backups
```

回滚到最近一次配置备份（或指定备份名）：

```bash
anytls-client cli rollback
anytls-client cli rollback client.json.20260208-183012.123456789.bak
```

说明：回滚会先恢复配置文件，运行中的 API/TUN/监听状态建议重启 `anytls-client -mode api` 后完全生效。

## 发布到 GitHub Release

仓库内置脚本：`scripts/release_github.sh`

脚本会在构建客户端前自动执行前端打包（`scripts/build_webui.sh`），通过 npm/esbuild 编译 `cmd/client/webui/src` 并生成嵌入文件 `cmd/client/webui/index.html`，再进行客户端编译。

发布产物已拆分为独立包（每个平台分别生成）：

- `anytls-client_<version>_<os>_<arch>.(tar.gz|zip)`
- `anytls-server_<version>_<os>_<arch>.(tar.gz|zip)`
- 安装脚本也会作为 release 资产发布：
  - `anytls-install_server.sh`
  - `anytls-client_manager.sh`
  - `anytls-client_manager.ps1`
  - `anytls-install_client_openwrt.sh`

不带参数直接运行会进入交互向导（只需输入版本号，并选择“立即发布正式版”或“发布预发布版”）：

```
./scripts/release_github.sh
```

示例（构建所有默认平台并发布 `v0.0.13`）：

```
./scripts/release_github.sh --version v0.0.13
```

发布预版本（例如 `v0.0.13-beta.1`，并自动标记为 prerelease）：

```
./scripts/release_github.sh --version v0.0.13 --pre beta.1
```

仅本地构建打包，不发布：

```
./scripts/release_github.sh --version v0.0.13 --no-publish
```

常用参数：

- `--repo owner/repo` 指定 GitHub 仓库（默认从 `remote.origin.url` 推断）
- `--target <commitish>` 指定 release 对应提交（默认 `HEAD`）
- `--targets <list>` 指定构建矩阵，例如 `linux/amd64,darwin/arm64,windows/amd64`
- `--notes-file <file>` 使用自定义发布说明
- `--prerelease` 标记为预发布
- `--pre <suffix>` 生成预发布标签（例如 `beta.1`、`rc.1`），并自动设置为 prerelease

## 服务器一键安装

新增脚本：`scripts/install_server.sh`

用途：在 Linux 服务器上一键下载 GitHub 最新版 `anytls-server`、交互配置并自动启动。

交互内容：

- 一级菜单：安装 / 卸载 / 更新版本 / 修改配置
- 可导出节点配置（URI + JSON 片段，用于客户端导入）
  - 导出时可选配置 `egress-ip`（默认不选择）
  - 可选配置 `egress-rule`（服务端按规则匹配出口 IP）
- 监听端口
- 连接密码
- 是否自动生成证书
  - 若选择否，需要输入证书目录
  - 目录内文件命名要求：`server.crt` 和 `server.key`

执行：

```bash
sudo ./scripts/install_server.sh
```

从 GitHub Release 一键运行：

```bash
curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-install_server.sh -o /tmp/anytls-install_server.sh && sudo bash /tmp/anytls-install_server.sh
```

如需通过代理下载：

```bash
curl -fsSL https://github.com/NiuStar/anytls-go/releases/latest/download/anytls-install_server.sh -o /tmp/anytls-install_server.sh && sudo bash /tmp/anytls-install_server.sh -p https://ghfast.top/
```


无安装脚本时，也可以直接用 `anytls-server` 完成配置编辑和节点导出：

```bash
# 无参数直接进入交互菜单（启动服务 / 编辑配置 / 导出节点）
anytls-server

# 交互编辑服务端配置（默认 /etc/anytls/server.env）
anytls-server config edit

# 导出节点（自动检测本机 IP，若有多个会导出多条）
anytls-server config export
```

非交互示例：

```bash
anytls-server config edit --config /etc/anytls/server.env --listen 0.0.0.0:20086 --password 'your-password' --auto-cert --yes
anytls-server config export --config /etc/anytls/server.env --addr example.com:20086 --node-prefix hk --egress-ip 203.0.113.10 --yes
```
