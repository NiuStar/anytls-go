# URI 格式

AnyTLS 的 URI 格式旨在提供一种简洁的方式来表示连接到 AnyTLS 服务器所需的必要信息。它包括各种参数，如服务器地址、验证密码，TLS 设置等。

本格式参考了 [Hysteria2](https://v2.hysteria.network/zh/docs/developers/URI-Scheme/)

## 结构

```
anytls://[auth@]hostname[:port]/?[key=value]&[key=value]...
```

## 组件

### 协议名

`anytls`

### 验证

验证密码应在 URI 的 `auth` 中指定。这部分实际上就是标准 URI 格式中的用户名部分，因此如果包含特殊字符，需要进行 [百分号编码](https://datatracker.ietf.org/doc/html/rfc3986#section-2.1)。

### 地址

服务器的地址和可选端口。如果省略端口，则默认为 443。

### 参数

- `sni`：用于 TLS 连接的服务器 SNI。（特殊情况：当 `sni` 的值为 [IP 地址](https://datatracker.ietf.org/doc/html/rfc6066#section-3:~:text=Literal%20IPv4%20and%20IPv6%20addresses%20are%20not%20permitted%20in%20%22HostName%22.)时，客户端必须不发送 SNI）

- `insecure`：是否允许不安全的 TLS 连接。接受 `1` 表示 `true`，`0` 表示 `false`。

- `egress-ip`：可选，指定服务器代理出站时绑定的本地源 IP（需为服务器本机可用地址）。

- `egress-rule`：可选，指定服务器按目标地址匹配出口 IP 的规则，格式示例：
  - `domain:example.com=203.0.113.10`
  - `suffix:google.com=203.0.113.11`
  - `cidr:1.1.1.0/24=203.0.113.12`
  - `default=203.0.113.13`

## 示例

```
anytls://letmein@example.com/?sni=real.example.com
anytls://letmein@example.com/?sni=127.0.0.1&insecure=1
anytls://letmein@example.com/?sni=real.example.com&egress-ip=203.0.113.10
anytls://letmein@example.com/?sni=real.example.com&egress-rule=suffix%3Agoogle.com%3D203.0.113.11%3Bdefault%3D203.0.113.10
anytls://0fdf77d7-d4ba-455e-9ed9-a98dd6d5489a@[2409:8a71:6a00:1953::615]:8964/?insecure=1
```

## 注意事项

这个 URI 故意只包含连接到 AnyTLS 服务器所需的基础信息。尽管第三方实现可以根据需要添加额外的参数，但它们不应假设其他实现能理解这些额外参数。

## 客户端扩展（外核桥接）

以下 URI 仅用于 `anytls-client` 节点导入，非 AnyTLS 协议标准：

- `socks5://[user:pass@]host:port`：将该节点流量桥接到现有 SOCKS5。
- `singbox://x?socks=host:port&config=/path/config.json&autostart=1[&bin=/path/sing-box]`：桥接并可自动拉起 sing-box。
- `mihomo://x?socks=host:port&config=/path/config.yaml&autostart=1[&bin=/path/mihomo]`：桥接并可自动拉起 mihomo。

## 客户端扩展（原生协议 URI）

以下 URI 可直接导入为节点，`anytls-client` 会自动生成临时 sing-box 配置并拉起侧车：

- `ss://...`
- `vmess://...`
- `vless://...`
- `trojan://...`
- `hy2://...` / `hysteria2://...`
- `tuic://...`
- `wireguard://...` / `wg://...`
- `ssh://...`

说明：

- 这些 URI 仅用于客户端导入，不改变 AnyTLS 协议本身。
- 可通过环境变量 `ANYTLS_SINGBOX_BIN` 指定 sing-box 可执行文件路径（默认 `sing-box`）。
- Clash/Surge 订阅中的 `type: ss/vmess/vless/trojan/hy2/tuic/wireguard/ssh` 也会尽量自动映射为对应 URI；
  常见字段（如 ws/grpc/reality/tls）会保留，极少数字段若无 URI 对应将被忽略。
- 当“代理可导入但有字段未映射”时，订阅更新结果会提示 `mapped N proxies with M ignored field(s)`，
  并附带高频被忽略字段名，便于按字段回查和补齐。

### 协议字段映射（当前）

- `ss`：`cipher/method`、`password`、`plugin`、`plugin-opts*`
- `vmess`：`uuid/id/username`、`alterId`、`cipher/security`、`sni`、`network/ws/grpc`、`path`、`host`、`alpn`
- `vless`：`uuid/id/username`、`flow`、`security/tls/reality`、`sni`、`network/ws/grpc`、`path`、`host`、`serviceName`、`pbk/sid`、`alpn`、`allowInsecure`
- `trojan`：`password`、`sni`、`security`、`network/ws/grpc`、`path`、`host`、`serviceName`、`allowInsecure`、`pbk/sid`
- `hy2/hysteria2`：`password/auth`、`sni`、`obfs`、`obfs-password`、`up/down mbps`、`insecure`
- `tuic`：`uuid/username`、`password`、`sni`、`congestion_control`、`alpn`、`udp_relay_mode`、`insecure`
- `wireguard/wg`：`private_key`、`peer public key`、`address/local_address`、`mtu`、`pre_shared_key`、`reserved`
- `ssh`：`username/user`、`password`、`private_key`
