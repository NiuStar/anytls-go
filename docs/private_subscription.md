# Public-IP private subscription

No domain, ACME, nginx or public CA is required. AnyTLS defaults to TCP 8443;
the independent subscription HTTPS listener defaults to TCP 443. Open both ports
in the host/cloud firewall. A port bind failure aborts startup, rather than
leaving a half-ready server. This feature does not multiplex HTTP onto AnyTLS.

On the intended Linux server, after publishing a binary containing this feature:

```sh
sudo bash scripts/anytls-install_server.sh --install
# Advanced unattended override: select a real public numeric IP and proxy port.
sudo bash scripts/anytls-install_server.sh --install --public-ip <public-ip> --port 8443
# Optional dedicated HTTPS port (independent of the proxy port):
sudo bash scripts/anytls-install_server.sh --install --subscription-listen :9443
```

In a terminal, choose the public IP by number and enter the AnyTLS proxy port
(default 8443). The menu's Install action uses exactly the same flow. No password,
`--addr`, domain or certificate file is required. The selected IP becomes the
subscription node identity; IPv6 host/port output is automatically bracketed.
The HTTPS subscription port defaults to 443 and must differ from the proxy port;
an interactive conflicting port is re-prompted, explicit conflict fails before
configuration writes.

Candidates combine global interface addresses (`ip -j address`, when available)
and four parallel, certificate-verified HTTPS probes: IPv4 and IPv6 requests to
api.ipify.org and ifconfig.co/ip, each with a 5-second maximum and 3-second
connection timeout, no proxy or redirects. Private, loopback, documentation,
multicast, reserved and malformed addresses are excluded. No candidates means
manual public-IP entry, not a private fallback. Egress detection does **not** prove
inbound reachability; NAT/cloud firewall forwarding remains the operator's job.
This installer uses Bash/system tools and adds no Python dependency.

Existing public IP is the first/default choice; Enter retains it. Existing port,
password, TLS key/cert and subscription token are preserved unless explicitly
changed. Explicit `--public-ip` skips IP selection; `--port`/`--listen` skip the
port prompt. With no terminal, no selection reads are performed: existing/default
proxy port is retained and the server's existing bounded HTTPS discovery supplies
an absent public IP on first setup, or fails. Existing custom cert-file/key-file
settings are preserved. Dynamic per-SNI CA issuance is not supported for the
subscription: use a persistent cert-dir or cert-file/key-file.

Source-tree changes do not update immutable older Release script attachments;
the Release/latest download command gains these prompts only after a matching
new script is published. No release or production service operation is performed
by the regression tests (`python3 -m unittest discover -s scripts -p 'test_*.py'`).

The installer intentionally restarts its systemd service, checks active state,
and verifies local HTTPS leaf identity and exact node content before printing a
private link. This is an operator-executed installation, not a production action
performed by development or tests. A new script cannot enable this feature in
an older released binary; publish/install a matching binary first.

Manual configuration (using an already prepared server.env):

```sh
anytls-server config subscription --config /etc/anytls/server.env --public-ip YOUR_PUBLIC_IP
# First setup writes /etc/anytls/subscription.json with mode 0600; it prints no link.
# Start with all the existing password/TLS/listen flags, plus:
anytls-server -l 0.0.0.0:8443 --password-file /etc/anytls/server.password --subscription-config /etc/anytls/subscription.json
# Explicit local trusted credential handoff after the server has started:
anytls-server config subscription --config /etc/anytls/server.env --check-active
```

The JSON config stores `public_ip`, `listen`, `token`, and `node_name`. It must
be a regular 0600 file. The separate token is 32 cryptographically random bytes,
43 canonical base64url characters. Re-running setup does not rotate it. Explicit
revocation is an operator change to that private token followed by restart;
old-token requests then receive generic 404. Do not log or publish the URL.

The one-paste link is `https://IP[:port]/subscribe/TOKEN#anytls-cert-sha256=HEX`.
IPv6 is bracketed. The fragment is the active leaf DER SHA256 (lowercase hex),
not SPKI, and is not sent in HTTP. Trust the handoff channel: an attacker who
replaces the entire link can replace its trust root. The client must compare
the pin before sending the secret token, use no DNS/proxy/redirect, and enforce
public-address and request/body/time bounds. This is **pin-only authentication**,
not PKIX/hostname plus pin. Certificate changes require explicit redistribution;
never obtain a replacement pin from an unverified endpoint.

GET/HEAD returns nodes-only native YAML (`application/yaml`), serialized as
JSON, a YAML 1.2 subset, with a `proxies` list. Password, public IP and actual
AnyTLS port come from runtime inputs; `certificate-public-key-sha256` is the
canonical standard-base64 SHA256 of parsed active leaf DER-SPKI. It is distinct
from the URL DER pin; `skip-cert-verify` is false. The consuming embedded SDK's
SPKI path is also pin-only trust. No CA paths, rules, groups, providers or
client-fingerprint are supplied. Existing URI export DER-pin semantics are
unchanged.

HTTP is fixed-route and token-authenticated, sends no-store/no-referrer/nosniff,
uses TLS >=1.2, read/header/write/idle limits, small header limits and no access
URL logger. Runtime shutdown closes both listeners. Local TLS/readback tests
are not evidence of public-internet reachability or real protocol interoperability.
