# Raphael External-Target Bridge

Deterministic, scoped, auditable external access for Raphael 2.0 — JSON-RPC 2.0
over stdio. No parallel tool catalog: tool execution reuses **kali.run**
(kali-tools HTTP service); the bridge only enforces engagement scope, egress
policy, rate limits and the audit trail.

```
OpenCode agent ──stdio──▶ bridge/raphael_bridge.py ──▶ src/bridge/external_target_manager.py
                                   │  fail-closed scope gate        ├──▶ tor-proxy (SOCKS5)
                                   ├──▶ kali-tools  /run            ├──▶ openvpn (host tun0)
                                   ├──▶ DNS (dnspython/socket)      └──▶ ssh -N -D / HTTP CONNECT
                                   └──▶ projects/<engagement>/bridge/audit.jsonl
```

## Run

```bash
# from repo root — both forms are equivalent:
python -m bridge.raphael_bridge
python bridge/raphael_bridge.py

# one-shot smoke (prints one system.health response, exits 0):
python bridge/raphael_bridge.py --check

# with a persisted engagement:
python -m bridge.raphael_bridge --engagement eng-demo
```

Manual shell test:

```bash
echo '{"id":"1","method":"system.health","params":{}}' | python -m bridge.raphael_bridge
```

## OpenCode integration (stdio)

**Direct shell integration** — add to the agent's shell toolset:

```json
{
  "command": "python3 -m bridge.raphael_bridge",
  "cwd": "/home/yaser/raphael-redteam",
  "framing": "line-delimited JSON-RPC 2.0"
}
```

**MCP stdio server** — the bridge natively answers `initialize`,
`tools/list` and `tools/call`, so it mounts as a minimal MCP server:

```json
{
  "mcpServers": {
    "raphael-bridge": {
      "command": "python3",
      "args": ["-m", "bridge.raphael_bridge"],
      "cwd": "/home/yaser/raphael-redteam",
      "env": {
        "PYTHONPATH": "/home/yaser/raphael-redteam",
        "EGRESS_STRATEGY": "tor",
        "TOR_SOCKS": "tor-proxy:9050",
        "KALI_TOOLS_URL": "http://kali-tools:3800",
        "SLIVER_OPERATOR_CONFIG": "/home/yaser/raphael-redteam/sliver/operator.cfg"
      }
    }
  }
}
```

> The bridge never auto-mutates OpenCode/MCP/permission configs — the snippet
> above is applied by the operator. Method load time is < 2 s (pure-python
> imports, no network calls at startup).

## JSON-RPC methods

| # | Method | Scope | Notes |
|---|--------|-------|-------|
| 1 | `system.health` | free | `{status, components:{tor, sliver, neo4j, kali, vpn_provider, ovpn_profile_loaded, dns}}`; degraded components listed |
| 2 | `bridge.version` | free | bridge + repo + engagement + method list |
| 3 | `vpn.status` | free | explicit `connected:false` + `openvpn_installed`, never crashes |
| 4 | `vpn.connect {profile, username?, password?}` | **engagement** | openvpn daemon, `--writepid/--status`, 0600 auth tempfile, returns `{session_id, mtu, latency_ms}` or explicit error |
| 5 | `vpn.disconnect {session_id}` | **engagement** | SIGTERM → SIGKILL, removes pid/status/log artifacts |
| 6 | `targets.set {engagement_id, cidrs[], urls[], credentials?}` | free (creates scope) | persists `projects/<eng>/bridge/policy.json` (0600) |
| 7 | `targets.get_policy {engagement_id}` | free | `{scope_cidrs, allowed_ports, egress_policy, max_rate}` — never secrets |
| 8 | `network.check_reachability {target, ports[], timeout}` | **engagement** | scoped async TCP probes, per-port open/closed/filtered |
| 9 | `egress_policy.set {engagement_id, mode}` | free | `proxy\|tor\|vpn\|direct` (also `ssh_tunnel`, `http_connect`) |
| 10 | `proxy.status` | free | tor reachable, socks5 bool, exit-IP check |
| 11 | `proxy.test` | free | curl `--socks5-hostname` canary + leak heuristic |
| 12 | `dns.resolve {host}` | free (canaries) / **engagement** | dnspython → socket fallback; **deferred to SOCKS under tor** |
| 13 | `tls.query {target, min_version, cipher}` | **engagement** | negotiated version/cipher/cert, `satisfies_min_version` |
| 14 | `vpn/profile/load {path}` | free | validates OVPN (remote line, auth, unsafe directives) |
| 15 | `bridge.logs {last_n}` | free | tail of `audit.jsonl` |
| + | `kali.run {tool, args, target, timeout?}` | **engagement** | routes to kali-tools `/run` (single tool catalog) |
| + | `initialize` / `tools/list` / `tools/call` / `ping` | free | MCP shim |

**Bold scope** = fail closed: without a loaded engagement
(`targets.set` or `--engagement` + persisted policy) the method refuses with
error `-32002`. Out-of-scope targets refuse with `-32001`.

## Security model

* **Fail closed** — no connect without `engagement_id`, `target_scope_cidr`,
  egress policy and (when the profile demands) credential bundle. Unset or
  partial state refuses, never defaults to open.
* **Scope engine** — IP / CIDR (subnet-of) / host / host:port / URL targets
  checked against declared CIDRs + url scopes (wildcard `*.example`).
  `allowed_ports` narrows ports; `max_packet_rate` (default 30 pps) is a
  token-bucket ceiling on tool/probe operations.
* **DNS never leaks under Tor** — with egress `tor`, in-scope hostnames are
  not resolved locally: `dns.resolve` defers to `socks5h://tor-proxy:9050`
  and raw TCP to hostnames is refused (IP literals allowed — no DNS needed).
* **Secrets** — held in memory or `projects/<eng>/bridge/policy.json` (0600);
  never echoed in responses, logs, audit records or exceptions.
* **Audit** — every external session appends
  `{ts, engagement, source_iface, target, bytes, duration_ms, status, session_id}`
  to `projects/<engagement>/bridge/audit.jsonl` (0700 dir).
* **No privileged containers** — `configs/docker-compose.override.yml` adds
  only `CAP_NET_ADMIN` + `/dev/net/tun` to the opt-in `vpn-gateway`
  (`--profile vpn`); everything else stays unprivileged.

## Environment

Copy `.env.bridge.example` into your gitignored `.env`. Key variables:

`EGRESS_STRATEGY` (tor\|direct\|vpn) · `TOR_SOCKS`/`TOR_CONTROL` ·
`KALI_TOOLS_URL` · `SLIVER_OPERATOR_CONFIG` · `VPN_PROFILE_PATH` /
`VPN_USERNAME` / `VPN_PASSWORD` · `OUTBOUND_PROXY` · `SSH_TUNNEL_*` ·
`DNS_PRIMARY`/`DNS_SECONDARY`/`DNS_CORPORATE` · `BRIDGE_LOCAL_TOOLS` ·
`RAPHAEL_REPO_ROOT`.

Legacy `/home/yaser/raphael-2.0` paths in env vars are remapped at runtime to
the current repo root.

## System-level network setup (WSL2 + Docker)

```bash
# 0. host prerequisites (openvpn, TUN, dig, curl — idempotent, no sudo pw):
sudo ./scripts/install_vpn_deps.sh

# 1. docker bridge / internet check (non-destructive):
docker run --rm --network host curlimages/curl:latest -sI https://example.com

# 2. host.docker.internal (WSL2): add to services via compose extra_hosts
#    (already wired in configs/docker-compose.override.yml):
#      extra_hosts: ["host.docker.internal:host-gateway"]
#    host fallback: grep -q host.docker.internal /etc/hosts || \
#      echo "172.17.0.1 host.docker.internal" | sudo tee -a /etc/hosts

# 3. NAT/DNS for declared targets only; default rate ceiling 30 pps
#    (enforced per engagement by the bridge token bucket).
#    No captive-portal hijacking: explicit resolvers 8.8.8.8 / 1.1.1.1,
#    corporate DNS (DNS_CORPORATE) takes priority only under VPN egress.

# 4. Tor: docker compose up -d tor-proxy  →  TOR_SOCKS=tor-proxy:9050
#    (host-run agents may need 127.0.0.1:9050 if the port is published)

# 5. Sliver operator config lands on host via the ./sliver:/config bind:
#    ls -l /home/yaser/raphael-redteam/sliver/operator.cfg

# 6. Optional containerized VPN egress (CAP_NET_ADMIN only, opt-in):
docker compose -f configs/docker-compose.override.yml --profile vpn up -d vpn-gateway
#    put profile.ovpn (+ auth.txt, 0600) under projects/_global/vpn/
#    Host VPN alternative: python -m bridge.raphael_bridge → vpn.connect
#    (needs /dev/net/tun — WSL2 kernels normally expose it; else use the container)

# 7. CA bundle is bind-mounted into every TLS-consuming service.
```

## Tests

```bash
python -m pytest bridge/tests -q          # from repo root (bridge/pytest.ini)
python scripts/test_external_bridge.py    # live, non-destructive smoke
python scripts/test_external_bridge.py --skip-tor --json
```

## Acceptance criteria mapping

| Criterion | Evidence |
|-----------|----------|
| bridge emits JSON lines, `system.health` → `status:"ok"` | `tests/test_jsonrpc.py::TestHealthAndVersion` |
| `targets.set` persists scoped engagement | `tests/test_scope_validation.py::TestTargetsSetViaBridge` |
| `proxy.test` confirms tor exit ≠ direct (no identity leak) | `tests/test_egress_policy.py::TestLeakHeuristics` + `proxy.test` |
| `kali.run` supports external targets from the kali network | `run_tool` → kali-tools `/run`; scoped; audited |
| OpenCode method mapping loads < 2 s | stdio startup has zero network calls; `bridge.version` answers immediately |
| `vpn.connect` without VPN config → explicit non-fatal error | `tests/test_jsonrpc.py::TestFailClosedBehavior::test_process_survives_errors` |
| Fail closed everywhere | `-32001/-32002` codes; all `TestFailClosed*` tests |

## Non-goals honoured

No parallel tool catalog (kali is the only executor) · no arbitrary internet
scanning (scope gate + canary allowlist) · no hardcoded sudo passwords or API
keys (`install_vpn_deps.sh` requires `sudo -n`) · no auto-mutation of MCP /
permission configs (README snippets only).
