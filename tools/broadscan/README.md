# broadscan

Internet-broad TCP scanner used by Raphael. Connect scan by default, raw SYN
with `-syn`. Targets stream through a generator; the probe rate is a token
bucket, so `-rate` is a real ceiling.

## Build

```sh
make -C tools/broadscan        # -> tools/broadscan/bin/broadscan
```

## Direct use

```sh
bin/broadscan -targets 1.2.3.0/24 -ports 22,80,443
bin/broadscan -targets 0.0.0.0/0 -ports 443 -rate 20000 -scope scope.json
sudo bin/broadscan -syn -targets 10.0.0.0/8 -ports 1-1024 -rate 50000
```

Flags: `-targets` (CIDR / `a.b.c.d-e` / host, comma list or file),
`-exclude`, `-ports`, `-rate`, `-timeout`, `-workers`, `-out`, `-json`,
`-banners`, `-shuffle`, `-syn`, `-src`, `-scope`.

`-syn` builds IP/TCP by hand from an AF_INET raw socket and matches replies on
a second raw socket. Without `-src` the source address is resolved per target
/24 from the routing table, so mixed loopback + interface scans work; the
receiver matches probes on (port, source port) tuples rather than on a single
local address. The kernel also emits its own RST for each SYN-ACK it has no
socket for — harmless here, but drop outbound RSTs if a target complains:

```sh
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

## Opsec / anti-forensics

`-opsec` requires `-syn` and turns on: no banner grabs (a banner is a full TCP
connection plus an application log line per hit), TTL 48-64 randomized, random
window, 25 ms jitter, random source ports.

Independent knobs:

| flag | effect on the probe stream |
| --- | --- |
| `-decoys CIDR,.. -decoy-n N` | interleave N spoofed-source SYNs per real probe; replies never tracked |
| `-jitter 25ms` | randomized inter-probe gap, breaks constant-rate fingerprints |
| `-ttl 48-64` | per-probe TTL randomization, defeats TTL-based OS inference |
| `-frag 8` | split the TCP header into tiny IP fragments (multiple of 8) |
| `-tcp-ts` | 32-byte TCP header with a timestamp option instead of the bare 20 |
| `-sport fixed\|random` | tuple pressure strategy |
| `-wipe-scope` | unlink the scope file once read (the python layers pass this on every run) |
| `-stdin` | read targets from stdin instead of argv (`ps` sees no target list) |

Operator-host hygiene: core dumps are disabled via `RLIMIT_CORE=0` at startup,
and the scope file is a 0600 temp copy that is removed after parsing.

Decoys are validated against the same allow list: a spoofed source outside the
engagement scope is refused before any packet is built.

## Scope gate

`-scope` takes a JSON document:

```json
{"allow": ["10.10.10.0/24"], "deny": ["10.10.10.128/25"]}
```

Targets are intersected with `allow` before expansion, `deny` is subtracted,
and every emitted address is re-checked against `deny`. A target set that
resolves to zero addresses exits non-zero instead of scanning nothing.

## In-tree integration

| Caller | Path | Gate |
| --- | --- | --- |
| JSON-RPC / MCP | `scan.broad` → `RaphaelBridge._m_scan_broad` | `EgressProfile` |
| Python API | `ExternalTargetManager.broadscan()` | `EgressProfile` |
| Brain | `POST /tools/execute {"tool":"broadscan"}` | `BROADSCAN_SCOPE` doc |

`src/bridge/broadscan.py` derives the allow list from the profile CIDRs, the
deny list from `profile.meta["deny_cidrs"]`, restricts ports to
`allowed_ports`, and caps `-rate` at `max_packet_rate`.

`brain/broadscan_tool.py` is the standalone path for the brain container: it
reads `BROADSCAN_SCOPE` (file) or `BROADSCAN_SCOPE_INLINE` (JSON), resolves
hostname scope entries to /32s, and refuses to run without a scope unless
`BROADSCAN_ALLOW_OPEN=1`. The opsec layer rides through both paths via the
`scan.broad` params (`opsec`, `decoys`, `jitter_ms`, `frag`, `ttl`, `tcp_ts`,
`sport`) or the matching CLI flags on `/tools/execute` args.
