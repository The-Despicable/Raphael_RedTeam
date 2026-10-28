# Raphael 2.0 — native runtime

Raphael runs as ordinary host processes. Docker is **optional**: it is retained
only as a rollback path and as a source of vulnerable targets (DVWA).

## Quickstart

```bash
cd /home/yaser/raphael-redteam

./scripts/setup-kali.sh          # host toolchain (apt, no upgrade) + .venv deps
source ./env.sh
"$RAPHAEL_PY" scripts/doctor.py  # optional readiness report

./scripts/native_up.sh           # core services on real ports
./scripts/native_status.sh       # health sweep + toolchain summary
./scripts/native_down.sh         # stop everything via PID files
```

Detached / subset / shadow:

```bash
./scripts/native_up.sh --detach
./scripts/native_up.sh --only brain,kali-tools
python3 scripts/verify_native.py   # boot 10 services on 3980+, kill one, prove respawn
```

## Ports

Defined once, in `configs/services.json`. Nothing else may hardcode them
(`scripts/check_consistency.py` rule R3 enforces this).

| service | port | health |
|---|---|---|
| cai-service | 3201 | `/health` |
| mhddos-service | 3301 | `/health` |
| cloak-service | 3401 | `/health` |
| c2-server | 3501 | `/health` |
| phishing | 3502 | `/health` |
| recon-pipeline | 3503 | `/health` |
| sword | 3600 | `/health` (+ `/sword/health`) |
| brain | 3700 | `/health` |
| kali-tools | 3800 | `/health` |
| raphael-api | 3900 | `/health` |

Optional (env-gated, TCP health): tor 9050/9052, sliver 31337/31334,
neo4j 7474/7687, caido 48080.

## Single sources of truth

| Concern | File | Enforced by |
|---|---|---|
| ports / commands / deps | `configs/services.json` | R1, R2, R3 |
| host tool inventory | `configs/tool-catalog.json` | R4, `scripts/check_tools.py` |
| engagement scope | `configs/engagement-scope.json` | R10 (fail closed) |
| phishing routes | `docs/phishing-openapi.json` | WP-06 route diff |
| structure | — | `scripts/check_consistency.py` (12 rules) |

```bash
python3 scripts/check_consistency.py --verbose   # ALL CHECKS PASSED
python3 scripts/check_tools.py --strict          # host binaries
```

## Tools without Docker

Tool calls go through `scripts/local_tools_manager.py` (direct subprocess, PATH
resolved, timeout, per-call health). `KALI_TOOLS_URL=http://127.0.0.1:3800`
remains as a compatibility shim for code that still speaks HTTP to `kali-tools`.

Self-hosted, no container required:

- `tools/broadscan` — Go scanner. Build: `(cd tools/broadscan && go build -o bin/broadscan .)`
- `tools/cloakbrowser` — stealth browser. Install: `"$RAPHAEL_PY" -m pip install -e tools/cloakbrowser`

## Anti-forensics

Planning only, dry-run by default:

```bash
python3 -c "from orchestrator.evasion import plan, render_script; print(render_script(plan()))"
curl -s localhost:3900/api/evasion/plan | head
```

Execution requires both `RAPHAEL_AF_EXECUTE=1` **and**
`confirm="I-ACCEPT-DESTRUCTIVE-WIPES"`; destructive steps additionally require
`allow_destructive=True`. See `src/orchestrator/evasion/antiforensics.py`.

## Docker / rollback

`archive/docker-compose.legacy.yml` is the one-release rollback artifact.
It is not used by any native path. Targets (DVWA) may still run under Docker.

## Troubleshooting

- `native_status.sh` all DOWN → `source ./env.sh` first; check `runtime/logs/*.log`.
- `ProxyError: SOCKS server failure` → something exported `http_proxy`. Health
  probes use `trust_env=False`; do not export proxy vars globally.
- `port busy` → a Docker container still publishes that port; stop it or use `--shadow`.
- `ModuleNotFoundError: aiosqlite` → `"$RAPHAEL_PY" -m pip install -r configs/requirements.txt`.
