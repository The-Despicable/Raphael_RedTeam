# raphael-redteam — full audit report

Date: 2026-10-28. Scope: every top-level component; `src/cli/node_modules` and `src/arena/*_results` treated as generated/vendor (not audited). Tracked files = 68k (mostly generated).

## 1. Layout (top level, category → path → status)

### Core (counts are source, excluding venv/node_modules/generated)
- `brain/` — autonomous brain (Python). Active; 15 tracked + New files. Key: config.py, tools_service.py, schemas.py, system_service.py, evidence_service.py, broadscan_tool.py, cloak_tool.py.
- `bridge/` + `bridge/raphael_bridge.py` — RPC bridge. Modified: richer web.cloak + scan.broad handlers.
- `src/bridge/` — runner wrappers: broadscan.py, cloak.py, external_target_manager.py (scope engine).
- `tools/` — broadscan (Go, native to bin/) + cloakbrowser (vendored Chromium).
- `tests/` — brain-side tests: test_broadscan_tool.py (new), test_cloak_tool.py (new).
- `bridge/tests/` — test_broadscan_scope.py, test_cloak_scope.py, plus legacy egress/proxy/vpn/jsonrpc.
- `configs/` — native-service-registry, backups.
- `docker/` (tor), `docker-compose.yml`, `docker-compose.yml.legacy` — deployment.
- `runtime/`, `data/`, `failures/`, `evaluations/`, `benchmarks/` — outputs.

### Auxiliary / integration (symlinked external services)
- `cai_service` → /home/yaser/raphael-2.0/cai-service
- `cloak_service` → /home/yaser/raphael-2.0/cloak-service
- `mcp_hub` → /home/yaser/raphael-2.0/mcp-hub
- `mhddos_service`, orchestrator (→ src/orchestrator), sword
- `sliver/`, `kali-tools/` (host-assist)
- `rupheal-redteam` service dirs embedded in src/

### Non-code / artifacts (not source)
- `.glm_native_backup/`, `brain.backup/`, `brain.pre_glm2/`, `Raphael_Pre_Chimera_Archive/`, `Raphael_Build/` snapshots (frozen backups; candidate for cleanup).
- `Raphael_Pre_Chimera_Archive/`, `Report_Raphael/`, `Report_Raphael.zip`, `SESSION_REPORT_FULL.md`.
- root stray `.Zone.Identifier` files (14), `*.bak` (11), `*.ovpn.bak`, `machine_*` — junk.
- `WORKLOG.md`, `INSTALL.bridge.md`, multiple env files (`.env`, `.env.bak`, `.env.pre-native.bak`, `.env.example`, `.env.tier2.template`).

## 2. Source (only the audited surface — code that runs)

### brain/ (8 Python modules, 272K total incl. backups)
- config.py (+29): BROADSCAN_* + CLOAK_* settings, health snapshots.
- tools_service.py (+101): SELF_HOSTED enum now {'broadscan','cloakfetch','cloak_fetch'}; routing in `_execute_self_hosted`; tool list surfacing.
- schemas.py (+12): ToolExecuteResponse extended with engine/routed/status_code/title/final_url/html/scan fields.
- system_service.py (+15): health snapshot includes self_hosted config.
- evidence_service.py (+2), requirements.txt (-16 lines).
- NEW: brain/broadscan_tool.py, brain/cloak_tool.py.

### bridge/ (520K)
- raphael_bridge.py (+99) — scan.broad, web.cloak, MCP schemas, approval policy map.
- NEW tests: test_broadscan_scope.py, test_cloak_scope.py.

### src/ (real source, excluding node_modules/results)
- src/bridge/external_target_manager.py (+29) — scope engine + broadscan()/cloak_fetch() entry points.
- NEW: src/bridge/broadscan.py (runner), src/bridge/cloak.py (CloakBrowserRunner).
- src/agent, src/arena (manifests/specs/tests + results data), src/orchestrator (chains, agents, capabilities), src/cli, src/kali-tools, src/mcp-hub, src/phishing, src/raphael, src/student.

### tools/
- tools/broadscan (Go module) — main.go core, opsec.go anti-forensics, Makefile, README.
- tools/cloakbrowser (vendored 9MB) — imports via sys.path; binary cache ~/.cloakbrowser.

## 3. Changes made in this session (uncommitted)
- Broadscan integration complete (Go + bridge + MCP + brain).
- CloakBrowser integration complete (vendored + bridge + brain), end-to-end verified (200/Example Domain/screenshots).
- Scope system: fail-closed enforced by ExternalTargetManager + runner gates + env scope docs.
- System health now exposes self-hosted config flags.

## 4. Gaps & bugs found (not necessarily breaking)

### Correctness / structure
- Duplicate `brain/` vs `raphael-autonomous-brain/` vs `brain.backup/` vs `brain.pre_glm2/` — unclear source of truth; risk of editing stale copy. `tools_service.py` imports may resolve to wrong brain copy depending on PYTHONPATH.
- `orchestrator` symlink points into `src/orchestrator`; double registration possible in services/maps.
- `cai_service`, `cloak_service`, `mcp_hub`, `mhddos_service` are symlinks into a sibling repo (raphael-2.0). If that sibling moves, hard break.
- Vendored `tools/cloakbrowser` (9 MB) is not a git submodule; no version pin; bin downloads only at runtime into `~/.cloakbrowser`.
- `pyproject.toml` present but .env auto-load unclear; `Settings()` reads env inconsistently between brain and bridge.

### Test coverage
- No async/live test for brain cloak in CI (only `CLOAK_LIVE=1`).
- system_service snapshot has no test coverage; error path `_safe` silently returns error dict.
- broadscan `_main` CLI exit code path untested.
- `_execute_self_hosted` success now normalizes, but still returns different field shapes for broadscan vs cloakfetch (both include `exit_code/0`, but only cloak returns status_code/title etc., only broadscan returns hits/probed/open). Schema is a superset — fine, but consumers should guard.

### Security / scope
- opsec mode forbids banner grabs via `_run`? Check gap: `opsec` flag force-disable banners — verify in opsec.go that banner grabs are skipped, not just log. Also `--opsec` requires `-syn` (root) but error path should be clearer.
- Broadscan targets from stdin: trust model — any host input reaching scan; gate is broad but `--targets -` reading attacker-controlled file okay under scope. Gap: `-allow-open` opt-out exists (CLOAK_ALLOW_OPEN for cloak) but broadscan allow-open is via JSON only — inconsistent. Consider unifying.
- Sudo password appears in earlier shell logs and AGENTS.md; should be removed from docs/logs. (Hygiene.)

### Cleanup / hygiene
- `*.Zone.Identifier` (14), `*.bak` (11), jRES/others at root clutter and get captured in combos.
- 67K tracked `src/cli/node_modules` and arena results bloat repo seriously; `.gitignore` should ignore them (currently does not).
- 8+ backup directories + generated data directories (`failures/`, `evaluations/`, `benchmarks/`, `gli-response/`).
- `.ua/` analysis data not in default ignore (note: per understand skill requires adding).
- Requirements list reduced (gain) — fine, but pydantic-settings must stay (pip-installed for current user), and pip lock pinning absent.

### Documentation
- `tools/broadscan/README.md` exists; no equivalent for cloak vendoring.
- `INSTALL.bridge.md` + `README.bridge` overlap.
- `WORKLOG.md` is authoritative chronology — sync after each change (likely done).

## 5. Improvement list (prioritized)

P0 / fast wins
1. Unify allow-open: both tools should use a common CLOUD/ENGAGEMENT_SCOPEGATE helper; one env knob `ENGAGEMENT_ALLOW_OPEN`.
2. Move `.ua/` (and node_modules, arena results) into .gitignore; purge tracked generated assets via git rm --cached or BFG.
3. Delete backups (`brain.backup`, `Raphael_Pre_Chimera_Archive`, `.glm_native_backup`) after manual diff; or move to archive/ out of repo; add `archive/` to .gitignore.
4. Remove Zone.Identifier / .bak junk from commit set.
5. Trim `src/cli/node_modules` from git (npm install on deploy).

P1 / robustness
6. Add CI tests: broadscan connect-scan against loopback networks; cloak fetch mocked offline (already unit tests, need CI wiring); system_service health test.
7. Make tool result schemas strictly discriminated unions (broadscan vs cloak) instead of a flat superset with all optional fields.
8. Health endpoint should probe `cloak_configured` binary presence (currently config-only) and `broadscan_configured`.
9. Add retry/backoff + timeout clarity in cloak (`HARD_MAX_TIMEOUT=240` enforced by caller, not by fetch_sync when given larger.
10. Scope env docs format should be validated at startup; on parse error refuse with explicit message.

P2 / cleanup
11. Make broaden integration a real package (remove sys.path inserts both in bridge and brain); vendor cloak via git submodule with pinned tag.
12. Centralize audit logging (bridge audit.jsonl + brain) into one schema with correlation IDs.
13. Consolidate telemetry: `engagement_id`, profile source, and audit into a single source-of-truth instead of duplicated.
14. Document scope file format in a single canonical README (config format, allow/deny, globs) shared by broadscan + cloak + bridge + brain.
15. Remove secrets (sudo password) from AGENTS.md / logs; move to keyring/secret manager.
16. Add `tests/` for system_service.

P3 / strategic
17. Decide canonical brain home (rename brain → raphael_brain or merge with raphael-autonomous-brain).
18. Replace symlinks into raphael-2.0 with proper git submodules or a monorepo to eliminate cross-repo breakage.
19. Move `data/`, `failures/`, `evaluations/`, `benchmarks/` out of repo (artifact storage / S3) and keep only index summaries.
20. Pin Python deps with pip-compile; add lockfile; make pydantic-settings an explicit declared dep (we pip-installed it manually).

## 6. Verification status (Raphael session final state)
- pytest: 149 passed, 2 skipped
- Go vet clean; broadscan binary built (28 KB)
- live broadscan connect scan: verified
- live cloak fetch (example.com via CloakBrowser): verified, screenshot ~80 KB
- brain ToolsService cloakfetch path: verified via schema + rejections
- scope fail-closed: verified on both paths (bridge + brain) and multiple shapes

## 7. Constraint note
All remaining changes uncommitted (repo has extensive pre-existing uncommitted work). Do NOT commit unless asked.
