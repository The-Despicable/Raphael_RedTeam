# Runtime policy — CANONICAL

**Production runtime: Docker Compose from `docker-compose.yml` at the repo root.**

Raphael stays on Docker. Native mode (`scripts/native_up.sh`) is a verified
fallback that boots 10/10 core services on shadow ports 3980-3989 and proves
supervisor respawn. It is not the cutover path and is not enabled on real ports
while Docker owns them.

## Frozen images (do not rebuild casually)

See `docker/images.lock` for immutable tags `2026-10-28` and their image IDs.
Regenerate with `./scripts/freeze_images.sh <date>`.

## Non-negotiable rules (current setup)

1. Never run `docker compose build` or `docker image build` without first bumping
   a frozen tag. A rebuild erased the gophish/evilginx/set API and the
   anti-forensic binary layer twice already.
2. The working copies `docker-compose.rollback.yml` (validated) and
   `archive/docker-compose.legacy.yml`-compatible legacy file exist for rollback.
3. `configs/docker-compose.yml` is intentionally absent — there is exactly one
   canonical compose file: root `docker-compose.yml`.
4. Tor is local-only: `docker/tor/torrc` binds `127.0.0.1` SOCKS and control.
5. Egress is proven, not assumed: `curl --proxy socks5h://127.0.0.1:9050`.
6. `setup-kali.sh` is the way to make the host toolchain Docker-independent
   without yet cutting over.
7. Anti-forensics is dry-run unless `RAPHAEL_AF_EXECUTE=1` and the confirm
   token are supplied; `execute` is locked by default.

## Cut-over triggers (frozen ↔ native)

Migrate to native (control plane only, leave weapon tier in Docker) IF and ONLY IF:
- Docker fails twice during an engagement, OR
- a required anti-forensic / C2 tool cannot be rebuilt from a frozen image, OR
- host egress provability is demanded by an external engagement.

Until then, this file stays and the canonical runtime stays Docker.

## Source-of-truth invariant

- ports: `configs/services.json` (single source)
- tools: `configs/tool-catalog.json`
- scope: `configs/engagement-scope.json`
- structure: `scripts/check_consistency.py` (12 rules)  → ALL CHECKS PASSED
