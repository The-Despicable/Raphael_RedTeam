#!/usr/bin/env bash
# scripts/teardown_docker.sh — explicit compose teardown + reference cleanup.
#
# Per spec this does NOT just move the compose file:
#   1. docker compose down (with volumes, remove orphans) for the legacy stack
#   2. move docker-compose.yml -> external-audits/docker-compose.yml.legacy
#      (kept for ONE release as the rollback plan)
#   3. scrub `docker compose` / `docker exec` references from health scripts
#      and docs in the repo (leaves external-audits/ and .legacy alone)
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

echo "[teardown] 1/3 docker compose down (legacy stack)"
if command -v docker >/dev/null 2>&1; then
    if docker compose ls 2>/dev/null | grep -q .; then
        docker compose down --volumes --remove-orphans || true
    else
        echo "  no active compose projects"
    fi
    # Old-style project name if compose plugin doesn't see it
    docker ps -a --format '{{.Names}}' | grep -E 'raphael|kali|tor|cai|cloak' \
        | xargs -r docker rm -f || true
    docker network rm raphael-net 2>/dev/null \
        && echo "  removed dead overlay network raphael-net" \
        || echo "  raphael-net already gone (correct — it must not exist natively)"
else
    echo "  docker not installed — nothing to tear down"
fi

echo "[teardown] 2/3 archive compose as rollback artifact"
if [ -f docker-compose.yml ]; then
    mkdir -p external-audits
    git mv docker-compose.yml external-audits/docker-compose.yml.legacy 2>/dev/null \
        || mv docker-compose.yml external-audits/docker-compose.yml.legacy
    echo "  docker-compose.yml -> external-audits/docker-compose.yml.legacy (kept one release)"
fi

echo "[teardown] 3/3 scrub docker references from health scripts + docs"
# Rewrite any `docker compose` / `docker exec` lines in scripts/ and docs/
# to point at the native equivalents. .legacy and external-audits/ excluded.
if command -v grep >/dev/null && command -v sed >/dev/null; then
    FILES="$(grep -rl -E 'docker (compose|exec)' scripts/ docs/ README.md 2>/dev/null \
        | grep -v -E 'teardown_docker|external-audits' || true)"
    if [ -n "${FILES}" ]; then
        for f in $FILES; do
            sed -i \
                -e 's|docker compose up[^#]*|./scripts/native_up.sh   # migrated: docker compose|g' \
                -e 's|docker compose down[^#]*|./scripts/native_down.sh   # migrated: docker compose|g' \
                -e 's|docker compose ps|./scripts/native_status.sh   # migrated: docker compose|g' \
                -e 's|docker exec -it kali-tools |python3 scripts/local_tools_manager.py run --tool |g' \
                "$f"
            echo "  scrubbed: $f"
        done
    else
        echo "  no docker references found in scripts/ docs/ README.md"
    fi
fi

echo "[teardown] done. Rollback: external-audits/docker-compose.yml.legacy (valid one release)."
