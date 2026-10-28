#!/usr/bin/env bash
# scripts/native_status.sh — deterministic health sweep for all native services.
# No docker, no docker compose, no docker exec anywhere in this script.
set -uo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

FAIL=0

check() {
    local name="$1" port="$2"
    local pidfile="${RAPHAEL_RUN_DIR}/${name}.pid" pid="(-)"
    [ -f "$pidfile" ] && pid="$(cat "$pidfile")"
    local body
    body="$(curl -s -m "$HEALTH_TIMEOUT" "http://127.0.0.1:${port}/health" || true)"
    if echo "$body" | grep -q '"status": *"ok"'; then
        printf "OK    %-12s pid=%-8s http://127.0.0.1:%s/health\n" "$name" "$pid" "$port"
    else
        printf "DOWN  %-12s pid=%-8s http://127.0.0.1:%s/health -> %s\n" "$name" "$pid" "$port" "${body:-<no response>}"
        FAIL=1
    fi
}

check cai         "$CAI_PORT"
check cloak       "$CLOAK_PORT"
check phishing    "$PHISHING_PORT"
check brain       "$BRAIN_PORT"
check kali-tools  "$KALI_TOOLS_PORT"
check raphael-api "$RAPHAEL_API_PORT"

echo "--- tools on PATH ---"
for t in nmap srm pupy bloodhound; do
    p="$(command -v "$t" 2>/dev/null || true)"
    if [ -n "$p" ]; then printf "OK    %s -> %s\n" "$t" "$p"; else printf "MISS  %s\n" "$t"; FAIL=1; fi
done

echo "--- logs ---"
ls -la "$RAPHAEL_LOG_DIR" 2>/dev/null | tail -n +2

exit "$FAIL"
