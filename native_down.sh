#!/usr/bin/env bash
# scripts/native_down.sh — stop native services (replaces docker compose down).
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

stop_service() {
    local name="$1"
    local pidfile="${RAPHAEL_RUN_DIR}/${name}.pid"
    if [ -f "$pidfile" ]; then
        local pid; pid="$(cat "$pidfile")"
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" && echo "[native_down] stopped $name (pid $pid)"
        else
            echo "[native_down] $name pid $pid already dead"
        fi
        rm -f "$pidfile"
    else
        echo "[native_down] $name not running (no pidfile)"
    fi
}

# Core (reverse order of start)
for s in raphael-api kali-tools brain phishing cloak cai; do stop_service "$s"; done
# Optional
for s in neo4j privoxy caido sliver tor; do stop_service "$s"; done

echo "[native_down] all native services stopped."
