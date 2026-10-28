#!/usr/bin/env bash
# scripts/native_up.sh — bring the native stack up. Replaces `docker compose up`.
#
#   ./scripts/native_up.sh                 # core services on real ports
#   ./scripts/native_up.sh --shadow        # core services on ports+100 (3980..)
#   ./scripts/native_up.sh --detach        # start and return
#   ./scripts/native_up.sh --only brain,kali-tools
#
# Ports come from configs/services.json via env.sh. Nothing here hardcodes one.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

log() { echo "[native_up] $*"; }

# ---- preflight -------------------------------------------------------------
command -v "$RAPHAEL_PY" >/dev/null 2>&1 || { echo "[native_up] FAIL: interpreter $RAPHAEL_PY not found" >&2; exit 1; }

if ! "$RAPHAEL_PY" scripts/check_tools.py --strict >/dev/null 2>&1; then
    log "preflight: required tools missing — running scripts/check_tools.py for detail"
    "$RAPHAEL_PY" scripts/check_tools.py || true
    log "preflight: run ./scripts/setup-kali.sh first. Continuing (services may degrade)."
fi

# ---- start -----------------------------------------------------------------
exec "$RAPHAEL_PY" scripts/start.py "$@"
