#!/usr/bin/env bash
# scripts/native_down.sh — stop the native stack via PID files.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh
exec "$RAPHAEL_PY" scripts/stop.py "$@"
