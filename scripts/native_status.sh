#!/usr/bin/env bash
# scripts/native_status.sh — health sweep + toolchain summary.
# Exit 0 only when every core service answers {"status":"ok"}.
set -uo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

echo "== services =="
"$RAPHAEL_PY" scripts/status.py "$@"
SVC_RC=$?

echo
echo "== tools =="
"$RAPHAEL_PY" scripts/check_tools.py || true

echo
echo "== logs: $RAPHAEL_LOG_DIR =="
ls -1 "$RAPHAEL_LOG_DIR" 2>/dev/null | tail -n 12 || true

exit "$SVC_RC"
