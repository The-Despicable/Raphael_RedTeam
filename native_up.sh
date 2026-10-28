#!/usr/bin/env bash
# scripts/native_up.sh — native process supervisor start (replaces docker compose up).
#
# Starts, in order:
#   0. preflight: env, dirs, required host tools (calls setup-kali.sh if gaps)
#   1. optional env-gated services (tor, sliver, caido, neo4j, privoxy)
#   2. core services: cai 3201, cloak 3401, phishing 3502, brain 3700,
#      kali-tools 3800, raphael-api 3900
#
# Each service:
#   - runs under nohup with a PID file in $RAPHAEL_RUN_DIR
#   - logs to /var/log/raphael/<service>.log
#   - is health-checked on its exact port; expects `status: ok`
#
# For restart-on-crash behavior use the systemd user units in deploy/systemd/
# (scripts/systemd_install.sh) — nohup here is the manual fallback.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

FAIL=0

log()  { echo "[native_up] $*"; }
ok()   { echo "[native_up] OK  $*"; }
bad()  { echo "[native_up] FAIL $*"; FAIL=1; }

# ---------------------------------------------------------------- preflight
for t in uvicorn python3; do
    command -v "$t" >/dev/null 2>&1 || { bad "preflight: $t not on PATH"; }
done

# Cleanup/forensics set must exist before the kali service starts.
MISSING=0
for t in nmap srm bleachbit wipe sleuthkit auditctl bloodhound pupy; do
    command -v "$t" >/dev/null 2>&1 || { log "preflight: $t missing"; MISSING=1; }
done
if [ "$MISSING" -ne 0 ]; then
    log "preflight: gaps detected — running setup-kali.sh (install ordering enforced there)"
    bash scripts/setup-kali.sh || bad "setup-kali.sh failed — continuing, but expect tool denials"
fi

# ---------------------------------------------------------------- supervisor helpers

start_service() {
    # start_service <name> <port> <module:app> [extra env pairs...]
    local name="$1" port="$2" module="$3"; shift 3
    local pidfile="${RAPHAEL_RUN_DIR}/${name}.pid"
    local logfile="${RAPHAEL_LOG_DIR}/${name}.log"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        ok "$name already running (pid $(cat "$pidfile"))"
        return 0
    fi
    log "starting $name on 127.0.0.1:${port} (module ${module})"
    ( env "$@" nohup python3 -m uvicorn "${module}" \
            --host 127.0.0.1 --port "${port}" \
            >>"$logfile" 2>&1 & echo $! > "$pidfile" )
    sleep 0.3
    local pid; pid="$(cat "$pidfile" 2>/dev/null || echo '')"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        ok "$name started (pid $pid, log $logfile)"
    else
        bad "$name failed to start — check $logfile"
    fi
}

start_optional() {
    # start_optional <envflag> <name> -- <command...>
    local flag="$1" name="$2"; shift 3
    if [ "${!flag}" = "1" ]; then
        local pidfile="${RAPHAEL_RUN_DIR}/${name}.pid"
        local logfile="${RAPHAEL_LOG_DIR}/${name}.log"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            ok "$name (optional) already running"
            return 0
        fi
        log "starting optional $name"
        ( nohup "$@" >>"$logfile" 2>&1 & echo $! > "$pidfile" )
        ok "$name (optional) started"
    else
        log "optional $name skipped (${flag}=0)"
    fi
}

# ---------------------------------------------------------------- optional (env-gated)
start_optional RAPHAEL_ENABLE_TOR      tor     -- "$TOR_BIN" -f "$TORRC_PATH"
start_optional RAPHAEL_ENABLE_SLIVER   sliver  -- sliver-server daemon
start_optional RAPHAEL_ENABLE_CAIDO    caido   -- caido
start_optional RAPHAEL_ENABLE_PRIVOXY  privoxy -- privoxy --no-daemon
start_optional RAPHAEL_ENABLE_NEO4J    neo4j   -- neo4j console

# ---------------------------------------------------------------- core (fixed ports)
start_service cai         "$CAI_PORT"         "$CAI_MODULE"
start_service cloak       "$CLOAK_PORT"       "$CLOAK_MODULE"
start_service phishing    "$PHISHING_PORT"    "$PHISHING_MODULE"
start_service brain       "$BRAIN_PORT"       "$BRAIN_MODULE"
start_service kali-tools  "$KALI_TOOLS_PORT"  "$KALI_TOOLS_MODULE" KALI_TOOLS_URL="http://127.0.0.1:${KALI_TOOLS_PORT}"
start_service raphael-api "$RAPHAEL_API_PORT" "$RAPHAEL_API_MODULE"

# ---------------------------------------------------------------- deterministic health checks
log "health sweep (each must answer {\"status\":\"ok\"})"
sweep() {
    local name="$1" port="$2"
    local body
    body="$(curl -s -m "$HEALTH_TIMEOUT" "http://127.0.0.1:${port}/health" || true)"
    if echo "$body" | grep -q '"status": *"ok"'; then
        ok "${name} http://127.0.0.1:${port}/health -> $body"
    else
        bad "${name} http://127.0.0.1:${port}/health -> ${body:-<no response>}"
    fi
}
sleep 1
sweep cai         "$CAI_PORT"
sweep cloak       "$CLOAK_PORT"
sweep phishing    "$PHISHING_PORT"
sweep brain       "$BRAIN_PORT"
sweep kali-tools  "$KALI_TOOLS_PORT"
sweep raphael-api "$RAPHAEL_API_PORT"

if [ "$FAIL" -ne 0 ]; then
    echo "[native_up] COMPLETED WITH FAILURES — see above"
    exit 1
fi
echo "[native_up] all core services native and healthy. Docker is not required."
