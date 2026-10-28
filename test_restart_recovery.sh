#!/usr/bin/env bash
# scripts/test_restart_recovery.sh — proves services come back after arbitrary
# process death via systemd (Restart=always), not manual bash.
#
# Works on the systemd user units. Run after systemd_install.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

FAIL=0
declare -A PORTS=(
    [cai]=$CAI_PORT [cloak]=$CLOAK_PORT [phishing]=$PHISHING_PORT
    [brain]=$BRAIN_PORT [kali-tools]=$KALI_TOOLS_PORT [raphael-api]=$RAPHAEL_API_PORT
)

wait_ok() {
    local port="$1" i
    for i in $(seq 1 20); do
        if curl -s -m "$HEALTH_TIMEOUT" "http://127.0.0.1:${port}/health" | grep -q '"status": *"ok"'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

for svc in "${!PORTS[@]}"; do
    port="${PORTS[$svc]}"
    unit="raphael-${svc}.service"
    echo "--- ${svc} (port ${port}) ---"
    if ! systemctl --user is-active --quiet "$unit"; then
        echo "SKIP (unit not active) — install units first: scripts/systemd_install.sh"
        FAIL=1; continue
    fi
    echo "killing ${unit} with SIGKILL (simulated arbitrary death)"
    systemctl --user kill --signal=SIGKILL "$unit"
    if wait_ok "$port"; then
        echo "RECOVERED: ${svc} back to status: ok on port ${port} after SIGKILL"
    else
        echo "FAILED: ${svc} did not recover within 20s"
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then echo "RESTART TEST FAILED"; exit 1; fi
echo "RESTART TEST PASSED — every core service survives arbitrary death via systemd."
