#!/usr/bin/env bash
# scripts/setup-kali.sh — host-side Kali tool install.
#
# MUST run BEFORE the native kali service starts (native_up.sh preflight
# calls this only if missing tools are detected; you can also run it
# manually first).
#
# Ordering rules (per spec):
#   1. apt-get update ONLY (never apt-get upgrade / full-upgrade — the stack
#      is PASS-locked; an upgrade would pull new tool versions and break
#      pinned offsets).
#   2. Install the cleanup/forensics set (srm bleachbit wipe sleuthkit
#      auditd) BEFORE anything else — the native kali service and the
#      local_tools_manager both expect these present.
#   3. Then the network/web/AD tool set.
#   4. Then pip-level tooling (uvicorn, httpx) if not present.
#
# GAP-006: bloodhound 1.9.0 + pupy must remain available. This script
# verifies their presence at the end and fails loudly if missing.
set -euo pipefail

echo "[setup-kali] apt update (never upgrade — stack is version-locked)"
sudo apt-get update -y

echo "[setup-kali] phase 1: cleanup/forensics set (MUST precede kali service start)"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    srm bleachbit wipe sleuthkit auditd

echo "[setup-kali] phase 2: network / web / AD tool set"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap masscan nuclei feroxbuster ffuf whatweb fping curl \
    crackmapexec smbclient rpcclient \
    impacket-scripts \
    proxychains4 tor

echo "[setup-kali] phase 3: python service deps"
python3 -m pip install --quiet uvicorn httpx 2>/dev/null || pip3 install --quiet uvicorn httpx

echo "[setup-kali] phase 4: GAP-006 verification (bloodhound 1.9.0 + pupy)"
fail=0
for t in nmap srm bleachbit wipe bloodhound pupy auditctl; do
    if command -v "$t" >/dev/null 2>&1; then
        echo "  [ok]   $t -> $(command -v $t)"
    else
        echo "  [FAIL] $t missing"
        fail=1
    fi
done
if [ "$fail" -ne 0 ]; then
    echo "[setup-kali] GAP-006 FAILED — bloodhound/pupy or cleanup set missing."
    echo "               Install manually before starting the native kali service."
    exit 1
fi
echo "[setup-kali] all required tools present. Native kali service may start."
