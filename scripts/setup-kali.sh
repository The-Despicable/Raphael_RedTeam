#!/usr/bin/env bash
# scripts/setup-kali.sh — host toolchain install (no Docker, no image).
#
# Run BEFORE `scripts/native_up.sh`. Idempotent. Ordering is load-bearing:
#   1. apt-get update ONLY  (never upgrade/full-upgrade — the stack is pinned)
#   2. cleanup/forensics set FIRST — the kali service and the evasion module
#      both assume srm/bleachbit/wipe/tsk/auditctl exist
#   3. network / web / AD / stealth set
#   4. python service deps
#   5. build tools/broadscan from source (the binary is gitignored)
#   6. verify against configs/tool-catalog.json
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

say() { echo "[setup-kali] $*"; }

say "apt-get update (never upgrade — stack is version-locked)"
$SUDO apt-get update -y

say "phase 1: cleanup/forensics (must precede the kali service)"
$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    secure-delete bleachbit wipe sleuthkit auditd coreutils

say "phase 2: network / web / AD / stealth"
$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap masscan nuclei feroxbuster ffuf whatweb fping curl \
    smbclient rpcclient impacket-scripts \
    proxychains4 tor wireguard-tools openvpn golang-go

# crackmapexec was renamed; install whichever the distro ships.
if ! command -v crackmapexec >/dev/null 2>&1 && ! command -v nxc >/dev/null 2>&1; then
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nxc 2>/dev/null || $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends crackmapexec
fi

# bloodhound.py: package name varies (bloodhound.py / bloodhound-python).
if ! command -v bloodhound-python >/dev/null 2>&1; then
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bloodhound.py 2>/dev/null || true
fi

say "phase 3: python service deps"
"$RAPHAEL_PY" -m pip install --quiet \
    fastapi "uvicorn[standard]" httpx aiosqlite pydantic pydantic-settings \
    paramiko cryptography pytest 2>/dev/null || \
  say "pip install failed — run: $RAPHAEL_PY -m pip install -r configs/requirements.txt"

say "phase 3b: vendored stealth browser (installs into .venv, not /tmp)"
"$RAPHAEL_PY" -m pip install --quiet -e tools/cloakbrowser 2>/dev/null \
  || say "cloakbrowser editable install failed; bridge will report NotConfigured"

say "phase 4: build broadscan from source (binary is gitignored)"
if command -v go >/dev/null 2>&1; then
    ( cd tools/broadscan && go build -trimpath -o bin/broadscan . ) \
      && say "broadscan built -> tools/broadscan/bin/broadscan" \
      || say "broadscan build FAILED"
else
    say "go not found — install golang-go, then: (cd tools/broadscan && go build -o bin/broadscan .)"
fi

say "phase 5: capability grants (per-binary, never global root)"
for t in nmap masscan fping; do
    bin="$(command -v "$t" 2>/dev/null || true)"
    [ -n "$bin" ] && $SUDO setcap cap_net_raw,cap_net_admin+ep "$bin" 2>/dev/null || true
done

say "phase 6: verification against configs/tool-catalog.json"
"$RAPHAEL_PY" scripts/check_tools.py || true
if ! "$RAPHAEL_PY" scripts/check_tools.py --strict; then
    say "REQUIRED TOOLS MISSING — do not start the native kali service yet."
    say "Fix the FAIL rows above (pupy is a known non-gating deferral)."
    exit 1
fi
say "all required tools present. Native kali service may start."
