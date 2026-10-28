#!/usr/bin/env bash
# scripts/systemd_install.sh — install systemd USER units for every core service.
# Equivalent of compose `restart: unless-stopped`: services come back after
# crash, reboot, or arbitrary process death — no manual bash required.
#
# Usage:
#   scripts/systemd_install.sh          # install + enable + start (user units)
#   scripts/systemd_install.sh --uninstall
set -euo pipefail
cd "$(dirname "$0")/.."
source ./env.sh

UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$UNIT_DIR"

UNINSTALL=0
[ "${1:-}" = "--uninstall" ] && UNINSTALL=1

SERVICES=(cai cloak phishing brain kali-tools raphael-api)

if [ "$UNINSTALL" -eq 1 ]; then
    for s in "${SERVICES[@]}"; do
        systemctl --user disable --now "raphael-${s}.service" 2>/dev/null || true
        rm -f "${UNIT_DIR}/raphael-${s}.service"
    done
    systemctl --user daemon-reload
    echo "[systemd_install] units uninstalled."
    exit 0
fi

install_unit() {
    local name="$1" port="$2" module="$3"
    local unit="${UNIT_DIR}/raphael-${name}.service"
    cat > "$unit" <<EOF
[Unit]
Description=Raphael ${name} (native, port ${port})
After=network.target

[Service]
Type=simple
WorkingDirectory=${RAPHAEL_ROOT}
Environment=PYTHONPATH=${RAPHAEL_ROOT}:${RAPHAEL_ROOT}/src
Environment=KALI_TOOLS_URL=http://127.0.0.1:${KALI_TOOLS_PORT}
Environment=RAPHAEL_LOG_DIR=${RAPHAEL_LOG_DIR}
ExecStart=${UVICORN_BIN:-$(command -v uvicorn || echo uvicorn)} ${module} --host 127.0.0.1 --port ${port}
Restart=always
RestartSec=3
StandardOutput=append:${RAPHAEL_LOG_DIR}/${name}.log
StandardError=append:${RAPHAEL_LOG_DIR}/${name}.log

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now "raphael-${name}.service"
    echo "[systemd_install] installed + started raphael-${name}.service (port ${port})"
}

install_unit cai         "$CAI_PORT"         "$CAI_MODULE"
install_unit cloak       "$CLOAK_PORT"       "$CLOAK_MODULE"
install_unit phishing    "$PHISHING_PORT"    "$PHISHING_MODULE"
install_unit brain       "$BRAIN_PORT"       "$BRAIN_MODULE"
install_unit kali-tools  "$KALI_TOOLS_PORT"  "$KALI_TOOLS_MODULE"
install_unit raphael-api "$RAPHAEL_API_PORT" "$RAPHAEL_API_MODULE"

echo "[systemd_install] all units live. Logs: ${RAPHAEL_LOG_DIR}/<service>.log"
echo "[systemd_install] verify: systemctl --user status raphael-brain.service"
