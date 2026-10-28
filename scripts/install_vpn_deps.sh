#!/usr/bin/env bash
# install_vpn_deps.sh — host prerequisites for the Raphael external-target bridge.
#
# Idempotent. NEVER hardcodes a sudo password: if not root it requires
# passwordless sudo (sudo -n) and aborts with instructions otherwise.
#
# Usage:  sudo ./scripts/install_vpn_deps.sh          (recommended)
#         ./scripts/install_vpn_deps.sh               (root or sudo -n)
set -euo pipefail

log()  { printf '[install_vpn_deps] %s\n' "$*" >&2; }
die()  { printf '[install_vpn_deps] ERROR: %s\n' "$*" >&2; exit 1; }

# --- privileges (no hardcoded passwords — NON-NEGOTIABLE) ------------------
if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true 2>/dev/null; then
        log "re-running as root via passwordless sudo"
        exec sudo -n "$0" "$@"
    else
        die "run as root: sudo $0 (this script never hardcodes sudo passwords)"
    fi
fi

# --- packages ----------------------------------------------------------------
PKGS=(openvpn curl ca-certificates dnsutils iproute2 iptables iputils-ping openssh-client)
if command -v apt-get >/dev/null 2>&1; then
    log "apt-get installing: ${PKGS[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "${PKGS[@]}"
else
    missing=0
    for p in openvpn curl dig ip ssh; do
        command -v "$p" >/dev/null 2>&1 || { log "missing: $p"; missing=1; }
    done
    [ "$missing" -eq 0 ] || die "non-Debian host: install these manually: ${PKGS[*]}"
fi

# --- TUN device (required by openvpn; WSL2 kernels usually expose it) --------
if [ ! -e /dev/net/tun ]; then
    log "/dev/net/tun missing — creating node (c 10 200)"
    mkdir -p /dev/net
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 || true
fi
if [ -e /dev/net/tun ]; then
    log "TUN device present: $(ls -l /dev/net/tun 2>/dev/null || echo '/dev/net/tun')"
else
    log "WARNING: /dev/net/tun unavailable. On WSL2:"
    log "  - verify kernel TUN support: grep -i tun /proc/misc"
    log "  - or use the containerized vpn-gateway (compose profile: vpn)"
fi

# --- sanity checks -------------------------------------------------------------
openvpn --version | head -1 || die "openvpn failed to execute"
command -v dig  >/dev/null || die "dig missing (dnsutils)"
command -v curl >/dev/null || die "curl missing"

# --- sysctl hints (no forced mutation; informational) ---------------------------
if [ -f /proc/sys/net/ipv4/ip_forward ]; then
    fwd=$(cat /proc/sys/net/ipv4/ip_forward)
    log "net.ipv4.ip_forward=$fwd (leave 1 only when routing for other hosts)"
fi
log "polkit: bridge runs openvpn as the calling user; no polkit rule required"
log "NOTE: do NOT commit .env — VPN credentials stay gitignored on the host"
log "OK — all VPN dependencies present"
