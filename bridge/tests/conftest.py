"""Shared fixtures for bridge tests. Run from repo root:

    python -m pytest bridge/tests -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.bridge.external_target_manager import (  # noqa: E402
    EgressPolicy,
    EgressProfile,
    ExternalTargetManager,
)

CLEAN_ENV = {
    # keep tests hermetic: no host .env / proxies / configured components
    "EGRESS_STRATEGY": "",
    "TOR_SOCKS": "",
    "TOR_CONTROL": "",
    "KALI_TOOLS_URL": "",
    "OUTBOUND_PROXY": "",
    "VPN_PROFILE_PATH": "",
    "VPN_USERNAME": "",
    "VPN_PASSWORD": "",
    "DNS_PRIMARY": "",
    "DNS_SECONDARY": "",
    "DNS_CORPORATE": "",
    "BRIDGE_LOCAL_TOOLS": "",
    "BRIDGE_ENGAGEMENT": "",
    "SLIVER_OPERATOR_CONFIG": "",
    "NEO4J_URI": "",
}


@pytest.fixture()
def audit_root(tmp_path):
    return tmp_path / "projects"


@pytest.fixture()
def manager(audit_root):
    return ExternalTargetManager(
        env=CLEAN_ENV, repo_root=REPO_ROOT, audit_root=audit_root
    )


PROFILE_OBJ = {
    "engagement_id": "eng-test-01",
    "cidrs": ["10.10.10.0/24"],
    "urls": ["*.target.example", "victim.example"],
    "egress": "tor",
    "credentials": {"vpn_username": "vpnuser", "vpn_password": "vpnpass"},
    "allowed_ports": [80, 443, 22],
}


@pytest.fixture()
def loaded_manager(manager):
    """Manager with a valid engagement profile pre-loaded."""
    manager.profile = EgressProfile.from_obj(PROFILE_OBJ)
    return manager


VALID_OVPN = """\
# test profile
client
dev tun
proto tcp
remote vpn.example.org 1194 tcp
remote vpn2.example.org 443
resolv-retry infinite
auth-user-pass
ca inline-ca.pem
cipher AES-256-GCM
"""

UNSAFE_OVPN = """\
client
dev tun
remote vpn.example.org 1194
script-security 2
up /etc/openvpn/update-resolv.sh
down /etc/openvpn/down.sh
"""


def write_ovpn(tmp_path, text=VALID_OVPN, name="profile.ovpn"):
    p = tmp_path / name
    p.write_text(text)
    return p
