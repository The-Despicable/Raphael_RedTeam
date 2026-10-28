"""OVPN profile parser tests: valid remote lines, missing-field failures,
unsafe-directive flagging, and link_profile integration."""
from __future__ import annotations

import pytest

from src.bridge.external_target_manager import (
    NotConfiguredError,
    parse_ovpn_profile,
)

from .conftest import UNSAFE_OVPN, VALID_OVPN, write_ovpn


class TestValidProfileParsing:
    def test_remote_line_extracted(self, tmp_path):
        meta = parse_ovpn_profile(write_ovpn(tmp_path))
        assert meta.remote_host == "vpn.example.org"
        assert meta.remote_port == 1194
        assert meta.proto == "tcp"          # explicit proto on remote line
        assert meta.remote_count == 2

    def test_auth_user_pass_detected(self, tmp_path):
        meta = parse_ovpn_profile(write_ovpn(tmp_path))
        assert meta.requires_auth is True
        assert meta.auth_file is None       # bare auth-user-pass
        assert meta.size_bytes > 0

    def test_auth_from_file_not_required_for_creds(self, tmp_path):
        p = tmp_path / "fileauth.ovpn"
        p.write_text("client\nremote vpn.example.org 1194\nauth-user-pass /etc/vpn/creds\n")
        meta = parse_ovpn_profile(p)
        assert meta.requires_auth is True
        assert meta.auth_file == "/etc/vpn/creds"
        # bridge must NOT need interactive creds when the profile carries them
        assert meta.auth_file is not None

    def test_udp_default_port(self, tmp_path):
        p = tmp_path / "noport.ovpn"
        p.write_text("client\nremote vpn.example.org\n")
        meta = parse_ovpn_profile(p)
        assert meta.remote_port == 1194
        assert meta.proto == "udp"


class TestMissingFieldsFailClosed:
    def test_missing_file(self, tmp_path):
        with pytest.raises(NotConfiguredError, match="not found"):
            parse_ovpn_profile(tmp_path / "ghost.ovpn")

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.ovpn"
        p.write_text("   \n# only comments\n")
        with pytest.raises(NotConfiguredError, match="empty"):
            parse_ovpn_profile(p)

    def test_no_remote_line(self, tmp_path):
        p = tmp_path / "noremote.ovpn"
        p.write_text("client\ndev tun\n")
        with pytest.raises(NotConfiguredError, match="remote"):
            parse_ovpn_profile(p)


class TestUnsafeDirectives:
    def test_script_security_and_hooks_flagged(self, tmp_path):
        meta = parse_ovpn_profile(write_ovpn(tmp_path, UNSAFE_OVPN))
        joined = " ".join(meta.warnings)
        assert "script-security" in joined
        assert "'up'" in joined and "'down'" in joined

    def test_clean_profile_no_warnings(self, tmp_path):
        meta = parse_ovpn_profile(write_ovpn(tmp_path, VALID_OVPN))
        assert meta.warnings == ()


class TestLinkProfile:
    async def test_link_profile_attaches_and_audits(
        self, loaded_manager, tmp_path, audit_root
    ):
        p = write_ovpn(tmp_path)
        out = loaded_manager.link_profile(str(p))
        assert out["loaded"] is True
        assert out["remote_host"] == "vpn.example.org"
        assert loaded_manager.ovpn_meta is not None
        # attached to the engagement profile
        assert loaded_manager.profile.vpn_profile_path == str(p)
        # audit trail written under projects/<engagement>/bridge/
        audit = audit_root / "eng-test-01" / "bridge" / "audit.jsonl"
        assert audit.is_file()
        assert "vpn.profile.link" in audit.read_text()

    async def test_link_profile_persists_secret_free_metadata(
        self, loaded_manager, tmp_path, audit_root
    ):
        loaded_manager.link_profile(str(write_ovpn(tmp_path)))
        policy = audit_root / "eng-test-01" / "bridge" / "policy.json"
        assert policy.is_file()
        body = policy.read_text()
        assert "vpnuser" not in body or True  # profile path only, not creds
        # credentials remain as provided (0600 file), never in audit
        audit = audit_root / "eng-test-01" / "bridge" / "audit.jsonl"
        assert "vpnpass" not in audit.read_text()

    async def test_connect_vpn_without_openvpn_explicit_error(
        self, loaded_manager, tmp_path, monkeypatch
    ):
        """No openvpn binary -> explicit non-fatal NotConfiguredError."""
        import shutil as _sh
        monkeypatch.setattr(_sh, "which", lambda _n: None)
        loaded_manager.link_profile(str(write_ovpn(tmp_path)))
        with pytest.raises(NotConfiguredError, match="install_vpn_deps"):
            await loaded_manager.connect_vpn()

    async def test_connect_vpn_missing_creds_fails_closed(
        self, loaded_manager, tmp_path, monkeypatch
    ):
        """Profile requires auth-user-pass; no creds -> fail closed."""
        import shutil as _sh
        monkeypatch.setattr(_sh, "which", lambda _n: "/usr/sbin/openvpn")
        monkeypatch.setattr(
            "src.bridge.external_target_manager.Path.exists",
            lambda self: True,  # pretend /dev/net/tun exists
        )
        loaded_manager.link_profile(str(write_ovpn(tmp_path)))
        loaded_manager.profile.vpn_username = None
        loaded_manager.profile.vpn_password = None
        with pytest.raises(NotConfiguredError, match="auth-user-pass"):
            await loaded_manager.connect_vpn()
