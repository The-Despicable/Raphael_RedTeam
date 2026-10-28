"""Egress policy tests: TOR must not leak DNS, VPN interface checks,
policy switching persistence, and canary leak heuristics."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path

import pytest

import src.bridge.external_target_manager as etm
from src.bridge.external_target_manager import (
    EgressPolicy,
    PolicyViolationError,
)

from .conftest import PROFILE_OBJ


class TestTorDnsNoLeak:
    async def test_resolve_inscope_host_defers_to_socks(self, loaded_manager):
        """Under proxy_tor, in-scope hostnames never hit a local resolver."""
        assert loaded_manager.profile.egress is EgressPolicy.PROXY_TOR
        res = await loaded_manager.resolve("evil.target.example")
        assert res["deferred_to_proxy"] is True
        assert res["addresses"] == []
        assert res["via"].startswith("socks5h://")

    async def test_resolve_makes_no_local_query_under_tor(
        self, loaded_manager, monkeypatch
    ):
        """The deferred path must not touch socket/dnspython at all."""
        called = {"socket": False, "dns": False}

        async def _socket_spy(self, h):
            called["socket"] = True
            return ["127.0.0.1"]

        monkeypatch.setattr(
            etm.ExternalTargetManager, "_socket_resolve", _socket_spy
        )

        import dns.asyncresolver as _ar  # ensure module importable
        real_resolve = _ar.Resolver.resolve

        async def _dns_spy(self, *a, **kw):
            called["dns"] = True
            return await real_resolve(self, *a, **kw)

        monkeypatch.setattr(_ar.Resolver, "resolve", _dns_spy)

        await loaded_manager.resolve("web.target.example")
        assert called == {"socket": False, "dns": False}

    async def test_canary_resolves_normally_under_tor(self, loaded_manager):
        res = await loaded_manager.resolve("example.com")
        assert res.get("deferred_to_proxy") is None
        assert res["addresses"]  # sandbox/CI DNS; canaries allowed

    async def test_out_of_scope_host_refused_even_under_tor(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="outside engagement scope"):
            await loaded_manager.resolve("not-declared.example.org")

    async def test_check_reachability_hostname_refused_under_tor(
        self, loaded_manager
    ):
        """Raw TCP to a hostname would leak DNS — policy refuses."""
        loaded_manager.profile.urls = ("*.target.example",)
        with pytest.raises(PolicyViolationError, match="leak DNS under tor"):
            await loaded_manager.check_reachability("web.target.example", [443])

    async def test_check_reachability_ip_literal_allowed_under_tor(
        self, loaded_manager
    ):
        res = await loaded_manager.check_reachability("10.10.10.7", [443], timeout=1.0)
        assert res["host"] == "10.10.10.7"
        assert all(p["state"] in ("open", "closed", "filtered") for p in res["ports"])


class TestVpnInterfaceCheck:
    def test_tun_up_detected(self, loaded_manager, monkeypatch):
        monkeypatch.setattr(
            etm, "_tun_up", lambda: True, raising=True
        )
        assert etm._tun_up() is True

    def test_tun_down_when_no_tun_iface(self, monkeypatch):
        monkeypatch.setattr(os, "listdir", lambda p: ["eth0", "lo", "docker0"])
        assert etm._tun_up() is False

    def test_tun_up_via_sys_class_net(self, monkeypatch):
        monkeypatch.setattr(
            os, "listdir", lambda p: ["eth0", "lo", "tun0"]
        )
        assert etm._tun_up() is True

    async def test_vpn_status_reports_tun_state(self, loaded_manager, monkeypatch):
        monkeypatch.setattr(etm, "_tun_up", lambda: True)
        out = await loaded_manager.vpn_status()
        assert out["connected"] is False       # no session
        assert out["tun_device_present"] in (True, False)
        assert out["openvpn_installed"] in (True, False)

    async def test_test_egress_reports_vpn_exposed(self, loaded_manager, monkeypatch):
        monkeypatch.setattr(etm, "_tun_up", lambda: True)
        monkeypatch.setattr(
            etm.ExternalTargetManager, "_canary_ip",
            lambda self, socks=None, url=None: _ip("203.0.113.9"),
        )

        async def _ip(v):
            return v
        loaded_manager.profile.egress = EgressPolicy.VPN
        out = await loaded_manager.test_egress()
        assert out["vpn_exposed"] is True
        assert out["exit_ip"] == "203.0.113.9"
        assert out["egress_policy"] == "vpn"


class TestLeakHeuristics:
    async def test_identical_ips_flag_leak(self, loaded_manager, monkeypatch):
        loaded_manager.profile.egress = EgressPolicy.PROXY_TOR

        async def _fixed_ip(self, socks=None, url=None):
            return "198.51.100.7"

        monkeypatch.setattr(
            etm.ExternalTargetManager, "_canary_ip", _fixed_ip
        )
        out = await loaded_manager.test_egress()
        assert out["leak_suspected"] is True   # tor exit == direct exit

    async def test_distinct_ips_no_leak(self, loaded_manager, monkeypatch):
        loaded_manager.profile.egress = EgressPolicy.PROXY_TOR
        direct = {"value": "198.51.100.7"}

        async def _ips(self, socks=None, url=None):
            return "198.51.100.8" if socks else direct["value"]

        monkeypatch.setattr(etm.ExternalTargetManager, "_canary_ip", _ips)
        out = await loaded_manager.test_egress()
        assert out["leak_suspected"] is False
        assert out["exit_ip"] == "198.51.100.8"
        assert out["direct_ip"] == "198.51.100.7"


class TestEgressPolicySwitching:
    async def test_modes_coerced_to_enum(self):
        assert EgressPolicy.coerce("tor") is EgressPolicy.PROXY_TOR
        assert EgressPolicy.coerce("proxy") is EgressPolicy.PROXY_TOR
        assert EgressPolicy.coerce("vpn") is EgressPolicy.VPN
        assert EgressPolicy.coerce("direct") is EgressPolicy.DIRECT
        assert EgressPolicy.coerce("ssh") is EgressPolicy.SSH_TUNNEL
        assert EgressPolicy.coerce("http_connect") is EgressPolicy.HTTP_CONNECT

    def test_unknown_mode_fails_closed(self):
        with pytest.raises(PolicyViolationError, match="unknown egress mode"):
            EgressPolicy.coerce("carrier-pigeon")

    async def test_egress_policy_set_persists(self, manager, audit_root):
        from bridge.raphael_bridge import RaphaelBridge
        manager.env["EGRESS_STRATEGY"] = "tor"
        b = RaphaelBridge(manager)

        # create the engagement first
        await b.handle_line(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "targets.set",
            "params": PROFILE_OBJ,
        }))
        # switch to vpn
        resp = await b.handle_line(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "egress_policy.set",
            "params": {"engagement_id": "eng-test-01", "mode": "vpn"},
        }))
        assert resp["result"]["egress_policy"] == "vpn"

        # persisted to disk
        pol = json.loads(
            (audit_root / "eng-test-01" / "bridge" / "policy.json").read_text()
        )
        assert pol["egress"] == "vpn"

        # fresh manager sees the updated policy from disk
        m2 = etm.ExternalTargetManager(
            env=manager.env, repo_root=manager.repo_root, audit_root=audit_root
        )
        summary = m2.load_engagement_policy("eng-test-01")
        assert summary["egress"] == "vpn"

    async def test_egress_policy_set_invalid_mode_rejected(self, manager):
        from bridge.raphael_bridge import RaphaelBridge
        manager.env["EGRESS_STRATEGY"] = "tor"
        b = RaphaelBridge(manager)
        await b.handle_line(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "targets.set",
            "params": PROFILE_OBJ,
        }))
        resp = await b.handle_line(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "egress_policy.set",
            "params": {"engagement_id": "eng-test-01", "mode": "carrier-pigeon"},
        }))
        assert resp["error"]["code"] == -32001


class TestAuditTrail:
    async def test_audit_record_shape(self, loaded_manager, audit_root):
        loaded_manager.audit({
            "action": "unit-test",
            "target": "10.10.10.1",
            "bytes": 1234,
            "duration_ms": 42,
            "status": "ok",
        })
        audit = audit_root / "eng-test-01" / "bridge" / "audit.jsonl"
        lines = audit.read_text().strip().splitlines()
        rec = json.loads(lines[-1])
        # HARD RULE: ts, source iface, target, bytes, duration, status
        for key in ("ts", "source_iface", "target", "bytes", "duration_ms",
                    "status", "engagement"):
            assert key in rec, f"missing {key}"
        assert rec["action"] == "unit-test"

    async def test_audit_never_stores_secrets(self, loaded_manager, audit_root):
        loaded_manager.audit({
            "action": "leaky", "target": "10.10.10.1",
            "vpn_password": "supersecret", "proxy_auth": "user:pass",
        })
        audit = audit_root / "eng-test-01" / "bridge" / "audit.jsonl"
        body = audit.read_text()
        assert "supersecret" not in body
        assert "user:pass" not in body
        assert '"***"' in body
