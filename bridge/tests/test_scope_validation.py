"""Scope validation tests: only declared targets pass, everything else
(including targets with no profile loaded) is refused — fail closed."""
from __future__ import annotations

import json

import pytest

from src.bridge.external_target_manager import (
    EgressPolicy,
    EgressProfile,
    NotConfiguredError,
    PolicyViolationError,
)

from .conftest import PROFILE_OBJ


class TestFailClosed:
    async def test_no_profile_validate_returns_false(self, manager):
        assert await manager.validate_target_scope("10.10.10.1") is False

    async def test_no_profile_run_tool_raises(self, manager):
        with pytest.raises(NotConfiguredError, match="fail closed"):
            await manager.run_tool("nmap", ["-Pn", "10.10.10.1"], "10.10.10.1")

    async def test_no_profile_check_reachability_raises(self, manager):
        with pytest.raises(NotConfiguredError):
            await manager.check_reachability("10.10.10.1", [80])

    async def test_empty_scope_cidrs_rejected(self, manager):
        with pytest.raises(PolicyViolationError, match="target_scope_cidr"):
            EgressProfile.from_obj(
                {**PROFILE_OBJ, "engagement_id": "bad-scope", "cidrs": []}
            )

    async def test_invalid_cidr_rejected(self, manager):
        with pytest.raises(PolicyViolationError, match="invalid CIDR"):
            EgressProfile.from_obj(
                {**PROFILE_OBJ, "engagement_id": "bad-cidr",
                 "cidrs": ["10.10.10.999/24"]}
            )

    async def test_engagement_id_path_traversal_rejected(self, manager):
        for bad in ("../../etc", "a b", ".hidden", "x" * 65):
            with pytest.raises(PolicyViolationError):
                EgressProfile.from_obj(
                    {**PROFILE_OBJ, "engagement_id": bad}
                )


class TestIpScope:
    async def test_ip_in_scope(self, loaded_manager):
        assert await loaded_manager.validate_target_scope("10.10.10.7") is True

    async def test_ip_out_of_scope(self, loaded_manager):
        assert await loaded_manager.validate_target_scope("192.168.1.1") is False

    async def test_ip_port_form_in_scope(self, loaded_manager):
        assert await loaded_manager.validate_target_scope("10.10.10.7:443") is True

    async def test_url_form_in_scope(self, loaded_manager):
        assert await loaded_manager.validate_target_scope(
            "https://10.10.10.7:443/app"
        ) is True

    async def test_cidr_subrange_in_scope(self, loaded_manager):
        assert await loaded_manager.validate_target_scope("10.10.10.0/25") is True

    async def test_cidr_superset_out_of_scope(self, loaded_manager):
        # /16 is larger than the allowed /24 — must NOT pass
        assert await loaded_manager.validate_target_scope("10.10.0.0/16") is False


class TestHostScope:
    async def test_wildcard_host_matches(self, loaded_manager):
        assert await loaded_manager.validate_target_scope(
            "web.target.example") is True
        assert await loaded_manager.validate_target_scope(
            "https://api.target.example:443") is True

    async def test_wildcard_bare_domain_not_matched(self, loaded_manager):
        # "*.target.example" must not match the bare apex
        assert await loaded_manager.validate_target_scope(
            "target.example") is False

    async def test_exact_host_scope(self, loaded_manager):
        assert await loaded_manager.validate_target_scope("victim.example") is True
        assert await loaded_manager.validate_target_scope("other.example") is False

    async def test_random_internet_host_refused(self, loaded_manager):
        assert await loaded_manager.validate_target_scope("google.com") is False
        assert await loaded_manager.validate_target_scope("1.1.1.1") is False


class TestPortScope:
    async def test_allowed_port_passes(self, loaded_manager):
        assert await loaded_manager.validate_target_scope("10.10.10.7:443") is True

    async def test_disallowed_port_refused(self, loaded_manager):
        # 8080 not in allowed_ports [80, 443, 22]
        assert await loaded_manager.validate_target_scope("10.10.10.7:8080") is False


class TestRunToolScopeEnforcement:
    async def test_run_tool_out_of_scope_refused(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="outside engagement scope"):
            await loaded_manager.run_tool(
                "nmap", ["-sV", "192.168.1.1"], "192.168.1.1"
            )

    async def test_run_tool_shell_metachar_tool_name_refused(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="invalid tool name"):
            await loaded_manager.run_tool(
                "nmap; rm -rf /", ["-Pn", "10.10.10.1"], "10.10.10.1"
            )

    async def test_run_tool_null_byte_arg_refused(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="null byte"):
            await loaded_manager.run_tool(
                "nmap", ["-Pn\x00evil"], "10.10.10.1"
            )

    async def test_run_tool_kali_unreachable_explicit_error(self, loaded_manager):
        """Kali configured but unreachable -> ComponentError, not a crash."""
        from src.bridge.external_target_manager import ComponentError
        loaded_manager.env["KALI_TOOLS_URL"] = "http://127.0.0.1:1/kali"
        with pytest.raises(ComponentError, match="kali-tools unreachable"):
            await loaded_manager.run_tool(
                "nmap", ["-Pn", "10.10.10.1"], "10.10.10.1"
            )

    async def test_run_tool_kali_unconfigured_explicit_error(self, loaded_manager):
        """Kali absent + local fallback off -> explicit NotConfiguredError."""
        with pytest.raises(NotConfiguredError,
                           match="KALI_TOOLS_URL not configured"):
            await loaded_manager.run_tool(
                "nmap", ["-Pn", "10.10.10.1"], "10.10.10.1"
            )

    async def test_run_tool_local_fallback_allowlisted(
        self, loaded_manager, monkeypatch, audit_root
    ):
        """Opt-in local fallback runs allowlisted tool, shell-free, audited."""
        import shutil as _sh
        loaded_manager.env["BRIDGE_LOCAL_TOOLS"] = "1"
        monkeypatch.setattr(_sh, "which", lambda n: f"/usr/bin/{n}")
        monkeypatch.setattr(
            "src.bridge.external_target_manager."
            "ExternalTargetManager._run_local_allowlisted",
            lambda self, tool, argv, timeout: _fake_local(tool, argv, timeout),
        )
        async def _fake_local(tool, argv, timeout):
            return {"stdout": "fake", "stderr": "", "exit_code": 0,
                    "routed": "local", "fallback_used": True}
        out = await loaded_manager.run_tool(
            "nmap", ["-Pn"], "10.10.10.1"
        )
        assert out["routed"] == "local"
        audit = audit_root / "eng-test-01" / "bridge" / "audit.jsonl"
        assert "kali.run" in audit.read_text()

    async def test_run_tool_local_fallowlist_rejects_unknown_tool(
        self, loaded_manager, monkeypatch
    ):
        """Local fallback only runs tools inside the allowlist (no sqlmap)."""
        import shutil as _sh
        loaded_manager.env["BRIDGE_LOCAL_TOOLS"] = "1"
        monkeypatch.setattr(_sh, "which", lambda n: f"/usr/bin/{n}")
        with pytest.raises(PolicyViolationError, match="not in local allowlist"):
            await loaded_manager.run_tool("sqlmap", [], "10.10.10.1")


class TestTargetsSetViaBridge:
    async def test_targets_set_persists_and_answers_policy(self, audit_root):
        from bridge.raphael_bridge import RaphaelBridge
        mgr = None  # built inside to avoid env bleed
        import src.bridge.external_target_manager as etm
        mgr = etm.ExternalTargetManager(
            env={"EGRESS_STRATEGY": "tor", "KALI_TOOLS_URL": "",
                 "BRIDGE_LOCAL_TOOLS": ""},
            repo_root=audit_root.parents[0] if False else None,
            audit_root=audit_root,
        )
        b = RaphaelBridge(mgr)

        raw = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "targets.set",
            "params": PROFILE_OBJ,
        })
        resp = await b.handle_line(raw)
        assert "result" in resp, resp
        res = resp["result"]
        assert res["engagement_id"] == "eng-test-01"
        assert "policy_file" in res
        assert res["has_vpn_credentials"] is True

        # persisted file exists and is secret-bearing (0600 store)
        pol = audit_root / "eng-test-01" / "bridge" / "policy.json"
        assert pol.is_file()
        body = pol.read_text()
        assert "vpnpass" in body  # credentials persisted for cross-session use

        # get_policy returns contract shape, never secrets
        resp2 = await b.handle_line(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "targets.get_policy",
            "params": {"engagement_id": "eng-test-01"},
        }))
        pol_view = resp2["result"]
        assert pol_view["scope_cidrs"] == ["10.10.10.0/24"]
        assert pol_view["egress_policy"] == "proxy_tor"
        assert pol_view["max_rate"] == 30
        assert "vpn_password" not in json.dumps(pol_view)

    async def test_targets_set_without_cidrs_fails(self, manager, audit_root):
        from bridge.raphael_bridge import RaphaelBridge
        b = RaphaelBridge(manager)
        resp = await b.handle_line(json.dumps({
            "jsonrpc": "2.0", "id": 9, "method": "targets.set",
            "params": {"engagement_id": "no-cidrs", "urls": ["x.example"]},
        }))
        assert resp["error"]["code"] == -32602
        assert "cidrs" in resp["error"]["message"]
