"""broadscan scope gate: planning must refuse anything outside the profile
before a probe is sent, cap the rate at the engagement ceiling, and fail
closed with no profile loaded."""
from __future__ import annotations

import pytest

from src.bridge.broadscan import BroadscanRunner
from src.bridge.external_target_manager import (
    NotConfiguredError,
    PolicyViolationError,
)


class TestNoProfile:
    def test_plan_requires_profile(self, manager):
        with pytest.raises(NotConfiguredError, match="fail closed"):
            BroadscanRunner(manager).plan(["10.10.10.7"])

    def test_scope_requires_profile(self, manager):
        with pytest.raises(NotConfiguredError):
            BroadscanRunner(manager).scope()


class TestScope:
    def test_in_scope_cidr_passes(self, loaded_manager):
        plan = BroadscanRunner(loaded_manager).plan(["10.10.10.0/24"], ports=[80])
        assert plan["targets"] == ["10.10.10.0/24"]
        assert plan["scope"]["allow"] == ["10.10.10.0/24"]

    def test_superset_cidr_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="outside engagement scope"):
            BroadscanRunner(loaded_manager).plan(["10.10.0.0/16"], ports=[80])

    def test_unrelated_cidr_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError):
            BroadscanRunner(loaded_manager).plan(["192.168.1.0/24"], ports=[80])

    def test_empty_targets_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="empty"):
            BroadscanRunner(loaded_manager).plan([], ports=[80])

    def test_deny_cidrs_subtracted_in_gate_file(self, loaded_manager):
        loaded_manager.profile.meta["deny_cidrs"] = ["10.10.10.128/25"]
        scope = BroadscanRunner(loaded_manager).scope()
        assert scope["deny"] == ["10.10.10.128/25"]

    def test_invalid_deny_cidr_rejected(self, loaded_manager):
        loaded_manager.profile.meta["deny_cidrs"] = ["10.10.10.999/25"]
        with pytest.raises(PolicyViolationError, match="invalid deny CIDR"):
            BroadscanRunner(loaded_manager).scope()


class TestPorts:
    def test_declared_ports_only(self, loaded_manager):
        runner = BroadscanRunner(loaded_manager)
        assert runner.plan(["10.10.10.7"], ports=[22, 80])["ports"] == "22,80"

    def test_undeclared_port_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="not in allowed_ports"):
            BroadscanRunner(loaded_manager).plan(["10.10.10.7"], ports=[3306])

    def test_range_expands_and_is_checked(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="not in allowed_ports"):
            BroadscanRunner(loaded_manager).plan(["10.10.10.7"], ports=["80-82"])

    def test_bad_port_string_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="bad port"):
            BroadscanRunner(loaded_manager).plan(["10.10.10.7"], ports=["http"])


class TestRate:
    def test_rate_capped_at_profile_ceiling(self, loaded_manager):
        loaded_manager.profile.max_packet_rate = 200
        plan = BroadscanRunner(loaded_manager).plan(["10.10.10.7"], rate=50_000)
        assert plan["rate"] == 200

    def test_default_rate_is_the_ceiling(self, loaded_manager):
        loaded_manager.profile.max_packet_rate = 75
        plan = BroadscanRunner(loaded_manager).plan(["10.10.10.7"])
        assert plan["rate"] == 75

    def test_zero_rate_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="rate"):
            BroadscanRunner(loaded_manager).plan(["10.10.10.7"], rate=0)


class TestOpsec:
    def test_opsec_requires_syn(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="opsec requires syn"):
            BroadscanRunner(loaded_manager).plan(["10.10.10.7"], opsec=True)

    def test_opsec_sets_defaults_and_drops_banners(self, loaded_manager):
        plan = BroadscanRunner(loaded_manager).plan(
            ["10.10.10.7"], ports=[80], syn=True, opsec=True
        )
        assert plan["opsec"] is True
        assert plan["banners"] is False
        assert plan["jitter_ms"] == 25
        assert plan["ttl"] == "48-64"
        assert plan["sport"] == "random"

    def test_decoys_inside_scope_pass(self, loaded_manager):
        plan = BroadscanRunner(loaded_manager).plan(
            ["10.10.10.7"], ports=[80], syn=True, opsec=True,
            decoys=["10.10.10.64/29"],
        )
        assert plan["decoys"] == ["10.10.10.64/29"]

    def test_decoys_outside_scope_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="decoy source"):
            BroadscanRunner(loaded_manager).plan(
                ["10.10.10.7"], ports=[80], syn=True, opsec=True,
                decoys=["198.51.100.0/24"],
            )

    def test_frag_must_be_multiple_of_eight(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="multiple of 8"):
            BroadscanRunner(loaded_manager).plan(
                ["10.10.10.7"], ports=[80], syn=True, frag=12
            )

    def test_bad_ttl_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="ttl"):
            BroadscanRunner(loaded_manager).plan(
                ["10.10.10.7"], ports=[80], syn=True, ttl="300"
            )

    def test_bad_sport_rejected(self, loaded_manager):
        with pytest.raises(PolicyViolationError, match="sport"):
            BroadscanRunner(loaded_manager).plan(
                ["10.10.10.7"], ports=[80], syn=True, sport="seq"
            )


class TestBinary:
    def test_missing_binary_is_reported(self, loaded_manager, monkeypatch):
        monkeypatch.setenv("BROADSCAN_BIN", "/nonexistent/broadscan")
        with pytest.raises(NotConfiguredError, match="not an executable"):
            BroadscanRunner(loaded_manager).binary()

    def test_repo_binary_or_clear_error(self, loaded_manager):
        runner = BroadscanRunner(loaded_manager)
        try:
            path = runner.binary()
        except NotConfiguredError as e:
            assert "make -C tools/broadscan" in str(e)
        else:
            assert path.endswith("broadscan")
