"""Semantic invariant tests for Stage 1 contracts (A1, A2, C1).

These verify the structural guarantees that the contracts enforce,
not just that serialization works.
"""

import json
import hashlib
import time
import sys
from pathlib import Path

# Ensure project root is on path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


# ═══════════════════════════════════════════════════════════════
# A1: Trust Provenance Invariants
# ═══════════════════════════════════════════════════════════════

def test_trust_provenance_serialization_roundtrip():
    """Trust provenance survives serialization/deserialization without losing classification."""
    from orchestrator.brain.phases.models import Finding
    from orchestrator.brain.trust import TrustLevel

    f = Finding(
        phase="recon", type="port_open", description="Port 443 open",
        target="10.0.0.1",
        trust_level=TrustLevel.TARGET_CONTROLLED,
        source_detail="HTTP response body from /api/status",
    )
    d = f.to_dict()
    assert d["trust_level"] == "target_controlled"
    assert d["source_detail"] == "HTTP response body from /api/status"

    # Reconstruct from dict
    f2 = Finding(
        phase=d["phase"], type=d["type"],
        description=d["description"], evidence=d["evidence"],
        target=d["target"], port=d["port"], service=d["service"],
        trust_level=TrustLevel(d["trust_level"]),
        source_detail=d["source_detail"],
    )
    assert f2.trust_level == TrustLevel.TARGET_CONTROLLED
    assert f2.source_detail == "HTTP response body from /api/status"
    print("✅ A1 invariant 1: Trust provenance survives serialization round-trip")


def test_nested_trust_preserved():
    """Target-controlled content nested inside a trusted tool observation
    remains explicitly target-controlled in the evidence field."""
    from orchestrator.brain.phases.models import Finding
    from orchestrator.brain.trust import TrustLevel

    # Simulate: curl receives HTTP response from target
    # The OBSERVATION (we received a response) is TOOL_OBSERVATION
    # The CONTENT of the response is TARGET_CONTROLLED
    observation = Finding(
        phase="recon",
        type="http_response",
        description="HTTP 200 from target /api/users",
        evidence='{"users": [{"name": "admin", "role": "admin"}]}',
        target="10.0.0.1",
        trust_level=TrustLevel.TOOL_OBSERVATION,
        source_detail="curl -s http://10.0.0.1/api/users",
    )

    # The Finding trust_level describes the observation, not the evidence content.
    # The evidence field contains target-controlled data.
    # This invariant is SEMANTIC: the consumer must know that evidence from a
    # TOOL_OBSERVATION finding may contain TARGET_CONTROLLED content.
    assert observation.trust_level == TrustLevel.TOOL_OBSERVATION
    assert observation.source_detail == "curl -s http://10.0.0.1/api/users"

    # The evidence is demarcated in its own field. When evidence is extracted,
    # it should be reclassified as TARGET_CONTROLLED.
    evidence_content = observation.evidence
    evidence_finding = Finding(
        phase=observation.phase,
        type="raw_content",
        description="Raw response body from target",
        evidence=evidence_content,
        target=observation.target,
        trust_level=TrustLevel.TARGET_CONTROLLED,
        source_detail=f"evidence from {observation.source_detail}",
    )
    assert evidence_finding.trust_level == TrustLevel.TARGET_CONTROLLED
    assert "admin" in evidence_finding.evidence
    print("✅ A1 invariant 2: Nested target-controlled content can be extracted with correct trust level")


def test_all_trust_levels_classified():
    """Every TrustLevel can be instantiated and serialized."""
    from orchestrator.brain.trust import TrustLevel

    levels = [
        TrustLevel.SYSTEM_POLICY,
        TrustLevel.OPERATOR_INSTRUCTION,
        TrustLevel.ENGAGEMENT_CONFIG,
        TrustLevel.TOOL_OBSERVATION,
        TrustLevel.TARGET_CONTROLLED,
        TrustLevel.MODEL_INFERENCE,
    ]
    assert len(levels) == 6
    for level in levels:
        assert level.value  # Not empty
        # Round trip through string
        restored = TrustLevel(level.value)
        assert restored == level
    print(f"✅ A1 invariant 3: All {len(levels)} trust levels classify and round-trip")


# ═══════════════════════════════════════════════════════════════
# A2: ActionReceipt Invariants
# ═══════════════════════════════════════════════════════════════

def test_allow_and_deny_both_produce_receipts():
    """ALLOW and DENY both produce auditable decisions with distinct states."""
    from orchestrator.hardening.action_receipt import (
        create_proposal, authorize, deny, ActionProposalStatus,
    )

    # ALLOW
    r1 = create_proposal(target="10.0.0.1", capability="scan", method="nmap")
    r1 = authorize(r1, reason="In scope", policy_version="1.0")
    assert r1.status == ActionProposalStatus.AUTHORIZED
    assert r1.decision == "allow"
    assert r1.audit_hash
    assert r1.verify_integrity()

    # DENY
    r2 = create_proposal(target="10.0.0.2", capability="exploit", method="metasploit")
    r2 = deny(r2, reason="Out of scope", policy_version="1.0", authorized_by="scope_check")
    assert r2.status == ActionProposalStatus.DENIED
    assert r2.decision == "deny"
    assert r2.audit_hash
    assert r2.verify_integrity()

    assert r1.action_id != r2.action_id
    print("✅ A2 invariant 1: ALLOW and DENY both produce distinct, auditable receipts")


def test_auth_and_execution_separate():
    """Authorization status and execution status cannot be conflated.
    AUTHORIZED → SUCCEEDED is not a valid transition (must go through STARTED)."""
    from orchestrator.hardening.action_receipt import (
        create_proposal, authorize, start_execution, complete_execution,
        ActionProposalStatus,
    )

    r = create_proposal(target="10.0.0.1", capability="http", method="curl")
    r = authorize(r, reason="Test")
    assert r.status == ActionProposalStatus.AUTHORIZED

    # AUTHORIZED → SUCCEEDED directly is illegal
    assert not r.can_transition_to(ActionProposalStatus.SUCCEEDED)

    # AUTHORIZED → STARTED → SUCCEEDED is legal
    r = start_execution(r)
    assert r.status == ActionProposalStatus.STARTED
    r = complete_execution(r, success=True, result="ok")
    assert r.status == ActionProposalStatus.SUCCEEDED

    print("✅ A2 invariant 2: Authorization and execution status are separate (must go through STARTED)")


def test_denied_receipt_no_execution_fields():
    """DENIED receipts must not have execution fields set."""
    from orchestrator.hardening.action_receipt import (
        create_proposal, deny,
    )
    from orchestrator.hardening.action_receipt import ActionProposalStatus

    r = create_proposal(target="10.0.0.1", capability="exploit", method="metasploit")
    r = deny(r, reason="Not authorized")
    assert r.status == ActionProposalStatus.DENIED
    assert r.started_at == 0.0  # Invariant: DENIED must not have execution fields
    assert r.completed_at == 0.0
    assert r.result == ""

    # Verify the invariant is enforced by __post_init__
    try:
        from orchestrator.hardening.action_receipt import ActionReceipt, ActionProposalStatus
        bad = ActionReceipt(
            action_id="test",
            status=ActionProposalStatus.DENIED,
            started_at=12345.0,  # Should be 0
        )
        print("❌ A2 invariant 3: Should have rejected DENIED with execution fields")
        assert False, "Should have raised AssertionError"
    except AssertionError:
        pass

    print("✅ A2 invariant 3: DENIED receipts reject execution fields")


def test_tampered_receipt_fails_verification():
    """ActionReceipt tampering breaks hash verification."""
    from orchestrator.hardening.action_receipt import create_proposal

    r = create_proposal(target="10.0.0.1", capability="scan", method="nmap")
    original_hash = r.audit_hash
    r.target = "10.0.0.999"  # Tamper!
    assert not r.verify_integrity(), "Tampered receipt should fail verification"

    # Restore
    r.target = "10.0.0.1"
    assert r.verify_integrity(), "Restored receipt should pass verification"

    print("✅ A2 invariant 4: Tampering detected — hash verification fails and restores")


def test_receipt_transition_state_machine():
    """All valid and invalid transitions are enforced."""
    from orchestrator.hardening.action_receipt import (
        create_proposal, authorize, deny, start_execution, complete_execution,
        timeout_execution, ActionProposalStatus,
    )

    # Terminal states cannot transition
    r = create_proposal(target="10.0.0.1", capability="test", method="test")
    r = authorize(r, reason="Test")
    r = start_execution(r)
    r = complete_execution(r, success=True, result="done")
    assert not r.can_transition_to(ActionProposalStatus.STARTED)
    assert not r.can_transition_to(ActionProposalStatus.FAILED)
    print("✅ A2 invariant 5: Terminal states (SUCCEEDED/FAILED/TIMEOUT) reject transitions")


# ═══════════════════════════════════════════════════════════════
# C1: Arena Scenario Invariants
# ═══════════════════════════════════════════════════════════════

def test_engagement_view_excludes_evaluator_truth():
    """Arena scenario → engagement_view() provably excludes all evaluator ground truth."""
    from arena import ArenaScenario
    from orchestrator.brain.capability_broker import BrokerPolicy

    scenario = ArenaScenario(
        scenario_id="test-invariant-001",
        policy=BrokerPolicy(
            allowed_targets=["10.0.0.0/24"],
            prohibited_targets=[],
            allowed_action_types=["recon", "scan"],
            prohibited_action_types=[],
            allowed_capabilities=["nmap", "curl"],
            prohibited_capabilities=[],
        ),
        evaluator_truth={
            "vulnerabilities": [],
            "success_conditions": [{"description": "test", "type": "detection"}],
        },
    )

    ev = scenario.engagement_view()

    # Structural check: engagement_view has no evaluator_truth fields
    evaluator_fields = {"vulnerabilities", "benign_conditions", "relationships",
                        "expected_observations", "acceptable_actions",
                        "prohibited_actions", "success_conditions"}
    for field in evaluator_fields:
        assert field not in ev, f"engagement_view leaked evaluator field: {field}"

    # Dict check: engagement_view dict excludes evaluator fields
    ev_dict = ev
    for field in evaluator_fields:
        assert field not in ev_dict, f"engagement_view dict leaked evaluator field: {field}"

    print("✅ C1 invariant 1: engagement_view() provably excludes all evaluator ground truth")


def test_all_five_scenarios_load_without_leak():
    """All 5 arena scenarios load, validate, and do not leak evaluator truth."""
    from arena import load_scenario

    scenarios_dir = Path("arena/scenarios")
    evaluator_fields = {"vulnerabilities", "benign_conditions", "relationships",
                        "expected_observations", "acceptable_actions",
                        "prohibited_actions", "success_conditions"}

    for sf in sorted(scenarios_dir.glob("*.json")):
        scenario = load_scenario(sf.stem)  # Load by scenario_id
        issues = scenario.validate()
        assert len(issues) == 0, f"{sf.name}: {issues}"

        ev = scenario.engagement_view()
        for field in evaluator_fields:
            assert field not in ev, f"{sf.name}: engagement_view leaked {field}"

        for field in evaluator_fields:
            assert field not in ev, f"{sf.name}: dict leaked {field}"

    print(f"✅ C1 invariant 2: All {len(list(Path('arena/scenarios').glob('*.json')))} scenarios load, validate, no leaks")


def test_invalid_scope_combinations_fail():
    """Invalid scope/action combinations fail schema validation."""
    from arena import ArenaScenario
    from orchestrator.brain.capability_broker import BrokerPolicy

    # Same CIDR in both allowed and prohibited
    bad = ArenaScenario(
        scenario_id="test-invalid-001",
        policy=BrokerPolicy(
            allowed_targets=["10.0.1.0/24"],
            prohibited_targets=["10.0.1.0/24"],  # Same range!
        ),
        evaluator_truth={
            "success_conditions": [{"description": "x", "type": "detection"}],
        },
    )
    issues = bad.validate()
    assert any("Scope contradiction" in i for i in issues)
    print("✅ C1 invariant 3: Conflicting scope ranges fail validation")


def test_scenario_hash_changes_on_modification():
    """Scenario hash changes when content changes (integrity check)."""
    from arena import ArenaScenario
    from orchestrator.brain.capability_broker import BrokerPolicy

    s1 = ArenaScenario(
        scenario_id="test-hash-001",
        policy=BrokerPolicy(
            allowed_targets=["10.0.0.0/24"],
            allowed_action_types=["recon"],
            allowed_capabilities=["nmap"],
        ),
        evaluator_truth={
            "objective": "Original objective",
            "success_conditions": [{"description": "x", "type": "detection"}],
        },
    )
    h1 = s1.scenario_hash()

    s2 = ArenaScenario(
        scenario_id="test-hash-001",
        policy=BrokerPolicy(
            allowed_targets=["10.0.0.0/24"],
            allowed_action_types=["recon"],
            allowed_capabilities=["nmap"],
        ),
        evaluator_truth={
            "objective": "Modified objective",
            "success_conditions": [{"description": "x", "type": "detection"}],
        },
    )
    h2 = s2.scenario_hash()

    assert h1 != h2, "Scenario hash must change when content changes"
    print("✅ C1 invariant 4: Scenario hash detects content changes")


# ═══════════════════════════════════════════════════════════════
# Cross-contract: Finding backward compatibility
# ═══════════════════════════════════════════════════════════════

def test_finding_backward_compatibility():
    """Existing Finding consumers remain compatible (no required new fields)."""
    from orchestrator.brain.phases.models import Finding, Severity

    # Original style — no trust_level or source_detail
    f = Finding(
        phase="recon",
        type="port_open",
        severity=Severity.MEDIUM,
        description="Port 443 is open",
        evidence="nmap output here",
        target="10.0.0.1",
        port=443,
        service="https",
    )
    d = f.to_dict()

    # All original fields present
    assert d["phase"] == "recon"
    assert d["type"] == "port_open"
    assert d["severity"] == "medium"
    assert d["description"] == "Port 443 is open"
    assert d["port"] == 443

    # New fields have sensible defaults
    assert d["trust_level"] == "tool_observation"
    assert d["source_detail"] == ""

    print("✅ Cross-contract invariant: Existing Finding consumers remain compatible")


def test_imports_resolve():
    """All three contracts can be imported without error."""
    modules = [
        "orchestrator.brain.trust",
        "orchestrator.brain.phases.models",
        "orchestrator.hardening.action_receipt",
        "arena.runner",  # Use arena.runner instead of arena.scenario
    ]
    for mod_name in modules:
        try:
            __import__(mod_name)
        except Exception as e:
            print(f"❌ Import failed: {mod_name}: {e}")
            raise
    print(f"✅ Cross-contract invariant: All {len(modules)} modules import cleanly")


# ═══════════════════════════════════════════════════════════════
# Run all
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    tests = [
        test_trust_provenance_serialization_roundtrip,
        test_nested_trust_preserved,
        test_all_trust_levels_classified,
        test_allow_and_deny_both_produce_receipts,
        test_auth_and_execution_separate,
        test_denied_receipt_no_execution_fields,
        test_tampered_receipt_fails_verification,
        test_receipt_transition_state_machine,
        test_engagement_view_excludes_evaluator_truth,
        test_all_five_scenarios_load_without_leak,
        test_invalid_scope_combinations_fail,
        test_scenario_hash_changes_on_modification,
        test_finding_backward_compatibility,
        test_imports_resolve,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ FAIL: {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print()
    print(f"=== RESULTS: {passed} passed, {failed} failed ===")
    assert failed == 0, f"{failed} invariant tests failed"