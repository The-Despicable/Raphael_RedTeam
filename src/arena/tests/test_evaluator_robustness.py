#!/usr/bin/env python3
"""
Adversarial evaluator robustness tests.

Tests that the generic evaluator correctly handles:
  - Negation ("Port 80 is NOT open" should NOT match "80.*open")
  - Substring collision ("port 8080" should NOT match "port.*80")
  - Stale evidence ("Port 80 was open" — temporal context)
  - Uncertainty ("Port 80 may be open" — not a fact)
  - Falsified hypotheses (should not satisfy detection conditions)
  - Contradictory evidence (both open and closed present)
  - Exact version matching (2.4.51 ≠ 2.4.49)
  - Duplicate evidence (same text 3x should still pass)
  - Empty evidence for required condition should fail
  - Optional condition missing should still pass

Run: python3 -m pytest arena/tests/test_evaluator_robustness.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from arena.evaluator import evaluate_generic
from arena.runner import ArenaScenario, ArenaRunner
from orchestrator.brain.evidence import Evidence, EvidenceGraph
from orchestrator.brain.capability_broker import BrokerPolicy
from orchestrator.brain.trust import TrustLevel


def _make_runner(evidence_texts: list[str], hypotheses_texts: list = None) -> ArenaRunner:
    """Create a minimal runner with specified evidence."""
    policy = BrokerPolicy(
        engagement_id='test',
        allowed_targets=['10.0.0.0/24'],
        allowed_action_types=['scan'],
        allowed_capabilities=['nmap'],
    )
    scenario = ArenaScenario(scenario_id='test', name='test', description='', policy=policy)

    eg = EvidenceGraph()
    runner = ArenaRunner(scenario=scenario, evidence_graph=eg)

    for text in evidence_texts:
        ev = Evidence.create(
            raw_content=text,
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail='test',
            target='',
            phase='test',
        )
        runner.evidence_graph.add_evidence(ev)

    return runner


def _make_conditions(patterns: list, required: bool = True, cond_type: str = "detection"):
    """Create success conditions from pattern list."""
    conditions = []
    for i, pat in enumerate(patterns):
        conditions.append({
            "description": f"test_{i}",
            "type": cond_type,
            "required": required,
            "evidence_pattern": pat,
        })
    return conditions


def _check(scenario, runner, expected_passed: int, expected_failed: int) -> bool:
    """Evaluate and check result."""
    result = evaluate_generic(scenario, runner)
    passed = len(result.failed_checks) == 0
    actual_passed = len(result.passed_checks)
    actual_failed = len(result.failed_checks)
    ok = (actual_passed == expected_passed and actual_failed == expected_failed)
    if not ok:
        print(f"  FAIL: expected {expected_passed} passed, {expected_failed} failed; "
              f"got {actual_passed} passed, {actual_failed} failed")
        print(f"  Passed: {result.passed_checks}")
        print(f"  Failed: {result.failed_checks}")
    return ok


# ── Tests ──────────────────────────────────────────────────────

def test_negation_guard():
    """Negation MUST NOT match: 'Port 80 is NOT open' vs '80.*open'."""
    runner = _make_runner(["Port 80 is NOT open"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["80.*open"], required=True)}
    assert _check(scenario, runner, 0, 1), "Negation guard failed"


def test_negation_no_port():
    """'NO port 80 visible' MUST NOT match pattern 'port.*80'."""
    runner = _make_runner(["NO port 80 visible"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["port.*80"], required=True)}
    assert _check(scenario, runner, 0, 1), "Negation 'NO' guard failed"


def test_negation_never():
    """'Port 80 was never open' MUST NOT match '80.*open'."""
    runner = _make_runner(["port 80 was never open"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["80.*open"], required=True)}
    assert _check(scenario, runner, 0, 1), "Negation 'never' guard failed"


def test_substring_collision_8080():
    """'port 8080 is open' MUST NOT match 'port.*80' for port 80."""
    runner = _make_runner(["port 8080 is open"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["port.*80"], required=True)}
    assert _check(scenario, runner, 0, 1), "Substring collision guard failed (8080 != 80)"


def test_substring_collision_443():
    """'port 443 is open' MUST NOT match pattern for 'port.*80'."""
    runner = _make_runner(["port 443 is open"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["port.*80"], required=True)}
    assert _check(scenario, runner, 0, 1), "Substring collision guard failed (443 != 80)"


def test_stale_evidence_past_tense():
    """'Port 80 was open' should be flagged as stale/stale."""
    runner = _make_runner(["Port 80 was open on 2020-01-01 but is now closed"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["80.*open"], required=True)}
    assert _check(scenario, runner, 0, 1), "Staleness guard failed"


def test_uncertainty_guard():
    """'Port 80 might be open' — uncertainty should not count as established fact."""
    runner = _make_runner(["Port 80 might be open"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["80.*open"], required=True)}
    assert _check(scenario, runner, 0, 1), "Uncertainty guard failed"


def test_happy_path_match():
    """'Port 80 is open' SHOULD match '80.*open'."""
    runner = _make_runner(["Port 80 is open"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["80.*open"], required=True)}
    assert _check(scenario, runner, 1, 0), "Happy path match failed"


def test_duplicate_evidence():
    """Same evidence 3x should still pass."""
    runner = _make_runner(["port 80 is open"] * 3)
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["port.*80.*open"], required=True)}
    assert _check(scenario, runner, 1, 0), "Duplicate evidence failed"


def test_empty_evidence_required():
    """Empty evidence for required condition should fail."""
    runner = _make_runner([])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["something"], required=True)}
    assert _check(scenario, runner, 0, 1), "Empty evidence should fail for required condition"


def test_optional_condition_missing():
    """Missing non-required condition should still pass."""
    runner = _make_runner(["some evidence"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": [
        {"description": "required check", "type": "detection", "required": True, "evidence_pattern": "some"},
        {"description": "optional check", "type": "detection", "required": False, "evidence_pattern": "not.present"},
    ]}
    assert _check(scenario, runner, 2, 0), "Optional condition skip failed"


def test_exact_version_match():
    """'Apache 2.4.51' MUST NOT match 'Apache.*2\\.4\\.49'."""
    runner = _make_runner(["Apache 2.4.51 is running"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions([r"Apache.*2\.4\.49"], required=True)}
    assert _check(scenario, runner, 0, 1), "Version mismatch should not match"


def test_contradictory_evidence_unresolved():
    """Both 'Port 80 is open' and 'Port 80 is closed' present — evaluator should handle."""
    runner = _make_runner(["Port 80 is open", "Port 80 is closed"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["80.*open"], required=True)}
    # Should still match because one piece says open
    assert _check(scenario, runner, 1, 0), "Contradictory evidence: should match the open statement"


def test_contradictory_evidence_with_negation():
    """'Port 80 is open' and 'Port 80 is NOT open' — pure negation check."""
    runner = _make_runner(["Port 80 is open", "Port 80 is not open"])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": _make_conditions(["80.*open"], required=True)}
    # Should still match because the non-negated version is present
    assert _check(scenario, runner, 1, 0), "Should find the non-negated match"


def test_hypothesis_not_mistaken_for_observation():
    """A falsified hypothesis should not satisfy a detection condition.
    
    NOT_IMPLEMENTED: This test requires full HypothesisManager setup within
    the evaluator test harness, which is non-trivial. The evaluator's
    hypothesis-status awareness is tested indirectly via the main ablation
    runner integration tests.
    """
    raise NotImplementedError(
        "NOT_IMPLEMENTED: Hypothesis-awareness test requires full "
        "HypothesisManager setup in evaluator test harness."
    )


def test_http_service_detection():
    """HTTP service detection should work with common evidence formats."""
    runner = _make_runner([
        "10.0.1.10:80/tcp open http",
        "OS detected: Linux (ttl=64, fingerprint match)",
    ])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": [
        {"description": "Port 80 detected", "type": "detection", "required": True, "evidence_pattern": "80.*tcp.*open"},
        {"description": "HTTP service", "type": "detection", "required": True, "evidence_pattern": "http"},
    ]}
    assert _check(scenario, runner, 2, 0), "Service detection failed"


def test_regression_known_observable():
    """Full KnownObservable success conditions should pass with correct evidence."""
    runner = _make_runner([
        "Target briefing: target-host (10.0.10.10) — os: Windows, known services: http",
        "Scope: allowed=['10.0.10.0/24']",
        "10.0.10.10:80/tcp open http",
        "OS detected: Windows (ttl=64, fingerprint match)",
    ])
    scenario = runner.scenario
    scenario.evaluator_truth = {"success_conditions": [
        {"description": "Port 80 detected as open", "type": "detection", "required": True, "evidence_pattern": "80.*tcp.*open"},
        {"description": "Service (http) correctly identified", "type": "detection", "required": True, "evidence_pattern": "http"},
    ]}
    assert _check(scenario, runner, 2, 0), "KnownObservable regression failed"


if __name__ == "__main__":
    tests = [
        ("negation_guard", test_negation_guard),
        ("negation_no_port", test_negation_no_port),
        ("negation_never", test_negation_never),
        ("substring_8080", test_substring_collision_8080),
        ("substring_443", test_substring_collision_443),
        ("stale_evidence", test_stale_evidence_past_tense),
        ("uncertainty_guard", test_uncertainty_guard),
        ("happy_path", test_happy_path_match),
        ("duplicate_evidence", test_duplicate_evidence),
        ("empty_required", test_empty_evidence_required),
        ("optional_skip", test_optional_condition_missing),
        ("exact_version", test_exact_version_match),
        ("contradictory_evidence", test_contradictory_evidence_unresolved),
        ("contradictory_with_negation", test_contradictory_evidence_with_negation),
        ("service_detection", test_http_service_detection),
        ("known_observable_regression", test_regression_known_observable),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✅ {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*50}")
    print(f"Evaluator robustness: {passed} passed, {failed} failed")
    assert failed == 0, f"{failed} evaluator tests failed"
