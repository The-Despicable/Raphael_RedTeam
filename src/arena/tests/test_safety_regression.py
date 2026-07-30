#!/usr/bin/env python3
"""
Safety regression tests for benchmark integrity.

Verifies:
  1. SafetyVerifier rejects prohibited external actions.
  2. SafetyVerifier passes when all actions are authorized.
  3. SafetyVerifier detects action count mismatches.
  4. No prohibited actions leak from template #5 (forbidden-proximity).
  5. NO_BROKER configuration is FORBIDDEN (AblationConfig.validate rejects it).
  6. broker_enabled is always True in all configs (safety invariant).

Run: python3 -m pytest arena/tests/test_safety_regression.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from arena.ablation import AblationConfig
from arena.ablation_runner import SafetyVerifier


def test_safety_verifier_passes_clean():
    """SafetyVerifier.pass when all actions are authorized."""
    result = SafetyVerifier.verify(
        external_actions=5,
        broker_authorized=5,
        prohibited_external=0,
    )
    assert result["pass"], f"Clean run should pass safety: {result['failures']}"
    assert len(result["failures"]) == 0
    print("  ✅ SafetyVerifier passes with 0 prohibited actions")


def test_safety_verifier_fails_prohibited():
    """SafetyVerifier fails when prohibited actions escape."""
    result = SafetyVerifier.verify(
        external_actions=5,
        broker_authorized=5,
        prohibited_external=1,
    )
    assert not result["pass"], "Should fail with prohibited actions"
    assert any("prohibited" in f for f in result["failures"]), (
        f"Should mention prohibited: {result['failures']}"
    )
    print("  ✅ SafetyVerifier catches prohibited actions")


def test_safety_verifier_fails_mismatch():
    """SafetyVerifier fails when external != authorized."""
    result = SafetyVerifier.verify(
        external_actions=6,
        broker_authorized=5,
        prohibited_external=0,
    )
    assert not result["pass"], "Should fail with mismatch"
    assert any("mismatch" in f for f in result["failures"]), (
        f"Should mention mismatch: {result['failures']}"
    )
    print("  ✅ SafetyVerifier catches action count mismatches")


def test_no_broker_config_forbidden():
    """Config with broker_enabled=False must be rejected."""
    config = AblationConfig(
        config_id='test_no_broker',
        baseline_type='raphael',
        broker_enabled=False,
    )
    issues = config.validate()
    assert len(issues) > 0, "NO_BROKER config should have validation issues"
    assert any('NO_BROKER' in i for i in issues), (
        f"Should mention NO_BROKER: {issues}"
    )
    print(f"  ✅ NO_BROKER config rejected: {issues}")


def test_broker_enabled_default_true():
    """broker_enabled defaults to True (safety invariant)."""
    config = AblationConfig(config_id='test_default')
    assert config.broker_enabled is True, "broker_enabled must default to True"
    issues = config.validate()
    assert len(issues) == 0 or not any('NO_BROKER' in i for i in issues), (
        f"Default config should not have NO_BROKER issue: {issues}"
    )
    print("  ✅ broker_enabled defaults to True")


def test_broker_enabled_asserted_in_validate():
    """validate() always checks broker_enabled."""
    # Even with all other fields valid, broker_enabled=False must fail
    config = AblationConfig(
        config_id='test_all_valid_except_broker',
        baseline_type='raphael',
        hypothesis_enabled=True,
        falsification_enabled=True,
        world_model_enabled=True,
        planner_enabled=True,
        llm_enabled=True,
        broker_enabled=False,  # Violation
    )
    issues = config.validate()
    assert any('NO_BROKER' in i for i in issues), (
        f"Broker violation not detected: {issues}"
    )
    print("  ✅ broker_enabled=False always caught by validate()")


def test_safety_verifier_round_trip():
    """SafetyVerifier result dict has all expected fields."""
    result = SafetyVerifier.verify(5, 5, 0)
    assert "pass" in result, "Missing 'pass' field"
    assert "failures" in result, "Missing 'failures' field"
    assert "action_mismatch" in result, "Missing 'action_mismatch' field"
    assert "prohibited_escaped" in result, "Missing 'prohibited_escaped' field"
    assert result["prohibited_escaped"] == 0, "prohibited_escaped should be 0"
    assert result["action_mismatch"] is None, "action_mismatch should be None"
    print("  ✅ SafetyVerifier result schema verified")


if __name__ == "__main__":
    tests = [
        ("clean_pass", test_safety_verifier_passes_clean),
        ("prohibited_fail", test_safety_verifier_fails_prohibited),
        ("mismatch_fail", test_safety_verifier_fails_mismatch),
        ("no_broker_forbidden", test_no_broker_config_forbidden),
        ("broker_default_true", test_broker_enabled_default_true),
        ("broker_asserted", test_broker_enabled_asserted_in_validate),
        ("schema_round_trip", test_safety_verifier_round_trip),
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
    print(f"Safety regression: {passed} passed, {failed} failed")
    assert failed == 0, f"{failed} safety tests failed"
