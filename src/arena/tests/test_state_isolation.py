#!/usr/bin/env python3
"""
State isolation tests for benchmark integrity.

Verifies:
  1. Cross-run state contamination: running scenario A then B should NOT carry
     A's evidence/hypotheses into B's results.
  2. Contamination canary: each fresh run has a unique contamination_canary
     in its cognitive state, proving uniqueness.
  3. Singleton independence: EvidenceGraph, WorldModel, HypothesisManager,
     ContradictionManager are NOT reused across ArenaRunner instances.
  4. Order invariance: state(A→B) should produce the same B result as B alone
     (proving no cross-contamination from A to B).

Run: python3 -m pytest arena/tests/test_state_isolation.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from arena.runner import ArenaRunner, ArenaScenario
from arena.templates.families import TEMPLATE_REGISTRY
from orchestrator.brain.evidence import Evidence, EvidenceGraph
from orchestrator.brain.world import WorldModel
from orchestrator.brain.hypothesis import HypothesisManager
from orchestrator.brain.contradiction import ContradictionManager
from orchestrator.brain.capability_broker import BrokerPolicy
from orchestrator.brain.trust import TrustLevel
import uuid


def _fresh_id():
    return f"test_{uuid.uuid4().hex[:8]}"


def test_fresh_runner_has_empty_evidence():
    """A newly created ArenaRunner must have empty evidence graph."""
    pid = _fresh_id()
    policy = BrokerPolicy(
        engagement_id=pid,
        allowed_targets=['10.0.0.0/24'],
        allowed_action_types=['scan'],
        allowed_capabilities=['nmap'],
    )
    scenario = ArenaScenario(scenario_id=pid, name=pid, description='', policy=policy)
    runner = ArenaRunner(scenario=scenario)
    assert len(runner.evidence_graph.get_all_evidence()) == 0, "Fresh runner has non-empty evidence"
    print(f"  ✅ {pid}: fresh runner has empty evidence")


def test_contamination_canary_unique_per_run():
    """Each ArenaRunner must have a unique contamination_canary."""
    canaries = set()
    for i in range(10):
        pid = _fresh_id()
        policy = BrokerPolicy(
            engagement_id=pid,
            allowed_targets=['10.0.0.0/24'],
            allowed_action_types=['scan'],
            allowed_capabilities=['nmap'],
        )
        scenario = ArenaScenario(scenario_id=pid, name=pid, description='', policy=policy)
        runner = ArenaRunner(scenario=scenario)
        assert hasattr(runner, 'contamination_canary'), "Runner missing contamination_canary"
        assert runner.contamination_canary is not None, "contamination_canary is None"
        assert runner.contamination_canary not in canaries, f"Duplicate canary: {runner.contamination_canary}"
        canaries.add(runner.contamination_canary)
    print(f"  ✅ {len(canaries)} unique canaries verified")


def test_fresh_cognitive_components():
    """Each runner gets fresh EvidenceGraph, WorldModel, HypothesisManager, ContradictionManager.
    
    Uses list of weak-reference-safe tuples to avoid GC-induced id reuse.
    """
    components = ['evidence_graph', 'world_model', 'hypothesis_manager', 'contradiction_manager']
    runners = []  # Keep strong references to prevent GC
    prev_objects = {c: [] for c in components}  # Strong refs to prev objects

    for i in range(5):
        pid = _fresh_id()
        policy = BrokerPolicy(
            engagement_id=pid,
            allowed_targets=['10.0.0.0/24'],
            allowed_action_types=['scan'],
            allowed_capabilities=['nmap'],
        )
        scenario = ArenaScenario(scenario_id=pid, name=pid, description='', policy=policy)
        runner = ArenaRunner(scenario=scenario)
        runners.append(runner)

        for comp in components:
            obj = getattr(runner, comp, None)
            assert obj is not None, f"Runner missing {comp}"
            # Check it's not the same object as previously seen (use 'is' for identity)
            for prev_obj in prev_objects[comp]:
                assert obj is not prev_obj, f"Runner reuses {comp}"
            prev_objects[comp].append(obj)

    print(f"  ✅ All components are fresh per-run")


def test_cross_run_no_contamination():
    """Evidence from run A should NOT appear in run B started after A."""
    # Run A: add evidence
    pid_a = _fresh_id()
    policy_a = BrokerPolicy(
        engagement_id=pid_a,
        allowed_targets=['10.0.1.0/24'],
        allowed_action_types=['scan'],
        allowed_capabilities=['nmap'],
    )
    scenario_a = ArenaScenario(scenario_id=pid_a, name=pid_a, description='', policy=policy_a)
    runner_a = ArenaRunner(scenario=scenario_a)
    runner_a.evidence_graph.add_evidence(Evidence.create(
        raw_content='evidence-from-run-A',
        trust_level=TrustLevel.TOOL_OBSERVATION,
        source_detail='test',
        target='10.0.1.1',
        phase='scan',
    ))
    assert len(runner_a.evidence_graph.get_all_evidence()) == 1, "Run A should have 1 evidence"

    # Run B: should start empty
    pid_b = _fresh_id()
    policy_b = BrokerPolicy(
        engagement_id=pid_b,
        allowed_targets=['10.0.2.0/24'],
        allowed_action_types=['scan'],
        allowed_capabilities=['nmap'],
    )
    scenario_b = ArenaScenario(scenario_id=pid_b, name=pid_b, description='', policy=policy_b)
    runner_b = ArenaRunner(scenario=scenario_b)
    assert len(runner_b.evidence_graph.get_all_evidence()) == 0, (
        f"Run B contaminated: found {len(runner_b.evidence_graph.get_all_evidence())} evidence items"
    )
    print("  ✅ Cross-run contamination test passed")


def test_order_invariance():
    """Running B alone should produce the same B result as A→B."""
    # We can't do full rollout here, but we can test the structural property:
    # fresh ArenaRunner construction is idempotent — two consecutive fresh runners
    # for the same scenario have the same initial state.

    pid = _fresh_id()
    policy = BrokerPolicy(
        engagement_id=pid,
        allowed_targets=['10.0.0.0/24'],
        allowed_action_types=['scan'],
        allowed_capabilities=['nmap'],
    )
    scenario = ArenaScenario(scenario_id=pid, name=pid, description='', policy=policy)

    r1 = ArenaRunner(scenario=scenario)
    r2 = ArenaRunner(scenario=scenario)

    assert r1.contamination_canary != r2.contamination_canary, "Canaries should differ"
    assert len(r1.evidence_graph.get_all_evidence()) == len(r2.evidence_graph.get_all_evidence()) == 0, "Both should start empty"
    assert type(r1.world_model) == type(r2.world_model) == WorldModel
    assert type(r1.hypothesis_manager) == type(r2.hypothesis_manager) == HypothesisManager
    assert type(r1.contradiction_manager) == type(r2.contradiction_manager) == ContradictionManager
    print("  ✅ Order invariance structural test passed")


def test_canary_not_none():
    """contamination_canary must never be None."""
    pid = _fresh_id()
    policy = BrokerPolicy(
        engagement_id=pid,
        allowed_targets=['10.0.0.0/24'],
        allowed_action_types=['scan'],
        allowed_capabilities=['nmap'],
    )
    scenario = ArenaScenario(scenario_id=pid, name=pid, description='', policy=policy)
    runner = ArenaRunner(scenario=scenario)
    assert runner.contamination_canary is not None, "Canary is None"
    assert isinstance(runner.contamination_canary, str), "Canary must be string"
    print(f"  ✅ Canary is '{runner.contamination_canary}'")


def test_global_singletons_not_referenced():
    """The runner module should not import get_evidence_graph global."""
    import arena.runner as runner_mod
    # Check that get_evidence_graph is NOT imported or defined
    source = open(runner_mod.__file__).read()
    assert 'get_evidence_graph' not in source, (
        "runner.py still references get_evidence_graph global — possible contamination vector"
    )
    print("  ✅ No get_evidence_graph reference in runner.py")


def test_template_canary_isolation():
    """Templates created independently should not share state."""
    from arena.templates.families import (
        KnownObservableTemplate, SignalInNoiseTemplate,
        FalseLeadTemplate, ContradictionTemplate, ForbiddenProximityTemplate,
    )

    # Instantiate all 5 templates at same seed — should produce different scenarios
    templates = [
        ("known_observable", KnownObservableTemplate()),
        ("signal_noise", SignalInNoiseTemplate()),
        ("false_lead", FalseLeadTemplate()),
        ("contradiction", ContradictionTemplate()),
        ("forbidden_proximity", ForbiddenProximityTemplate()),
    ]

    # Verify independent creation
    scenarios = {}
    for tname, tpl in templates:
        sc = tpl.generate(seed=42)
        scenarios[tname] = sc

    # Different templates produce different scenario_ids
    ids = {s.scenario_id for s in scenarios.values()}
    assert len(ids) == len(scenarios), f"Template isolation failure: same ID from different templates ({len(ids)} unique vs {len(scenarios)} scenarios)"
    print(f"  ✅ Template canary isolation ({len(scenarios)} templates × seed=42 produces unique IDs)")


if __name__ == "__main__":
    tests = [
        ("fresh_runner_empty_evidence", test_fresh_runner_has_empty_evidence),
        ("unique_canaries", test_contamination_canary_unique_per_run),
        ("fresh_cognitive_components", test_fresh_cognitive_components),
        ("cross_run_no_contamination", test_cross_run_no_contamination),
        ("order_invariance", test_order_invariance),
        ("canary_not_none", test_canary_not_none),
        ("no_global_singletons", test_global_singletons_not_referenced),
        ("template_canary_isolation", test_template_canary_isolation),
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
    print(f"State isolation: {passed} passed, {failed} failed")
    assert failed == 0, f"{failed} isolation tests failed"
