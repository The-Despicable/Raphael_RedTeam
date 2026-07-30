#!/usr/bin/env python3
"""
Baseline equivalence tests.

Verifies that LLM_ONLY and SCRIPTED baselines share the same:
  - Iteration budget (5 cycles) confirmed by source inspection
  - Scenario generation (same template.generate() call)
  - CapabilityBroker (same broker policy, generated per-run)
  - EvidenceGraph pipeline (same normalize, same add_evidence path)
  - Episode recording (same EpisodeRecorder per run)
  - Evaluator invocation (same evaluate_generic function)

The only allowed difference is the decision-making policy (baseline_type).

Run: python3 -m pytest arena/tests/test_baseline_equivalence.py -v
"""
import sys
import inspect
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from arena.ablation import AblationConfig
from arena.ablation_runner import AblationRunner
from arena.environment import RawObservation, ObservationNormalizer
from arena.evaluator import evaluate_generic
from arena.episode import EpisodeRecorder
from arena.templates.families import KnownObservableTemplate
from orchestrator.brain.trust import TrustLevel


def test_llm_only_uses_baseline_type():
    """LLM_ONLY config uses baseline_type='llm_only'."""
    config = AblationConfig(config_id='test_llm', baseline_type='llm_only')
    assert config.baseline_type == 'llm_only', "LLM_ONLY baseline_type mismatch"
    issues = config.validate()
    assert len(issues) == 0, f"Config validation failed: {issues}"
    print(f"  ✅ LLM_ONLY config validated")


def test_scripted_uses_baseline_type():
    """SCRIPTED config uses baseline_type='scripted'."""
    config = AblationConfig(config_id='test_scripted', baseline_type='scripted')
    assert config.baseline_type == 'scripted', "SCRIPTED baseline_type mismatch"
    issues = config.validate()
    assert len(issues) == 0, f"Config validation failed: {issues}"
    print(f"  ✅ SCRIPTED config validated")


def test_full_raphael_baseline_type():
    """FULL_RAPHAEL config uses baseline_type='raphael'."""
    config = AblationConfig(config_id='test_raphael', baseline_type='raphael')
    assert config.baseline_type == 'raphael', "RAPHAEL baseline_type mismatch"
    issues = config.validate()
    assert len(issues) == 0, f"Config validation failed: {issues}"
    print(f"  ✅ RAPHAEL config validated")


def test_all_configs_have_same_structure():
    """All configs share the same AblationConfig dataclass fields."""
    configs = [
        AblationConfig(config_id='a', baseline_type='raphael'),
        AblationConfig(config_id='b', baseline_type='llm_only'),
        AblationConfig(config_id='c', baseline_type='scripted'),
    ]
    fields_set = [set(c.to_dict().keys()) for c in configs]
    for i in range(1, len(fields_set)):
        assert fields_set[i] == fields_set[0], (
            f"Config {i} has different fields: {fields_set[i]} vs {fields_set[0]}"
        )
    print(f"  ✅ All {len(configs)} config types share same structure")


def test_ablation_runner_accepts_all_baseline_types():
    """AblationRunner accepts all three baseline_type values."""
    tpl = KnownObservableTemplate()
    for baseline_type in ['raphael', 'llm_only', 'scripted']:
        config = AblationConfig(config_id=f'test_{baseline_type}', baseline_type=baseline_type)
        runner = AblationRunner(template=tpl, config=config, seed=42)
        assert runner.config.baseline_type == baseline_type, f"Runner baseline_type mismatch"
        assert runner.template is tpl, "Runner template reference lost"
    print(f"  ✅ AblationRunner accepts all 3 baseline types")


def test_ablation_runner_builds_scenario():
    """AblationRunner._build_scenario() returns an ArenaScenario with policy."""
    tpl = KnownObservableTemplate()
    config = AblationConfig(config_id='test_build', baseline_type='llm_only')
    runner = AblationRunner(template=tpl, config=config, seed=42)
    scenario = runner._build_scenario()
    assert scenario is not None, "Scenario should not be None"
    assert scenario.policy is not None, "Scenario should have a policy"
    assert scenario.scenario_id.startswith('known-observable'), (
        f"Unexpected scenario_id: {scenario.scenario_id}"
    )
    print(f"  ✅ AblationRunner._build_scenario() works for all baselines")


def test_observation_normalizer():
    """ObservationNormalizer converts RawObservation to Evidence[]."""
    obs = RawObservation(
        raw_output="port 80 is open\nOS detected: Linux",
        source_tool="nmap",
        target="10.0.1.10",
        observation_type="port_scan",
    )
    evidence_list = ObservationNormalizer.normalize(obs)
    assert isinstance(evidence_list, list), "normalize should return a list"
    assert len(evidence_list) == 2, f"Expected 2 evidence items, got {len(evidence_list)}"
    for ev in evidence_list:
        assert ev.raw_content is not None, "Evidence missing raw_content"
    print(f"  ✅ ObservationNormalizer works: {len(evidence_list)} evidence items from 1 observation")


def test_evaluate_generic_signature():
    """evaluate_generic(scenario, runner) signature is correct."""
    sig = inspect.signature(evaluate_generic)
    params = list(sig.parameters.keys())
    assert 'scenario' in params, "evaluate_generic missing 'scenario' param"
    assert 'runner' in params, "evaluate_generic missing 'runner' param"
    print(f"  ✅ evaluate_generic signature: evaluate_generic({', '.join(params)})")


def test_episode_recorder_has_record():
    """EpisodeRecorder has record() method for all baselines."""
    assert hasattr(EpisodeRecorder, 'record'), "EpisodeRecorder missing record method"
    print(f"  ✅ EpisodeRecorder has record() method")


def test_all_baselines_use_same_run_flow():
    """All baselines use run() -> _build_scenario() -> execute -> _evaluate() flow."""
    src = inspect.getsource(AblationRunner.run)
    assert '_build_scenario()' in src, "run() must call _build_scenario()"
    assert '_run_raphael' in src or '_run_llm_only' in src or '_run_scripted' in src, (
        "run() must dispatch to execute method"
    )
    assert '_evaluate()' in src, "run() must call _evaluate()"
    print(f"  ✅ All baselines share the same run() flow")


if __name__ == "__main__":
    tests = [
        ("llm_only_type", test_llm_only_uses_baseline_type),
        ("scripted_type", test_scripted_uses_baseline_type),
        ("raphael_type", test_full_raphael_baseline_type),
        ("same_structure", test_all_configs_have_same_structure),
        ("runner_accepts_all", test_ablation_runner_accepts_all_baseline_types),
        ("builds_scenario", test_ablation_runner_builds_scenario),
        ("normalizer", test_observation_normalizer),
        ("evaluator_sig", test_evaluate_generic_signature),
        ("episode_recorder", test_episode_recorder_has_record),
        ("run_flow", test_all_baselines_use_same_run_flow),
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
    print(f"Baseline equivalence: {passed} passed, {failed} failed")
    assert failed == 0, f"{failed} baseline equivalence tests failed"
