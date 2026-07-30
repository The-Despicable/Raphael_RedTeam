#!/usr/bin/env python3
"""
D-6C Holdout Experiment Runner

7 templates × 10 holdout seeds × 9 architectures = 630 episodes

FROZEN TREATMENT (per D-6C seal):
  - provider=nvidia
  - model=deepseek-ai/deepseek-v4-flash
  - api_base=https://integrate.api.nvidia.com/v1
  - temperature=0.0
  - max_tokens=512
  - timeout=15s

PROVIDER FAILURE POLICY (D-6C, per SENTINEL):
  - 503/timeout/connection_error leaves episode in dataset as PROVIDER_CONFOUNDED.
  - No selective retry. No skipping.
"""

import json
import hashlib
import time
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import (
    D6_SCENARIO_FACTORIES, D6_SCENARIO_EVALUATORS,
    SCENARIO_TEMPLATES, HOLDOUT_SEEDS,
)
from arena.runner import SCENARIO_EVALUATORS as _GLOBAL_EVALUATORS, evaluate_scenario
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.runner import ArenaRunner

# ── Register D-6 evaluators into global evaluator registry ──
_GLOBAL_EVALUATORS.update(D6_SCENARIO_EVALUATORS)

# ── Paths ───────────────────────────────────────────────────
OUTPUT_DIR = Path('/home/yaser/raphael-2.0/arena/d6c_results')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FILE = OUTPUT_DIR / 'd6c_holdout_results.jsonl'
PROGRESS_FILE = OUTPUT_DIR / 'd6c_progress.json'
RAW_DIR = OUTPUT_DIR / 'raw'
RAW_DIR.mkdir(parents=True, exist_ok=True)
FAILED_FILE = OUTPUT_DIR / 'd6c_failed.jsonl'


# ── Engine Identity (for audit trail) ────────────────────────
def _file_hash(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

ENGINE_HASHES = {
    "ablation_runner": _file_hash('/home/yaser/raphael-2.0/arena/ablation_runner.py'),
    "ablation_runner_hash": _file_hash('/home/yaser/raphael-2.0/arena/ablation_runner.py')[:16],
    "d6c_holdout_runner": _file_hash('/home/yaser/raphael-2.0/d6c_holdout_runner.py'),
    "d6c_holdout_runner_hash": _file_hash('/home/yaser/raphael-2.0/d6c_holdout_runner.py')[:16],
    "d6b_runner": _file_hash('/home/yaser/raphael-2.0/d6b_runner.py'),
    "d6b_runner_hash": _file_hash('/home/yaser/raphael-2.0/d6b_runner.py')[:16],
    "ablation": _file_hash('/home/yaser/raphael-2.0/arena/ablation.py'),
    "d6_manifest": _file_hash('/home/yaser/raphael-2.0/arena/d6_manifest.py'),
}

ARCH_NAMES = list(ABLATION_PRESETS.keys())


# ── D-6 Template Adapter ──────────────────────────────────────
class D6Template:
    """Adapts a D-6 scenario factory for AblationRunner compatibility.

    AblationRunner expects a template with:
      - family_id (str): used for scenario identity
      - generate(seed, split) -> ArenaScenario
    """
    def __init__(self, factory, scenario_id):
        self._factory = factory
        self.family_id = scenario_id
        self.schema_version = 2

    def generate(self, seed=0, split=None, scenario_id_override=None):
        return self._factory(seed=seed)


# ── Progress Persistence ──────────────────────────────────────
def load_progress():
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, 'r') as f:
            return json.load(f)
    return {'completed': [], 'failed': [], 'total_runs': 0}


def save_progress(progress):
    with open(PROGRESS_FILE, 'w') as f:
        json.dump(progress, f, indent=2)


def append_result(result):
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(result, default=str) + '\n')


def append_failed(record):
    with open(FAILED_FILE, 'a') as f:
        f.write(json.dumps(record, default=str) + '\n')


# ── Treatment Fidelity ────────────────────────────────────────
def classify_treatment_fidelity(config, engagement):
    config_to_comp = {
        "hypothesis_enabled": "hypothesis",
        "falsification_enabled": "falsification",
        "world_model_enabled": "world_model",
        "planner_enabled": "planner",
        "llm_enabled": "llm_service",
        "structured_reasoning_enabled": "structured_reasoning",
        "defeater_enabled": "defeater",
    }

    results = {}
    for field, comp in config_to_comp.items():
        expected = getattr(config, field, False)
        actual = engagement.get(comp, {}).get("invoked", 0)

        if expected and actual > 0:
            results[comp] = {"status": "PASS", "invoked": actual}
        elif expected and actual == 0:
            results[comp] = {"status": "FAIL", "invoked": 0,
                             "note": "Component expected but never invoked — treatment not applied"}
        elif not expected and actual == 0:
            results[comp] = {"status": "NOT_EXPECTED", "invoked": 0}
        elif not expected and actual > 0:
            results[comp] = {"status": "LEAK", "invoked": actual,
                             "note": "Component should be disabled but was invoked — isolation leak"}
        else:
            results[comp] = {"status": "NOT_EXPECTED", "invoked": 0}

    overall = "PASS" if all(r["status"] in ("PASS", "NOT_EXPECTED") for r in results.values()) else "FAIL"
    if any(r["status"] == "LEAK" for r in results.values()):
        overall = "LEAK"
    if any(r["status"] == "FAIL" for r in results.values()):
        overall = "FAIL"

    return {"overall": overall, "components": results}


# ── Main Orchestration Loop ───────────────────────────────────
def main():
    # Load progress
    progress = load_progress()
    completed = set(progress.get('completed', []))
    failed_runs = progress.get('failed', [])

    # Build run list: 7 templates × 10 holdout seeds × 9 architectures = 630
    runs = []
    for template_key, template_info in SCENARIO_TEMPLATES.items():
        scenario_id = template_info['id']
        seeds = HOLDOUT_SEEDS.get(template_key, [])
        for seed in seeds:
            for arch_name in ARCH_NAMES:
                run_key = f"{arch_name}|{scenario_id}|{seed}"
                runs.append((run_key, arch_name, template_key, seed, scenario_id))

    # Filter out already completed and errored
    remaining = [r for r in runs if r[0] not in completed]

    print(f"Total runs: {len(runs)}")
    print(f"Already completed: {len(completed)}")
    print(f"Remaining: {len(remaining)}")

    if not remaining:
        print("All 630 D-6C holdout runs completed!")
        return

    start_time = time.time()
    completed_count = len(completed)

    for i, (run_key, arch_name, template_key, seed, scenario_id) in enumerate(remaining):
        try:
            # 1. Create D-6 template adapter
            factory = D6_SCENARIO_FACTORIES[scenario_id]
            template = D6Template(factory, scenario_id)

            # 2. Get architecture config from ABLATION_PRESETS (includes LLM_ONLY)
            config = ABLATION_PRESETS[arch_name]

            # 3. Instantiate canonical AblationRunner with split="holdout"
            runner = AblationRunner(
                template=template,
                config=config,
                seed=seed,
                split="holdout",
                output_dir=str(OUTPUT_DIR),
            )

            # 4. Execute via canonical cognitive loop (_run_raphael)
            metrics = runner.run()

            # 5. Extract treatment-fidelity from tracer
            engagement = {}
            if hasattr(runner, 'tracer') and runner.tracer:
                for comp_name in ["hypothesis", "falsification", "world_model",
                                  "planner", "llm_service", "structured_reasoning", "defeater"]:
                    engagement[comp_name] = {"invoked": runner.tracer.count_by_component(comp_name)}

            fidelity = classify_treatment_fidelity(config, engagement)

            # 6. Run D-6 evaluator on the ArenaRunner state
            arena_runner = runner.arena_runner
            if arena_runner and config.baseline_type == "raphael":
                evaluation = evaluate_scenario(scenario_id, arena_runner)
            else:
                from arena.runner import EvaluationResult, EvaluationVerdict
                evaluation = EvaluationResult(
                    scenario_id=scenario_id,
                    run_id=runner.run_id,
                    verdict=EvaluationVerdict.INCONCLUSIVE,
                    score=0.0,
                    failed_checks=["non_raphael_baseline"],
                )

            # 7. Build result record (D-6C format)
            result = {
                'run_id': f"d6c_holdout_{arch_name}_{scenario_id}_s{seed}",
                'batch': 'D6C-HOLDOUT',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'architecture': arch_name,
                'template': template_key,
                'scenario_id': scenario_id,
                'seed': seed,
                'config': {
                    'hypothesis_enabled': config.hypothesis_enabled,
                    'falsification_enabled': config.falsification_enabled,
                    'world_model_enabled': config.world_model_enabled,
                    'planner_enabled': config.planner_enabled,
                    'llm_enabled': config.llm_enabled,
                    'structured_reasoning_enabled': config.structured_reasoning_enabled,
                    'defeater_enabled': config.defeater_enabled,
                    'baseline_type': config.baseline_type,
                },
                'evaluation': {
                    'verdict': evaluation.verdict.value if hasattr(evaluation.verdict, 'value') else str(evaluation.verdict),
                    'score': evaluation.score,
                    'passed_checks': evaluation.passed_checks,
                    'failed_checks': evaluation.failed_checks,
                },
                'treatment_fidelity': fidelity,
                'component_engagement': engagement,
                'execution_engine': {
                    'name': 'AblationRunner._run_raphael',
                    'entrypoint': '_run_raphael',
                    'ablation_runner_hash': ENGINE_HASHES['ablation_runner_hash'],
                    'd6c_holdout_runner_hash': ENGINE_HASHES['d6c_holdout_runner_hash'],
                },
                'metrics': {
                    'outcome': metrics.outcome,
                    'hypotheses_created': metrics.hypotheses_created,
                    'llm_calls': metrics.llm_calls,
                    'actions_proposed': metrics.actions_proposed,
                    'actions_authorized': metrics.actions_authorized,
                    'actions_denied': metrics.actions_denied,
                    'prohibited_external_actions': metrics.prohibited_external_actions,
                    'wall_time_seconds': metrics.wall_time_seconds,
                    'provider_failures': metrics.provider_failures,
                },
                'provider_confounded': metrics.provider_failures > 0,
                'provider_failure_count': metrics.provider_failures,
            }

            append_result(result)
            completed.add(run_key)
            completed_count += 1

            # Save raw result for audit trail
            raw_path = RAW_DIR / f"abl_{arch_name}_{scenario_id}_s{seed}_{time.time_ns()}"
            with open(raw_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)

        except Exception as e:
            err_str = str(e)
            print(f"  FAILED: {arch_name} {scenario_id} seed={seed} - {err_str}")
            append_failed({
                'run_key': run_key,
                'arch_name': arch_name,
                'scenario_id': scenario_id,
                'seed': seed,
                'error': err_str,
                'traceback': traceback.format_exc(),
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
            failed_runs.append(run_key)

        # Update progress every 5 episodes
        if len(completed) % 5 == 0 and len(completed) > progress.get('total_completed', 0):
            elapsed = time.time() - start_time
            rate = len(completed) / elapsed if elapsed > 0 else 0
            save_progress({
                'completed': list(completed),
                'failed': failed_runs,
                'total_runs': len(runs),
                'total_completed': len(completed),
                'elapsed_seconds': elapsed,
            })
            print(f"  Progress: {len(completed)}/{len(runs)} completed ({rate:.2f} runs/sec)")

    # Final progress save and seal
    elapsed = time.time() - start_time
    save_progress({
        'completed': list(completed),
        'failed': failed_runs,
        'total_runs': len(runs),
        'total_completed': len(completed),
        'elapsed_seconds': elapsed,
    })

    print(f"\nExperiment complete! {len(completed)}/{len(runs)} runs completed.")
    print(f"Total time: {elapsed:.1f}s ({len(completed)/elapsed:.2f} runs/sec)")
    print(f"Engine: AblationRunner._run_raphael()")
    print(f"  ablation_runner hash: {ENGINE_HASHES['ablation_runner_hash']}")
    print(f"  d6c_holdout_runner hash: {ENGINE_HASHES['d6c_holdout_runner_hash']}")
    print(f"  d6b_runner hash: {ENGINE_HASHES['d6b_runner_hash']}")


if __name__ == '__main__':
    main()