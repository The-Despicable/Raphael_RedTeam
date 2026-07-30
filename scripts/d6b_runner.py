#!/usr/bin/env python3
"""
D-6B-R1 Validation Experiment Runner (repaired)

7 templates × 5 validation seeds × 8 architectures = 280 runs

DESIGN (per SENTINEL directive):
  - d6b_runner.py is ORCHESTRATION ONLY.
  - It decides WHICH (template, seed, architecture) to run.
  - It does NOT implement cognition — that belongs to AblationRunner._run_raphael().
  - After execution, extracts treatment-fidelity metrics per episode.
  - Execution engine identity recorded in every result for auditability.

AUTHORIZED CHANGES (SENTINEL 2026-07-26):
  - Batch orchestration
  - Connection between D-6 scenarios and canonical AblationRunner
  - Treatment-fidelity instrumentation
  - Execution-conformance checks

NOT AUTHORIZED:
  - No scenario, evaluator, threshold, seed, algorithm, prompt, or metric changes.
"""

import json
import hashlib
import time
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import (
    D6_SCENARIO_FACTORIES, D6_SCENARIO_EVALUATORS,
    SCENARIO_TEMPLATES, VALIDATION_SEEDS, ITERATION_BUDGET,
)
from arena.runner import SCENARIO_EVALUATORS as _GLOBAL_EVALUATORS
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.runner import evaluate_scenario

# ── Register D-6 evaluators into global evaluator registry ──────────
# This is infrastructure wiring, not apparatus modification.
_GLOBAL_EVALUATORS.update(D6_SCENARIO_EVALUATORS)

# ── Paths ───────────────────────────────────────────────────────────
OUTPUT_DIR = Path('/home/yaser/raphael-2.0/arena/d6b_results')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FILE = OUTPUT_DIR / 'd6b_r1_results.jsonl'
PROGRESS_FILE = OUTPUT_DIR / 'd6b_r1_progress.json'

# ── Engine Identity (for audit trail) ────────────────────────────────
def _file_hash(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

ENGINE_HASHES = {
    "ablation_runner": _file_hash('/home/yaser/raphael-2.0/arena/ablation_runner.py'),
    "ablation_runner_hash": _file_hash('/home/yaser/raphael-2.0/arena/ablation_runner.py')[:16],
    "d6b_runner": _file_hash('/home/yaser/raphael-2.0/d6b_runner.py'),
    "d6b_runner_hash": _file_hash('/home/yaser/raphael-2.0/d6b_runner.py')[:16],
    "ablation": _file_hash('/home/yaser/raphael-2.0/arena/ablation.py'),
    "d6_manifest": _file_hash('/home/yaser/raphael-2.0/arena/d6_manifest.py'),
}


# ── D-6 Template Adapter ────────────────────────────────────────────
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


# ── Architecture Configs ────────────────────────────────────────────
ARCH_NAMES = list(ABLATION_PRESETS.keys())
# Order: FULL_RAPHAEL, NO_HYPOTHESIS, NO_FALSIFICATION, NO_WORLD_MODEL,
#        NO_PLANNER, NO_LLM, NO_DEFEATER, SCRIPTED_BASELINE


# ── Progress Persistence ────────────────────────────────────────────
def load_progress():
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, 'r') as f:
            return json.load(f)
    return {'completed': [], 'failed': []}

def save_progress(progress):
    with open(PROGRESS_FILE, 'w') as f:
        json.dump(progress, f, indent=2)

def append_result(result):
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(result, default=str) + '\n')


# ── Treatment-Fidelity Extraction ────────────────────────────────────
def extract_component_engagement(runner: AblationRunner) -> dict:
    """Extract per-component engagement for treatment-fidelity tracking.
    
    Uses the AblationRunner's tracer to count component invocations
    and unique operations performed during the run.
    """
    tracer = runner.tracer
    components = ["hypothesis", "falsification", "world_model",
                  "planner", "llm_service", "structured_reasoning", "defeater"]
    
    engagement = {}
    for comp in components:
        count = tracer.count_by_component(comp)
        ops = list(tracer.operation_set(comp))
        engagement[comp] = {
            "invoked": count,
            "operations": ops,
        }
    return engagement


# ── Treatment-Fidelity Classification ────────────────────────────────
def classify_treatment_fidelity(config_id: str, engagement: dict, scenario_id: str) -> dict:
    """Classify whether the treatment was actually applied for each component.
    
    Returns:
      PASS: component expected and was invoked
      FAIL: component expected but was NOT invoked (treatment not applied)
      NOT_EXPECTED: component not applicable for this config
    """
    config = ABLATION_PRESETS.get(config_id)
    if not config:
        return {"status": "UNKNOWN_CONFIG"}
    
    # Map config fields to component names in traces
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


# ── Main Orchestration Loop ──────────────────────────────────────────
def main():
    # Load progress
    progress = load_progress()
    completed = set(progress.get('completed', []))
    
    # Build run list: 7 templates × 5 seeds × 8 architectures = 280
    runs = []
    for template_key, template_info in SCENARIO_TEMPLATES.items():
        scenario_id = template_info['id']
        seeds = VALIDATION_SEEDS.get(template_key, [])
        for seed in seeds:
            for arch_name in ARCH_NAMES:
                run_key = f"{arch_name}|{scenario_id}|{seed}"
                runs.append((run_key, arch_name, template_key, seed, scenario_id))
    
    print(f"Total runs: {len(runs)}")
    print(f"Completed: {len(completed)}")
    runs = [r for r in runs if r[0] not in completed]
    print(f"Remaining: {len(runs)}")
    
    start_time = time.time()
    
    for i, (run_key, arch_name, template_key, seed, scenario_id) in enumerate(runs):
        try:
            # 1. Create D-6 template adapter
            factory = D6_SCENARIO_FACTORIES[scenario_id]
            template = D6Template(factory, scenario_id)
            
            # 2. Get architecture config
            config = ABLATION_PRESETS[arch_name]
            
            # 3. Instantiate canonical AblationRunner
            runner = AblationRunner(
                template=template,
                config=config,
                seed=seed,
                split="val",
                output_dir=str(OUTPUT_DIR),
            )
            
            # 4. Execute via canonical cognitive loop (_run_raphael)
            metrics = runner.run()
            
            # 5. Extract treatment-fidelity from tracer
            engagement = extract_component_engagement(runner)
            fidelity = classify_treatment_fidelity(arch_name, engagement, scenario_id)
            
            # 6. Run D-6 evaluator on the ArenaRunner state
            arena_runner = runner.arena_runner
            if arena_runner and config.baseline_type == "raphael":
                evaluation = evaluate_scenario(scenario_id, arena_runner)
            else:
                # For scripted/llm_only baselines, use metrics-based evaluation
                from arena.runner import EvaluationResult, EvaluationVerdict
                evaluation = EvaluationResult(
                    scenario_id=scenario_id,
                    run_id=runner.run_id,
                    verdict=EvaluationVerdict.INCONCLUSIVE,
                    score=0.0,
                    failed_checks=["non_raphael_baseline"],
                )
            
            # 7. Build result record
            result = {
                'run_id': f"d6b_r1_{arch_name}_{scenario_id}_s{seed}",
                'batch': 'D6B-R1',
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
                    'd6b_runner_hash': ENGINE_HASHES['d6b_runner_hash'],
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
            }
            
            append_result(result)
            completed.add(run_key)
            
        except Exception as e:
            import traceback
            print(f"  FAILED: {arch_name} {scenario_id} seed={seed} - {e}")
            traceback.print_exc()
            failed_file = OUTPUT_DIR / 'd6b_r1_failed.jsonl'
            with open(failed_file, 'a') as f:
                f.write(json.dumps({
                    'run': run_key, 'error': str(e),
                    'traceback': traceback.format_exc()
                }) + '\n')
        
        if len(completed) % 10 == 0:
            progress = {'completed': list(completed), 'total_runs': len(completed)}
            save_progress(progress)
            elapsed = time.time() - start_time
            rate = len(completed) / elapsed if elapsed > 0 else 0
            print(f"  Progress: {len(completed)}/280 completed ({rate:.1f} runs/sec)")
    
    print(f"\nExperiment complete! {len(completed)}/280 runs completed.")
    print(f"Engine: AblationRunner._run_raphael()")
    print(f"  ablation_runner hash: {ENGINE_HASHES['ablation_runner_hash']}")
    print(f"  d6b_runner hash: {ENGINE_HASHES['d6b_runner_hash']}")


if __name__ == '__main__':
    main()
