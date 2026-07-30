#!/usr/bin/env python3
"""
D7-R1 Gemma LLM Re-test — 45-episode batch

Per SENTINEL authorization:
  Architectures: FULL_RAPHAEL, NO_LLM, LLM_ONLY
  Templates: T3_FALSIFICATION_SENSITIVE, T4_WORLD_MODEL_IDENTITY, T6_SEMANTIC_LLM
  Seeds: VALIDATION split (5 per template)
  Provider: bjoernb/gemma4-31b-think (local Ollama)

Total episodes: 3 × 5 × 3 = 45

Success criterion: LLM call success rate ≥ 90%
Reports paired deltas (FULL vs NO_LLM, FULL vs LLM_ONLY)
"""

import sys
import json
import time
import traceback
from pathlib import Path
sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import (
    D6_SCENARIO_FACTORIES, D6_SCENARIO_EVALUATORS,
    SCENARIO_TEMPLATES, VALIDATION_SEEDS,
)
from arena.runner import SCENARIO_EVALUATORS as _GLOBAL_EVALUATORS, evaluate_scenario
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.llm_service import LLMService, LLMProviderConfig
from d6c_holdout_runner import D6Template

# Register D-6 evaluators
_GLOBAL_EVALUATORS.update(D6_SCENARIO_EVALUATORS)

ARCHITECTURES = ["FULL_RAPHAEL", "NO_LLM", "LLM_ONLY"]
TEMPLATES = ["T3_FALSIFICATION_SENSITIVE", "T4_WORLD_MODEL_IDENTITY", "T6_SEMANTIC_LLM"]

OUTPUT_DIR = Path("/home/yaser/raphael-2.0/arena/results/d7_r1_gemma_retest")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def make_llm_config():
    """Return LLMProviderConfig for local Ollama Gemma model."""
    return LLMProviderConfig(
        model_id="bjoernb/gemma4-31b-think:latest",
        provider="ollama_gemma4",
        api_base="http://localhost:11434/v1",
        api_key="",
        timeout_seconds=120,
        temperature=0.0,
        max_tokens=512,
    )


def run_single(arch_name, template_key, seed):
    """Run a single episode and return results with metrics."""
    template_info = SCENARIO_TEMPLATES[template_key]
    scenario_id = template_info["id"]
    factory = D6_SCENARIO_FACTORIES[scenario_id]
    template = D6Template(factory, scenario_id)
    config = ABLATION_PRESETS[arch_name]

    # Override LLM config for architectures that use LLM
    llm_config = None
    if arch_name in ("FULL_RAPHAEL", "LLM_ONLY"):
        llm_config = make_llm_config()

    runner = AblationRunner(
        template=template,
        config=config,
        seed=seed,
        split="validation",
        llm_config_override=llm_config,
    )

    metrics = runner.run()
    arena_runner = runner.arena_runner

    # Evaluate
    from arena.runner import EvaluationResult, EvaluationVerdict
    if arena_runner and config.baseline_type == "raphael":
        evaluation = evaluate_scenario(scenario_id, arena_runner)
    else:
        evaluation = EvaluationResult(
            scenario_id=scenario_id,
            run_id=runner.run_id,
            verdict=EvaluationVerdict.INCONCLUSIVE,
            score=0.0,
            failed_checks=["non_raphael_baseline"],
        )

    # Collect planner denial stats
    denial_records_count = 0
    persistent_count = 0
    temporary_count = 0
    candidate_exhaustion_count = 0
    if hasattr(runner, 'arena_runner') and runner.arena_runner:
        au = runner.arena_runner
        if hasattr(au, 'planner') and au.planner:
            planner = au.planner
            if hasattr(planner, '_inner'):
                planner = planner._inner
            if hasattr(planner, 'feedback_records'):
                denial_records_count = len(planner.feedback_records)
                for rec in planner.feedback_records.values():
                    if hasattr(rec, 'denial_class'):
                        from orchestrator.brain.action import DenialClass
                        if rec.denial_class == DenialClass.PERSISTENT:
                            persistent_count += 1
                        else:
                            temporary_count += 1
            if hasattr(planner, 'suppressed_proposals'):
                candidate_exhaustion_count = len(planner.suppressed_proposals)

    # Count LLM successes vs failures from diagnostic log
    # The _llm_service is created in _run_raphael() and holds the diagnostic log
    llm_success = 0
    llm_failure = 0
    llm_service = getattr(runner, '_llm_service', None)
    if llm_service is not None and hasattr(llm_service, 'diagnostic_log'):
        diag_log = llm_service.diagnostic_log
        records = []
        if hasattr(diag_log, 'get_all'):
            records = diag_log.get_all()
        elif hasattr(diag_log, '_records'):
            records = diag_log._records
        for log_entry in records:
            if getattr(log_entry, 'result_type', '') == 'success':
                llm_success += 1
            elif getattr(log_entry, 'result_type', '') == 'failure':
                llm_failure += 1

    result = {
        "run_id": runner.run_id,
        "architecture": arch_name,
        "template": template_key,
        "seed": seed,
        "scenario_id": scenario_id,
        "score": evaluation.score,
        "verdict": evaluation.verdict.value if hasattr(evaluation.verdict, 'value') else str(evaluation.verdict),
        "passed_checks": evaluation.passed_checks,
        "failed_checks": evaluation.failed_checks,
        "metrics": {
            "actions_proposed": metrics.actions_proposed,
            "actions_authorized": metrics.actions_authorized,
            "actions_denied": metrics.actions_denied,
            "prohibited_external_actions": metrics.prohibited_external_actions,
            "provider_failures": metrics.provider_failures,
        },
        "planner": {
            "denial_records": denial_records_count,
            "persistent_denials": persistent_count,
            "temporary_denials": temporary_count,
            "suppressed_proposals": candidate_exhaustion_count,
        },
        "llm": {
            "success_count": llm_success,
            "failure_count": llm_failure,
            "total_calls": llm_success + llm_failure,
            "success_rate": llm_success / (llm_success + llm_failure) if (llm_success + llm_failure) > 0 else 1.0,
        },
    }
    return result


def main():
    print("=" * 72)
    print("GEMMA LLM RE-TEST (D7-R1)")
    print("=" * 72)
    print(f"Provider: bjoernb/gemma4-31b-think (local Ollama)")
    print(f"Architectures: {ARCHITECTURES}")
    print(f"Templates: {TEMPLATES}")
    print(f"Seeds per template: 5 (VALIDATION split)")
    print(f"Total episodes: {len(TEMPLATES) * 5 * len(ARCHITECTURES)}")
    print()

    results = []
    failures = []

    total = len(TEMPLATES) * 5 * len(ARCHITECTURES)
    count = 0

    for template_key in TEMPLATES:
        seeds = VALIDATION_SEEDS[template_key][:5]
        for seed in seeds:
            for arch in ARCHITECTURES:
                count += 1
                key = f"{arch}|{template_key}|{seed}"
                print(f"[{count}/{total}] [{key}] Running...", end=" ", flush=True)

                try:
                    result = run_single(arch, template_key, seed)
                    results.append(result)
                    status = "✅" if result["verdict"] == "PASS" else "⬜"
                    provider_status = (
                        f"llm={result['llm']['success_rate']*100:.0f}%"
                        if result['llm']['total_calls'] > 0
                        else "no_llm"
                    )
                    print(f"{status} score={result['score']:.2f} "
                          f"passed={len(result['passed_checks'])} "
                          f"failed={len(result['failed_checks'])} "
                          f"[{provider_status}]")
                except Exception as e:
                    print(f"❌ FAILED: {e}")
                    traceback.print_exc()
                    failures.append({"key": key, "error": str(e)})

                # Save intermediate results every 10 runs
                if count % 10 == 0:
                    _save_snapshot(results, failures)

    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print()

    # ── Aggregate by architecture ──
    arch_results = {}
    for arch in ARCHITECTURES:
        arch_results[arch] = [r for r in results if r["architecture"] == arch]
        print(f"\n{'─' * 50}")
        print(f"  {arch}: {len(arch_results[arch])} episodes")
        print(f"{'─' * 50}")
        scores = [r["score"] for r in arch_results[arch]]
        print(f"  Mean score: {sum(scores) / len(scores):.3f}")
        print(f"  Scores: {[f'{s:.2f}' for s in scores]}")

        # D7 invariant: prohibited_attempted count
        prohibited = [r for r in arch_results[arch] if "prohibited_attempted" in r["failed_checks"]]
        print(f"  prohibited_attempted: {len(prohibited)}/{len(arch_results[arch])}")

        # LLM success rate
        if arch in ("FULL_RAPHAEL", "LLM_ONLY"):
            total_success = sum(r["llm"]["success_count"] for r in arch_results[arch])
            total_calls = sum(r["llm"]["total_calls"] for r in arch_results[arch])
            rate = total_success / total_calls if total_calls > 0 else 1.0
            print(f"  LLM success rate: {total_success}/{total_calls} = {rate*100:.1f}%")

    # ── Paired deltas ──
    print(f"\n{'─' * 50}")
    print("  PAIRED DELTAS")
    print(f"{'─' * 50}")

    for template_key in TEMPLATES:
        for seed in VALIDATION_SEEDS[template_key][:5]:
            f = next(r for r in results if r["architecture"] == "FULL_RAPHAEL"
                     and r["template"] == template_key and r["seed"] == seed)
            n = next(r for r in results if r["architecture"] == "NO_LLM"
                     and r["template"] == template_key and r["seed"] == seed)
            l = next(r for r in results if r["architecture"] == "LLM_ONLY"
                     and r["template"] == template_key and r["seed"] == seed)

            delta_fn = f["score"] - n["score"]
            delta_fl = f["score"] - l["score"]
            f_p = "✅" if f["llm"]["success_rate"] >= 0.9 else "⚠️"

            print(f"  {template_key}|{seed}: FULL={f['score']:.2f} "
                  f"NO_LLM={n['score']:.2f} LLM_ONLY={l['score']:.2f} "
                  f"Δ(F-N)={delta_fn:+.2f} Δ(F-L)={delta_fl:+.2f} "
                  f"LLM={f_p}")

    # ── Overall summary ──
    full_results = [r for r in results if r["architecture"] == "FULL_RAPHAEL"]
    no_llm_results = [r for r in results if r["architecture"] == "NO_LLM"]
    llm_only_results = [r for r in results if r["architecture"] == "LLM_ONLY"]

    full_mean = sum(r["score"] for r in full_results) / len(full_results)
    no_llm_mean = sum(r["score"] for r in no_llm_results) / len(no_llm_results)
    llm_only_mean = sum(r["score"] for r in llm_only_results) / len(llm_only_results)

    # LLM success rate across all architectures
    total_llm_success = sum(r["llm"]["success_count"] for r in results)
    total_llm_calls = sum(r["llm"]["total_calls"] for r in results)
    llm_success_rate = total_llm_success / total_llm_calls if total_llm_calls > 0 else 1.0

    # D7 invariant: how many FULL episodes have prohibited_attempted
    full_prohibited = [r for r in full_results if "prohibited_attempted" in r["failed_checks"]]

    print(f"\n{'=' * 50}")
    print("  OVERALL SUMMARY")
    print(f"{'=' * 50}")
    print(f"  FULL_RAPHAEL mean score:  {full_mean:.3f}")
    print(f"  NO_LLM mean score:        {no_llm_mean:.3f}")
    print(f"  LLM_ONLY mean score:      {llm_only_mean:.3f}")
    print(f"  Delta FULL - NO_LLM:     {(full_mean - no_llm_mean):+.3f}")
    print(f"  Delta FULL - LLM_ONLY:   {(full_mean - llm_only_mean):+.3f}")
    print(f"  LLM success rate:         {total_llm_success}/{total_llm_calls} = {llm_success_rate*100:.1f}%")
    print(f"  LLM success ≥ 90%:        {'✅ YES' if llm_success_rate >= 0.9 else '❌ NO'}")
    print(f"  FULL prohibited_attempted: {len(full_prohibited)}/{len(full_results)}")
    print(f"  Total episodes:           {len(results)}")
    print(f"  Failures:                 {len(failures)}")

    # ── Save final results ──
    final = {
        "meta": {
            "test": "D7-R1 Gemma LLM Re-test",
            "authorization": "SENTINEL (GLM-5.2)",
            "provider": "bjoernb/gemma4-31b-think (local Ollama)",
            "architectures": ARCHITECTURES,
            "templates": TEMPLATES,
            "total_episodes": len(results),
            "timestamp": time.time(),
        },
        "summary": {
            "full_mean_score": full_mean,
            "no_llm_mean_score": no_llm_mean,
            "llm_only_mean_score": llm_only_mean,
            "delta_full_minus_no_llm": full_mean - no_llm_mean,
            "delta_full_minus_llm_only": full_mean - llm_only_mean,
            "llm_success_rate": llm_success_rate,
            "llm_success_above_90": llm_success_rate >= 0.9,
            "full_prohibited_attempted_count": len(full_prohibited),
        },
        "results": results,
        "failures": failures,
    }

    output_path = OUTPUT_DIR / "d7_r1_gemma_retest_results.json"
    with open(output_path, "w") as f:
        json.dump(final, f, indent=2, default=str)
    print(f"\n  Results saved: {output_path}")

    # ── SENTINEL report format ──
    print(f"\n{'=' * 50}")
    print("  SENTINEL REPORT")
    print(f"{'=' * 50}")
    print(f"  D7-R1 Gemma Re-test: {'PASS' if llm_success_rate >= 0.9 else 'INCONCLUSIVE'}")
    print(f"  FULL mean: {full_mean:.3f} vs NO_LLM mean: {no_llm_mean:.3f} (Δ={full_mean - no_llm_mean:+.3f})")
    print(f"  FULL mean: {full_mean:.3f} vs LLM_ONLY mean: {llm_only_mean:.3f} (Δ={full_mean - llm_only_mean:+.3f})")
    print(f"  Gemma success rate: {llm_success_rate*100:.1f}%")
    sys.exit(0 if llm_success_rate >= 0.9 else 1)


def _save_snapshot(results, failures):
    """Save intermediate results checkpoint."""
    snapshot = {
        "partial": True,
        "results_count": len(results),
        "failures_count": len(failures),
        "results": results,
        "failures": failures,
    }
    path = OUTPUT_DIR / "snapshot.json"
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)


if __name__ == "__main__":
    main()
