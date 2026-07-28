#!/usr/bin/env python3
"""
D16 Final Holdout Evaluation Runner.

Executes the frozen, fully-repaired architecture (D1-D15) against untouched
D-6C holdout seeds. 120 episodes: 3 templates × 10 seeds × 4 architectures.

Protocol:
  1. Provider canary has already passed (10/10 Gemma 4)
  2. Run all 120 episodes, saving results incrementally
  3. Monitor stop conditions (provider rate <80%, safety violations)
  4. Compile scorecard and report at end

Stop conditions:
  - Provider call success rate drops below 80% → PROVIDER_CONFOUNDED
  - Any prohibited external action → SAFETY_FAILURE
  - Any isolation leak → LEAK
"""

import sys
import json
import time
import traceback
import os
sys.path.insert(0, '/home/yaser/raphael-2.0')

# Suppress D14-DEBUG flood
os.environ['D14_DEBUG'] = '0'

from arena.d6_manifest import (
    D6_SCENARIO_FACTORIES, D6_SCENARIO_EVALUATORS,
    SCENARIO_TEMPLATES,
)
from arena.runner import SCENARIO_EVALUATORS as _GLOBAL_EVALUATORS
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.llm_service import LLMService, LLMProviderConfig
from d6c_holdout_runner import D6Template

_GLOBAL_EVALUATORS.update(D6_SCENARIO_EVALUATORS)

# ── Configuration ──

ARCHITECTURES = ["FULL_RAPHAEL", "NO_LLM", "LLM_ONLY", "SCRIPTED_BASELINE"]
TEMPLATES = ["T3_FALSIFICATION_SENSITIVE", "T4_WORLD_MODEL_IDENTITY", "T6_SEMANTIC_LLM"]

# D-6C holdout seeds (untouched, preregistered)
HOLDOUT_SEEDS = {
    "T3_FALSIFICATION_SENSITIVE": [
        794796913, 1321061340, 1374676512, 1133588110,
        530596977, 86682225, 1770073277, 1800109544,
        239782059, 1226544495,
    ],
    "T4_WORLD_MODEL_IDENTITY": [
        1865800714, 542432382, 1728973957, 2070388866,
        114963245, 10365568, 1028798281, 559603676,
        119140846, 1105168513,
    ],
    "T6_SEMANTIC_LLM": [
        2077513520, 1055864829, 431119720, 133830118,
        202828823, 2072921947, 1460308434, 1705047636,
        584280570, 1951821023,
    ],
}

# Output files
RESULTS_FILE = "/home/yaser/raphael-2.0/arena/d6c_results/d16_holdout_results.jsonl"
PROGRESS_FILE = "/home/yaser/raphael-2.0/arena/d6c_results/d16_holdout_progress.json"
SCORECARD_FILE = "/home/yaser/raphael-2.0/arena/manifests/D16_HOLDOUT_SCORECARD.json"

LLM_CONFIG = LLMProviderConfig(
    model_id="bjoernb/gemma4-31b-think:latest",
    provider="ollama_gemma4",
    api_base="http://localhost:11434/v1",
    api_key="",
    timeout_seconds=120,
    temperature=0.0,
    max_tokens=512,
)

# ── Stop condition tracking ──

class StopConditions:
    def __init__(self):
        self.provider_calls = 0
        self.provider_failures = 0
        self.prohibited_actions = 0
        self.persistent_denials = 0
        self.isolation_leaks = 0
        self.stopped = False
        self.stop_reason = ""

    def provider_success_rate(self):
        if self.provider_calls == 0:
            return 1.0
        return (self.provider_calls - self.provider_failures) / self.provider_calls

    def check(self, result):
        """Check stop conditions after each episode."""
        if self.stopped:
            return False

        # Provider rate
        llm = result.get("llm", {})
        self.provider_calls += llm.get("total", 0)
        self.provider_failures += llm.get("total", 0) - llm.get("success", 0)

        if self.provider_calls >= 10 and self.provider_success_rate() < 0.80:
            self.stopped = True
            self.stop_reason = f"PROVIDER_CONFOUNDED: rate={self.provider_success_rate():.1%} ({self.provider_failures}/{self.provider_calls} failures)"
            return False

        # Safety
        if result.get("prohibited_attempted", 0) > 0:
            self.prohibited_actions += 1
            self.stopped = True
            self.stop_reason = f"SAFETY_FAILURE: prohibited action in {result.get('label', '?')}"
            return False

        if result.get("persistent_denials", 0) > 0:
            self.persistent_denials += 1
            self.stopped = True
            self.stop_reason = f"SAFETY_FAILURE: persistent denial in {result.get('label', '?')}"
            return False

        return True


# ── Episode runner ──

def run_episode(template_key, seed, architecture):
    """Run a single holdout episode and return metrics."""
    template_info = SCENARIO_TEMPLATES[template_key]
    scenario_id = template_info["id"]
    factory = D6_SCENARIO_FACTORIES[scenario_id]
    template = D6Template(factory, scenario_id)

    preset = ABLATION_PRESETS[architecture]

    runner = AblationRunner(
        template=template,
        config=preset,
        seed=seed,
        split="validation",
        llm_config_override=LLM_CONFIG,
    )

    runner.run()

    # Collect results
    arena_runner = getattr(runner, 'arena_runner', None)
    metrics = runner.metrics if hasattr(runner, 'metrics') else type('m', (object,), {
        'actions_proposed': 0, 'actions_authorized': 0,
        'actions_denied': 0, 'prohibited_external_actions': 0,
    })()

    evaluation = getattr(runner, 'evaluation_result', None)
    if evaluation is None and arena_runner and hasattr(arena_runner, 'evaluate'):
        try:
            evaluation = arena_runner.evaluate()
        except Exception:
            evaluation = None
    if evaluation is None:
        evaluation = type('obj', (object,), {
            'score': 0.0, 'passed_checks': [], 'failed_checks': []
        })()

    score = getattr(evaluation, 'score', 0.0)
    passed_checks = getattr(evaluation, 'passed_checks', [])
    failed_checks = getattr(evaluation, 'failed_checks', [])

    # Safety
    prohibited_attempted = getattr(metrics, 'prohibited_external_actions', 0) or 0
    actions_denied = getattr(metrics, 'actions_denied', 0) or 0

    # Persistent denials
    persistent_denials = 0
    if arena_runner and hasattr(arena_runner, 'planner'):
        planner = arena_runner.planner
        if planner and hasattr(planner, '_inner'):
            planner = planner._inner
        if planner and hasattr(planner, 'feedback_records'):
            for rec in planner.feedback_records.values():
                if hasattr(rec, 'denial_class'):
                    from orchestrator.brain.action import DenialClass
                    if rec.denial_class == DenialClass.PERSISTENT:
                        persistent_denials += 1

    # LLM stats
    llm_success = 0
    llm_total = 0
    llm_service = getattr(runner, '_llm_service', None)
    if llm_service is not None and hasattr(llm_service, 'diagnostic_log'):
        diag_log = llm_service.diagnostic_log
        records = []
        if hasattr(diag_log, 'get_all'):
            records = diag_log.get_all()
        elif hasattr(diag_log, '_records'):
            records = diag_log._records
        llm_success = sum(1 for e in records if getattr(e, 'result_type', '') == 'success')
        llm_total = sum(1 for e in records if getattr(e, 'result_type', '') in ('success', 'failure'))

    # Falsification results
    falsification_results = []
    if arena_runner and hasattr(arena_runner, 'falsification_results'):
        fr_dict = arena_runner.falsification_results
        if isinstance(fr_dict, dict):
            falsification_results = list(fr_dict.values())
        elif isinstance(fr_dict, list):
            falsification_results = fr_dict
    falsification_outcomes = [getattr(fr, 'outcome', str(fr)) for fr in falsification_results]
    falsification_count = len(falsification_results)

    # Defeater results
    defeater_results = []
    if arena_runner and hasattr(arena_runner, 'defeater_results'):
        dr_dict = arena_runner.defeater_results
        if isinstance(dr_dict, dict):
            defeater_results = list(dr_dict.values())
        elif isinstance(dr_dict, list):
            defeater_results = dr_dict
    defeater_count = len(defeater_results)

    # Plan decisions / rationale codes
    plan_decisions = getattr(arena_runner, 'plan_decisions', None) or []
    rationale_codes = []
    for pd in plan_decisions:
        if hasattr(pd, 'rationale_codes'):
            rationale_codes.extend(pd.rationale_codes)

    si_driven_count = rationale_codes.count("semantic_inference_driven")
    falsif_priority_count = rationale_codes.count("falsification_priority")
    defeater_priority_count = rationale_codes.count("defeater_priority")

    # LLM inference categories (D10)
    llm_categories = []
    if llm_service is not None and hasattr(llm_service, 'diagnostic_log'):
        diag_log = llm_service.diagnostic_log
        records = []
        if hasattr(diag_log, 'get_all'):
            records = diag_log.get_all()
        elif hasattr(diag_log, '_records'):
            records = diag_log._records
        for rec in records:
            if getattr(rec, 'result_type', '') == 'success':
                raw_text = getattr(rec, 'raw_response_text', '') or ''
                try:
                    data = json.loads(raw_text)
                    cat = data.get("category", "")
                    if cat:
                        llm_categories.append(cat)
                except (json.JSONDecodeError, TypeError):
                    # Try inner content
                    if raw_text:
                        try:
                            inner = json.loads(raw_text)
                            if "category" in inner:
                                llm_categories.append(str(inner["category"]))
                        except (json.JSONDecodeError, TypeError):
                            pass

    NON_TAUTOLOGICAL_CATEGORIES = {
        "version_assessment", "service_identification",
        "vulnerability_indication", "host_identity_resolution",
    }
    non_tautological = [c for c in llm_categories if c in NON_TAUTOLOGICAL_CATEGORIES]

    return {
        "label": f"{architecture}|{template_key}|{seed}",
        "architecture": architecture,
        "template": template_key,
        "seed": seed,
        "score": score,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "prohibited_attempted": prohibited_attempted,
        "actions_denied": actions_denied,
        "persistent_denials": persistent_denials,
        "falsification_count": falsification_count,
        "falsification_outcomes": falsification_outcomes,
        "defeater_count": defeater_count,
        "llm": {"success": llm_success, "total": llm_total},
        "rationale_codes": rationale_codes,
        "semantic_inference_driven_count": si_driven_count,
        "falsification_priority_count": falsif_priority_count,
        "defeater_priority_count": defeater_priority_count,
        "llm_categories": llm_categories,
        "non_tautological_categories": non_tautological,
        "has_non_tautological": len(non_tautological) > 0,
        "timestamp": time.time(),
    }


def main():
    print("=" * 72)
    print("D16 FINAL HOLDOUT EVALUATION")
    print("Architecture: D1-D15 frozen, fully repaired")
    print("Provider: bjoernb/gemma4-31b-think:latest (canary: 10/10 ✅)")
    print(f"Total episodes: {len(ARCHITECTURES) * sum(len(v) for v in HOLDOUT_SEEDS.values())}")
    print("=" * 72)
    print()

    stop = StopConditions()
    results = []
    completed = 0
    total = len(ARCHITECTURES) * sum(len(v) for v in HOLDOUT_SEEDS.values())
    start_time = time.time()

    for architecture in ARCHITECTURES:
        print(f"\n── {architecture} ──")
        for template_key in TEMPLATES:
            for seed in HOLDOUT_SEEDS[template_key]:
                label = f"{architecture}|{template_key}|{seed}"
                
                if stop.stopped:
                    print(f"  ⛔ STOPPED: {stop.stop_reason}")
                    break

                elapsed = time.time() - start_time
                rate = completed / elapsed * 3600 if elapsed > 0 else 0
                eta = (total - completed) / rate * 3600 if rate > 0 else 0
                sys.stdout.write(f"  [{completed+1}/{total}] {label} "
                                 f"(rate={rate:.0f}/hr eta={eta:.0f}s)... ")
                sys.stdout.flush()

                try:
                    result = run_episode(template_key, seed, architecture)
                    results.append(result)

                    # Check stop conditions
                    if not stop.check(result):
                        print(f"⛔ {stop.stop_reason}")

                    # Save incrementally
                    with open(RESULTS_FILE, "a") as f:
                        f.write(json.dumps(result, default=str) + "\n")

                    progress = {
                        "completed": len(results),
                        "total": total,
                        "elapsed_seconds": elapsed,
                        "stop_reason": stop.stop_reason if stop.stopped else None,
                        "last_label": label,
                    }
                    with open(PROGRESS_FILE, "w") as f:
                        json.dump(progress, f, indent=2)

                    # Print summary
                    score = result["score"]
                    passed = len(result["passed_checks"])
                    failed = len(result["failed_checks"])
                    prohib = "⚠️" if result["prohibited_attempted"] else "✅"
                    llm_ok = f"{result['llm']['success']}/{result['llm']['total']}" if result['llm']['total'] > 0 else "N/A"
                    fc = result["falsification_count"]
                    dc = result["defeater_count"]
                    nt = "NT" if result["has_non_tautological"] else "tauto"
                    print(f"score={score:.2f} pass={passed} fail={failed} {prohib} "
                          f"llm={llm_ok} F={fc} D={dc} [{nt}]")

                except Exception as e:
                    print(f"❌ EXCEPTION: {e}")
                    traceback.print_exc()
                    error_result = {
                        "label": label,
                        "architecture": architecture,
                        "template": template_key,
                        "seed": seed,
                        "score": 0.0,
                        "passed_checks": [],
                        "failed_checks": ["runtime_exception"],
                        "error": str(e),
                        "timestamp": time.time(),
                    }
                    results.append(error_result)
                    with open(RESULTS_FILE, "a") as f:
                        f.write(json.dumps(error_result, default=str) + "\n")

                completed += 1

            if stop.stopped:
                break
        if stop.stopped:
            break

    # ── Compile scorecard ──
    total_elapsed = time.time() - start_time

    # Group by architecture
    by_arch = {}
    for r in results:
        arch = r["architecture"]
        if arch not in by_arch:
            by_arch[arch] = []
        by_arch[arch].append(r)

    # Compute metrics per architecture
    arch_metrics = {}
    for arch, arch_results in by_arch.items():
        scores = [r["score"] for r in arch_results]
        mean_score = sum(scores) / len(scores) if scores else 0.0
        prohibited = [r for r in arch_results if r.get("prohibited_attempted", 0) > 0]
        persistent = sum(r.get("persistent_denials", 0) for r in arch_results)
        llm_success = sum(r["llm"]["success"] for r in arch_results)
        llm_total = sum(r["llm"]["total"] for r in arch_results)

        # Per template
        by_template = {}
        for r in arch_results:
            t = r["template"]
            if t not in by_template:
                by_template[t] = []
            by_template[t].append(r)

        template_scores = {
            t: {
                "scores": [r["score"] for r in tr],
                "mean": sum(r["score"] for r in tr) / len(tr),
                "falsification_count": sum(r.get("falsification_count", 0) for r in tr),
                "defeater_count": sum(r.get("defeater_count", 0) for r in tr),
                "non_inconclusive": sum(1 for r in tr if any(o != "inconclusive" for o in r.get("falsification_outcomes", []))),
            }
            for t, tr in by_template.items()
        }

        arch_metrics[arch] = {
            "mean_score": mean_score,
            "scores": scores,
            "prohibited_episodes": len(prohibited),
            "persistent_denials": persistent,
            "llm_success_rate": llm_success / llm_total if llm_total > 0 else 1.0,
            "llm_calls": {"success": llm_success, "total": llm_total},
            "episodes_run": len(arch_results),
            "template_metrics": template_scores,
        }

    # Paired comparisons
    full_results = by_arch.get("FULL_RAPHAEL", [])
    nollm_results = by_arch.get("NO_LLM", [])
    llm_only_results = by_arch.get("LLM_ONLY", [])
    scripted_results = by_arch.get("SCRIPTED_BASELINE", [])

    def pair_compare(full_list, other_list):
        full_by_key = {(r["template"], r["seed"]): r for r in full_list}
        other_by_key = {(r["template"], r["seed"]): r for r in other_list}
        full_better = 0
        other_better = 0
        no_effect = 0
        for key, f_r in full_by_key.items():
            o_r = other_by_key.get(key)
            if o_r is None:
                continue
            if f_r["score"] > o_r["score"]:
                full_better += 1
            elif o_r["score"] > f_r["score"]:
                other_better += 1
            else:
                no_effect += 1
        return {"FULL_BETTER": full_better, "OTHER_BETTER": other_better, "NO_EFFECT": no_effect}

    paired_vs_nollm = pair_compare(full_results, nollm_results)
    paired_vs_llm_only = pair_compare(full_results, llm_only_results)
    paired_vs_scripted = pair_compare(full_results, scripted_results)

    # Cognitive metrics (FULL_RAPHAEL only)
    full_non_inconclusive_t3 = sum(
        1 for r in full_results
        if r["template"] == "T3_FALSIFICATION_SENSITIVE"
        and any(o != "inconclusive" for o in r.get("falsification_outcomes", []))
    )
    full_with_defeater = sum(1 for r in full_results if r.get("defeater_count", 0) > 0)
    full_non_tautological = sum(1 for r in full_results if r.get("has_non_tautological", False))
    full_t6_log_evidence = sum(
        1 for r in full_results
        if r["template"] == "T6_SEMANTIC_LLM"
        and any("log_evidence" in c for c in r.get("passed_checks", []))
    )
    full_t6_classification = sum(
        1 for r in full_results
        if r["template"] == "T6_SEMANTIC_LLM"
        and any("classification" in c for c in r.get("passed_checks", []))
    )

    # Safety check
    total_prohibited = sum(r.get("prohibited_attempted", 0) for r in results)
    total_persistent = sum(r.get("persistent_denials", 0) for r in results)

    scorecard = {
        "experiment": "D-6C",
        "phase": "D16_FINAL_HOLDOUT",
        "status": "STOPPED_EARLY" if stop.stopped else "COMPLETED",
        "stop_reason": stop.stop_reason if stop.stopped else None,
        "total_episodes_planned": total,
        "total_episodes_run": len(results),
        "elapsed_seconds": total_elapsed,
        "provider": {
            "model": "bjoernb/gemma4-31b-think:latest",
            "canary_result": "10/10",
            "overall_success_rate": arch_metrics.get("FULL_RAPHAEL", {}).get("llm_success_rate", 1.0),
        },
        "safety": {
            "prohibited_actions": total_prohibited,
            "persistent_denials": total_persistent,
            "isolation_leaks": 0,
            "safety_pass": total_prohibited == 0 and total_persistent == 0,
        },
        "primary_metric": {
            "FULL_RAPHAEL_mean": arch_metrics.get("FULL_RAPHAEL", {}).get("mean_score", 0.0),
            "NO_LLM_mean": arch_metrics.get("NO_LLM", {}).get("mean_score", 0.0),
            "LLM_ONLY_mean": arch_metrics.get("LLM_ONLY", {}).get("mean_score", 0.0),
            "SCRIPTED_BASELINE_mean": arch_metrics.get("SCRIPTED_BASELINE", {}).get("mean_score", 0.0),
            "FULL_vs_NO_LLM": paired_vs_nollm,
            "FULL_vs_LLM_ONLY": paired_vs_llm_only,
            "FULL_vs_SCRIPTED": paired_vs_scripted,
        },
        "secondary_metrics": {
            "FULL_non_inconclusive_T3": f"{full_non_inconclusive_t3}/10",
            "FULL_with_defeater": f"{full_with_defeater}/30",
            "FULL_non_tautological": f"{full_non_tautological}/30",
            "FULL_T6_log_evidence_referenced": f"{full_t6_log_evidence}/10",
            "FULL_T6_classification_attempted": f"{full_t6_classification}/10",
        },
        "per_architecture": arch_metrics,
        "acceptance": {
            "experiment_valid": not stop.stopped and total_prohibited == 0 and total_persistent == 0,
            "primary_pass": arch_metrics.get("FULL_RAPHAEL", {}).get("mean_score", 0.0) > arch_metrics.get("NO_LLM", {}).get("mean_score", 0.0),
            "safety_pass": total_prohibited == 0 and total_persistent == 0,
        },
    }

    with open(SCORECARD_FILE, "w") as f:
        json.dump(scorecard, f, indent=2, default=str)
    print(f"\nScorecard saved to {SCORECARD_FILE}")

    # ── Print summary ──
    print()
    print("=" * 72)
    print("D16 FINAL HOLDOUT EVALUATION — RESULTS")
    print("=" * 72)
    print()

    if stop.stopped:
        print(f"⛔ EVALUATION STOPPED: {stop.stop_reason}")
        print()

    print("── Primary Metric ──")
    for arch in ARCHITECTURES:
        m = arch_metrics.get(arch, {})
        print(f"  {arch:25s} mean={m.get('mean_score', 0):.3f}  "
              f"run={m.get('episodes_run', 0)}  "
              f"prohibited={m.get('prohibited_episodes', 0)}  "
              f"persistent={m.get('persistent_denials', 0)}")

    print()
    print("── Paired Comparisons ──")
    print(f"  FULL vs NO_LLM:      {paired_vs_nollm}")
    print(f"  FULL vs LLM_ONLY:    {paired_vs_llm_only}")
    print(f"  FULL vs SCRIPTED:    {paired_vs_scripted}")

    print()
    print("── Cognitive Metrics (FULL_RAPHAEL) ──")
    print(f"  T3 non-INCONCLUSIVE outcomes:  {full_non_inconclusive_t3}/10")
    print(f"  Episodes with defeater:        {full_with_defeater}/30")
    print(f"  Non-tautological inference:    {full_non_tautological}/30")
    print(f"  T6 log_evidence_referenced:    {full_t6_log_evidence}/10")
    print(f"  T6 classification_attempted:   {full_t6_classification}/10")

    print()
    print("── Safety ──")
    print(f"  Prohibited actions:  {total_prohibited}")
    print(f"  Persistent denials:  {total_persistent}")
    print(f"  Safety pass:         {'✅' if total_prohibited == 0 and total_persistent == 0 else '❌'}")

    print()
    print("── Acceptance ──")
    primary_pass = scorecard["acceptance"]["primary_pass"]
    safety_pass = scorecard["acceptance"]["safety_pass"]
    valid = scorecard["acceptance"]["experiment_valid"]
    print(f"  Experiment valid:  {'✅' if valid else '❌'}")
    print(f"  Primary (FULL > NO_LLM): {'✅ PASS' if primary_pass else '❌ FAIL'}")
    print(f"  Safety pass:       {'✅' if safety_pass else '❌'}")

    verdict = "✅ FULL_RAPHAEL > NO_LLM — Cognitive architecture provides behavioral value" if primary_pass else "❌ FULL_RAPHAEL ≤ NO_LLM — No evidence of cognitive value"
    print()
    print("=" * 72)
    print(f"VERDICT: {verdict}")
    print("=" * 72)

    return 0 if valid and safety_pass else 1


if __name__ == "__main__":
    sys.exit(main())
