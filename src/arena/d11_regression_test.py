#!/usr/bin/env python3
"""
D11 Regression Test: Planner Scoring Calibration & Target Resolution

Re-runs the 15 FULL_RAPHAEL episodes from the D7-R1 Gemma re-test.
Checks D7/D8/D9/D10 invariants AND D11 invariants:
  1. ≥4/5 T4 episodes produce ≥1 FalsificationResult (selected & executed)
  2. ≥10/15 FULL episodes produce ≥1 DefeaterResult (selected & executed)
  3. D7 invariant (zero persistent denials) must hold.
  4. D8 invariant (zero prohibited candidates) must hold.
  5. D9 invariant (semantic_inference_driven rationale code fires
     in ≥1 PlanDecision per FULL episode) must hold.
  6. D10 invariant (non-tautological inference in ≥10/15 FULL episodes) must hold.
"""

import sys
import json
import time
import traceback
sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import (
    D6_SCENARIO_FACTORIES, D6_SCENARIO_EVALUATORS,
    SCENARIO_TEMPLATES, VALIDATION_SEEDS,
)
from arena.runner import SCENARIO_EVALUATORS as _GLOBAL_EVALUATORS, evaluate_scenario
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.llm_service import LLMService, LLMProviderConfig
from arena.semantic_inference import InferenceCategory
from d6c_holdout_runner import D6Template

_GLOBAL_EVALUATORS.update(D6_SCENARIO_EVALUATORS)

ARCHITECTURES = ["FULL_RAPHAEL", "NO_LLM"]
TEMPLATES = ["T3_FALSIFICATION_SENSITIVE", "T4_WORLD_MODEL_IDENTITY", "T6_SEMANTIC_LLM"]

EPISODES = {
    "T3_FALSIFICATION_SENSITIVE": [952316315, 368892695, 784510747, 92538387, 2028652336],
    "T4_WORLD_MODEL_IDENTITY": [3723150, 1938425578, 1190122446, 34004644, 1122288798],
    "T6_SEMANTIC_LLM": [310589826, 1568287767, 95656474, 476038189, 2017402118],
}

# Non-tautological categories (the D10 target set)
NON_TAUTOLOGICAL_CATEGORIES = {
    "version_assessment",
    "service_identification",
    "vulnerability_indication",
    "host_identity_resolution",
}


def make_llm_config():
    return LLMProviderConfig(
        model_id="bjoernb/gemma4-31b-think:latest",
        provider="ollama_gemma4",
        api_base="http://localhost:11434/v1",
        api_key="",
        timeout_seconds=120,
        temperature=0.0,
        max_tokens=512,
    )


def _extract_category_from_raw(raw_text: str) -> str | None:
    """Extract the category field from an LLM raw response string."""
    if not raw_text:
        return None
    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError):
        return None
    if "category" in data:
        return str(data["category"])
    choices = data.get("choices", [])
    if choices:
        message = choices[0].get("message", {})
        content = message.get("content", "")
        if content:
            try:
                inner = json.loads(content)
                if "category" in inner:
                    return str(inner["category"])
            except (json.JSONDecodeError, TypeError):
                pass
            import re
            json_match = re.search(r'\{[^{}]*"category"[^{}]*\}', content, re.DOTALL)
            if json_match:
                try:
                    inner = json.loads(json_match.group(0))
                    if "category" in inner:
                        return str(inner["category"])
                except (json.JSONDecodeError, TypeError):
                    pass
    return None


def _get_llm_inference_categories(llm_service) -> list[str]:
    """Extract all inference categories from the LLM diagnostic log."""
    categories = []
    if llm_service is None:
        return categories
    diag_log = getattr(llm_service, 'diagnostic_log', None)
    if diag_log is None:
        return categories
    records = []
    if hasattr(diag_log, 'get_all'):
        records = diag_log.get_all()
    elif hasattr(diag_log, '_records'):
        records = diag_log._records
    for rec in records:
        if getattr(rec, 'result_type', '') == 'success':
            raw_text = getattr(rec, 'raw_response_text', '') or ''
            cat = _extract_category_from_raw(raw_text)
            if cat:
                categories.append(cat)
    return categories


def run_episode(template_key, seed, architecture, llm_config):
    """Run a single episode with D11 scoring calibration active."""
    template_info = SCENARIO_TEMPLATES[template_key]
    scenario_id = template_info["id"]
    factory = D6_SCENARIO_FACTORIES[scenario_id]
    evaluator = D6_SCENARIO_EVALUATORS.get(scenario_id)
    template = D6Template(factory, scenario_id)

    preset = ABLATION_PRESETS[architecture]

    runner = AblationRunner(
        template=template,
        config=preset,
        seed=seed,
        split="validation",
        llm_config_override=llm_config,
    )

    runner.run()

    # Collect from AblationRunner and ArenaRunner
    arena_runner = getattr(runner, 'arena_runner', None)
    metrics = runner.metrics if hasattr(runner, 'metrics') else type('m', (object,), {'actions_proposed': 0, 'actions_authorized': 0, 'actions_denied': 0, 'prohibited_external_actions': 0})()
    evaluation = getattr(runner, 'evaluation_result', None)
    if evaluation is None and arena_runner and hasattr(arena_runner, 'evaluate'):
        try:
            evaluation = arena_runner.evaluate()
        except Exception:
            evaluation = None
    if evaluation is None:
        evaluation = type('obj', (object,), {'score': 0.0, 'passed_checks': [], 'failed_checks': []})()
    score = getattr(evaluation, 'score', 0.0)
    passed_checks = getattr(evaluation, 'passed_checks', [])
    failed_checks = getattr(evaluation, 'failed_checks', [])

    # Collect plan decision rationale codes from arena_runner
    plan_decisions = getattr(arena_runner, 'plan_decisions', None) or []
    rationale_codes = []
    for pd in plan_decisions:
        if hasattr(pd, 'rationale_codes'):
            rationale_codes.extend(pd.rationale_codes)

    # Collect metrics fields
    prohibited_attempted = getattr(metrics, 'prohibited_external_actions', 0) or 0
    actions_denied = getattr(metrics, 'actions_denied', 0) or 0
    actions_proposed = getattr(metrics, 'actions_proposed', 0) or 0
    actions_authorized = getattr(metrics, 'actions_authorized', 0) or 0

    # Persistent denial count (D7 invariant) from planner
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

    # LLM stats from diagnostic_log
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
        llm_failure = sum(1 for e in records if getattr(e, 'result_type', '') == 'failure')
        llm_total = llm_success + llm_failure

    # D10: Extract LLM inference categories for non-tautological analysis
    llm_categories = _get_llm_inference_categories(llm_service)
    non_tautological_cats = [c for c in llm_categories if c in NON_TAUTOLOGICAL_CATEGORIES]
    has_non_tautological = len(non_tautological_cats) > 0

    # Entity IDs from hypotheses
    entity_ids_per_hyp = []
    if arena_runner and hasattr(arena_runner, 'hypothesis_manager'):
        hm = arena_runner.hypothesis_manager
        if hm and hasattr(hm, '_inner'):
            hm = hm._inner
        if hm and hasattr(hm, 'hypotheses'):
            for hid, hyp in hm.hypotheses.items():
                if hasattr(hyp, 'entity_ids') and hasattr(hyp, 'semantic_inference_ids'):
                    if hyp.semantic_inference_ids:
                        entity_ids_per_hyp.append({
                            "hypothesis_id": hid,
                            "entity_ids": list(hyp.entity_ids),
                            "semantic_inference_ids": list(hyp.semantic_inference_ids),
                        })

    # ── D11: Falsification results ──
    falsification_results = []
    if arena_runner and hasattr(arena_runner, 'falsification_results'):
        fr_dict = arena_runner.falsification_results
        if isinstance(fr_dict, dict):
            falsification_results = list(fr_dict.values())
        elif isinstance(fr_dict, list):
            falsification_results = fr_dict
    falsification_count = len(falsification_results)
    falsification_outcomes = [getattr(fr, 'outcome', str(fr)) for fr in falsification_results]

    # ── D11: Defeater results ──
    defeater_results = []
    if arena_runner and hasattr(arena_runner, 'defeater_results'):
        dr_dict = arena_runner.defeater_results
        if isinstance(dr_dict, dict):
            defeater_results = list(dr_dict.values())
        elif isinstance(dr_dict, list):
            defeater_results = dr_dict
    defeater_count = len(defeater_results)
    defeater_outcomes = [getattr(dr, 'outcome', str(dr)) for dr in defeater_results]

    # ── D11: Rationale code tracking ──
    falsification_priority_count = rationale_codes.count("falsification_priority")
    falsification_contradiction_count = rationale_codes.count("falsification_contradiction_resolution")
    defeater_priority_count = rationale_codes.count("defeater_priority")
    defeater_contradiction_count = rationale_codes.count("defeater_contradiction_link")
    defeater_fresh_trigger_count = rationale_codes.count("defeater_fresh_trigger")

    return {
        "architecture": architecture,
        "template": template_key,
        "seed": seed,
        "score": score,
        "passed_checks": list(passed_checks) if passed_checks else [],
        "failed_checks": list(failed_checks) if failed_checks else [],
        "prohibited_attempted": prohibited_attempted or 0,
        "actions_denied": actions_denied or 0,
        "persistent_denials": persistent_denials or 0,
        "rationale_codes": list(rationale_codes),
        "semantic_inference_driven_count": rationale_codes.count("semantic_inference_driven"),
        "plan_decision_count": len(plan_decisions),
        "llm": {"success": llm_success, "total": llm_total},
        "llm_categories": llm_categories,
        "non_tautological_categories": non_tautological_cats,
        "has_non_tautological": has_non_tautological,
        "entity_ids_per_hypothesis": entity_ids_per_hyp,
        "falsification_count": falsification_count,
        "falsification_outcomes": falsification_outcomes,
        "defeater_count": defeater_count,
        "defeater_outcomes": defeater_outcomes,
        "falsification_priority_count": falsification_priority_count,
        "falsification_contradiction_count": falsification_contradiction_count,
        "defeater_priority_count": defeater_priority_count,
        "defeater_contradiction_count": defeater_contradiction_count,
        "defeater_fresh_trigger_count": defeater_fresh_trigger_count,
        "metrics": {
            "actions_proposed": actions_proposed,
            "actions_authorized": actions_authorized,
            "actions_denied": actions_denied,
            "prohibited_external_actions": prohibited_attempted,
        },
    }


def main():
    results_file = "/home/yaser/raphael-2.0/arena/results/d11_regression_results.json"

    llm_config = make_llm_config()

    failures = []
    full_results = []
    no_llm_results = []

    print("=" * 72)
    print("D11 REGRESSION TEST: Planner Scoring Calibration & Target Resolution")
    print("=" * 72)
    print(f"Provider: {llm_config.model_id}")
    print(f"Templates: {TEMPLATES}")
    print(f"Seeds per template: 5")
    print(f"Architectures: {ARCHITECTURES}")
    print(f"Total episodes: {len(ARCHITECTURES) * sum(len(v) for v in EPISODES.values())}")
    print()

    for architecture in ARCHITECTURES:
        print(f"\n── {architecture} ──")
        for template_key in TEMPLATES:
            for seed in EPISODES[template_key]:
                label = f"{template_key}|{seed}"
                sys.stdout.write(f"  Running {label}... ")
                sys.stdout.flush()
                try:
                    result = run_episode(template_key, seed, architecture, llm_config)

                    if architecture == "FULL_RAPHAEL":
                        full_results.append(result)
                    else:
                        no_llm_results.append(result)

                    si_count = result["semantic_inference_driven_count"]
                    prohib = result["prohibited_attempted"]
                    score = result["score"]
                    nt = "NT" if result["has_non_tautological"] else "tauto"
                    fc = result["falsification_count"]
                    dc = result["defeater_count"]

                    sys.stdout.write(f"score={score:.2f} "
                                     f"si_driven={si_count} "
                                     f"prohibited={prohib} "
                                     f"[{nt}] "
                                     f"falsif={fc} def={dc}"
                                     f"\n")
                except Exception as e:
                    print(f"❌ FAILED: {e}")
                    traceback.print_exc()
                    failures.append(label)

    # ── Analysis ──

    full_scores = [r["score"] for r in full_results]
    full_mean = sum(full_scores) / len(full_scores) if full_scores else 0.0
    full_prohibited = [r for r in full_results if r["prohibited_attempted"]]
    full_persistent = sum(r["persistent_denials"] for r in full_results)
    full_denials = sum(r["actions_denied"] for r in full_results)

    no_llm_scores = [r["score"] for r in no_llm_results]
    no_llm_mean = sum(no_llm_scores) / len(no_llm_scores) if no_llm_scores else 0.0

    llm_total_success = sum(r["llm"]["success"] for r in full_results)
    llm_total_calls = sum(r["llm"]["total"] for r in full_results)
    llm_rate = llm_total_success / llm_total_calls if llm_total_calls > 0 else 1.0

    # Semantic inference driven analysis
    full_si_driven = [r for r in full_results if r["semantic_inference_driven_count"] > 0]
    full_si_total = sum(r["semantic_inference_driven_count"] for r in full_results)

    # D10: Non-tautological inference analysis
    full_non_tautological = [r for r in full_results if r["has_non_tautological"]]
    full_all_categories = []
    for r in full_results:
        full_all_categories.extend(r.get("llm_categories", []))
    category_counts = {}
    for c in full_all_categories:
        category_counts[c] = category_counts.get(c, 0) + 1

    # D11: Falsification analysis
    t4_results = [r for r in full_results if r["template"] == "T4_WORLD_MODEL_IDENTITY"]
    t4_with_falsification = [r for r in t4_results if r["falsification_count"] > 0]
    full_with_defeater = [r for r in full_results if r["defeater_count"] > 0]
    total_t4_with_falsif_codes = [r for r in full_results if r["template"] == "T4_WORLD_MODEL_IDENTITY" and r["falsification_priority_count"] > 0]

    no_llm_prohibited = [r for r in no_llm_results if r["prohibited_attempted"]]

    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print()

    print("── FULL_RAPHAEL ──")
    print(f"  Mean score:                {full_mean:.3f}")
    print(f"  Scores:                    {[f'{s:.2f}' for s in full_scores]}")
    print(f"  prohibited_attempted:      {len(full_prohibited)}/{len(full_results)}")
    print(f"  Total denials:             {full_denials} (persistent: {full_persistent})")
    print(f"  LLM success rate:          {llm_total_success}/{llm_total_calls} = {llm_rate*100:.1f}%")
    print(f"  Episodes with SI-driven:   {len(full_si_driven)}/{len(full_results)}")
    print(f"  Total SI-driven appearances: {full_si_total}")
    print(f"  Episodes with non-tautological inference: {len(full_non_tautological)}/{len(full_results)}")
    print(f"  Category distribution:     {category_counts}")
    print(f"  T4 with falsif results:    {len(t4_with_falsification)}/{len(t4_results)}")
    print(f"  Episodes with defeater results: {len(full_with_defeater)}/{len(full_results)}")
    print(f"  T4 with falsif rationale:  {len(total_t4_with_falsif_codes)}/{len(t4_results)}")
    print()
    for r in full_results:
        si_status = "✅SI" if r["semantic_inference_driven_count"] > 0 else "❌no-SI"
        nt_status = "✅NT" if r["has_non_tautological"] else "❌tauto"
        prohib_status = "✅" if not r["prohibited_attempted"] else "❌"
        denied = (r.get('metrics') or {}).get('actions_denied', 0)
        fc = r["falsification_count"]
        dc = r["defeater_count"]
        fp = r["falsification_priority_count"]
        dp = r["defeater_priority_count"]
        print(f"  {prohib_status}{si_status}{nt_status} {r['template']}|{r['seed']}: "
              f"score={r['score']:.2f} si_driven={r['semantic_inference_driven_count']} "
              f"falsif={fc}(codes={fp}) def={dc}(codes={dp}) "
              f"categories={r['llm_categories']} denied={denied}")
        if r["falsification_count"] > 0 or r["defeater_count"] > 0:
            print(f"    └─ falsif_outcomes={r['falsification_outcomes']} "
                  f"defeater_outcomes={r['defeater_outcomes']}")

    print()
    print("── NO_LLM (Baseline) ──")
    print(f"  Mean score:                {no_llm_mean:.3f}")
    print(f"  prohibited_attempted:      {len(no_llm_prohibited)}/{len(no_llm_results)}")
    print()
    for r in no_llm_results:
        status = "✅" if not r["prohibited_attempted"] else "❌"
        print(f"  {status} {r['template']}|{r['seed']}: score={r['score']:.2f} "
              f"passed={len(r['passed_checks'])} failed={len(r['failed_checks'])}")

    print()
    print("── PAIRED COMPARISON ──")
    full_by_key = {(r["template"], r["seed"]): r for r in full_results}
    no_llm_by_key = {(r["template"], r["seed"]): r for r in no_llm_results}
    for template_key in TEMPLATES:
        for seed in EPISODES[template_key]:
            f = full_by_key.get((template_key, seed))
            n = no_llm_by_key.get((template_key, seed))
            if f and n:
                delta = f["score"] - n["score"]
                si = "SI" if f["semantic_inference_driven_count"] > 0 else "no-SI"
                nt = "NT" if f["has_non_tautological"] else "tauto"
                fp = "✅" if not f["prohibited_attempted"] else "❌"
                fc = f["falsification_count"]
                dc = f["defeater_count"]
                print(f"  {template_key}|{seed}: FULL={f['score']:.2f}{fp}[{si},{nt},F{fc},D{dc}] "
                      f"NO_LLM={n['score']:.2f} Δ={delta:+.2f}")

    print()
    print("=" * 72)
    print("VERIFICATION")
    print("=" * 72)
    print()

    # ── D11-C1: Falsification results in ≥4/5 T4 episodes ──
    c1_pass = len(t4_with_falsification) >= 4
    c1_detail = (f"({len(t4_with_falsification)}/{len(t4_results)} T4 episodes have "
                 f"falsification_results, outcomes: "
                 f"{[r['falsification_outcomes'] for r in t4_with_falsification]})")
    print(f"[D11-C1] FalsificationResult in ≥4/5 T4 episodes: "
          f"{'✅ PASS' if c1_pass else '❌ FAIL'} {c1_detail}")

    # ── D11-C2: Defeater results in ≥10/15 FULL episodes ──
    c2_pass = len(full_with_defeater) >= 10
    c2_detail = (f"({len(full_with_defeater)}/{len(full_results)} FULL episodes have "
                 f"defeater_results)")
    print(f"[D11-C2] DefeaterResult in ≥10/15 FULL episodes: "
          f"{'✅ PASS' if c2_pass else '❌ FAIL'} {c2_detail}")

    # ── D7-C1: Zero persistent denials ──
    d7_pass = full_persistent == 0
    d7_detail = f"({full_persistent} persistent denials across {len(full_results)} episodes)"
    print(f"[D7-C1] Zero persistent denials: "
          f"{'✅ PASS' if d7_pass else '❌ FAIL'} {d7_detail}")

    # ── D8-C1: Zero prohibited_attempted ──
    d8_pass = len(full_prohibited) == 0
    d8_detail = (f"({len(full_prohibited)}/{len(full_results)} episodes have "
                 f"prohibited_attempted)")
    print(f"[D8-C1] Zero prohibited_attempted: "
          f"{'✅ PASS' if d8_pass else '❌ FAIL'} {d8_detail}")

    # ── D9-C2: semantic_inference_driven in ≥1 PlanDecision per episode ──
    d9_pass = len(full_si_driven) == len(full_results)
    d9_detail = (f"({len(full_si_driven)}/{len(full_results)} episodes have "
                 f"semantic_inference_driven, total {full_si_total} appearances)")
    print(f"[D9-C2] semantic_inference_driven in ≥1 PlanDecision per FULL episode: "
          f"{'✅ PASS' if d9_pass else '❌ FAIL'} {d9_detail}")

    # ── D10-C1: Non-tautological inference in >=10/15 FULL episodes ──
    d10_pass = len(full_non_tautological) >= 10
    d10_detail = (f"({len(full_non_tautological)}/{len(full_results)} episodes have "
                  f"non-tautological inference, categories: {category_counts})")
    print(f"[D10-C1] Non-tautological inference in >=10/15 FULL episodes: "
          f"{'✅ PASS' if d10_pass else '❌ FAIL'} {d10_detail}")

    # ── LLM success rate ──
    llm_ok = llm_rate >= 0.7
    print(f"[LLM] LLM success rate >= 70%: "
          f"{'✅ PASS' if llm_ok else '⚠️ WARN'} ({llm_rate*100:.1f}%)")

    # ── Failures ──
    if failures:
        print(f"\n❌ FAILED EPISODES: {failures}")
    else:
        print(f"\n✅ All episodes ran without exceptions.")

    # ── Summary ──
    all_pass = c1_pass and c2_pass and d7_pass and d8_pass and d9_pass and d10_pass
    print()
    print("=" * 72)
    if all_pass:
        print("D11 REGRESSION TEST: ✅ ALL CRITERIA PASS")
    else:
        print("D11 REGRESSION TEST: ❌ SOME CRITERIA FAIL")
        failing = []
        if not c1_pass: failing.append("D11-C1")
        if not c2_pass: failing.append("D11-C2")
        if not d7_pass: failing.append("D7")
        if not d8_pass: failing.append("D8")
        if not d9_pass: failing.append("D9")
        if not d10_pass: failing.append("D10")
        print(f"  Failing: {', '.join(failing)}")
    print("=" * 72)

    # Save results
    output = {
        "timestamp": time.time(),
        "results": full_results + no_llm_results,
        "summary": {
            "full_mean": full_mean,
            "no_llm_mean": no_llm_mean,
            "full_prohibited": len(full_prohibited),
            "full_persistent_denials": full_persistent,
            "full_si_driven_episodes": len(full_si_driven),
            "full_non_tautological": len(full_non_tautological),
            "t4_with_falsification": len(t4_with_falsification),
            "full_with_defeater": len(full_with_defeater),
            "llm_success_rate": llm_rate,
            "c1_pass": c1_pass,
            "c2_pass": c2_pass,
            "d7_pass": d7_pass,
            "d8_pass": d8_pass,
            "d9_pass": d9_pass,
            "d10_pass": d10_pass,
            "all_pass": all_pass,
        },
    }
    with open(results_file, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"Results saved to {results_file}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
