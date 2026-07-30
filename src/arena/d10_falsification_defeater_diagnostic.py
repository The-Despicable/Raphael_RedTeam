#!/usr/bin/env python3
"""
D10 Falsification & Defeater Diagnostic Trace

Runs the 15 FULL_RAPHAEL episodes and instruments the Falsification
and Defeater pipelines to answer SENTINEL's four questions:

1. Falsification Activation: Is ContradictionManager.detect_contradictions() invoked?
2. Falsification Output: Are FalsificationResult objects produced? With what outcomes?
3. Defeater Activation: Does DefeaterGenerator.find_defeaters() produce triggers?
4. Consumption: Are these outputs consumed by Planner or HypothesisManager?
"""

import sys
import json
import time
import traceback
sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import (
    D6_SCENARIO_FACTORIES, D6_SCENARIO_EVALUATORS,
    SCENARIO_TEMPLATES,
)
from arena.runner import SCENARIO_EVALUATORS as _GLOBAL_EVALUATORS
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.llm_service import LLMProviderConfig
from arena.defeater import DefeaterOutcome
from arena.conclusion import FalsificationOutcome
from d6c_holdout_runner import D6Template

_GLOBAL_EVALUATORS.update(D6_SCENARIO_EVALUATORS)

ARCHITECTURE = "FULL_RAPHAEL"
TEMPLATES = ["T3_FALSIFICATION_SENSITIVE", "T4_WORLD_MODEL_IDENTITY", "T6_SEMANTIC_LLM"]

EPISODES = {
    "T3_FALSIFICATION_SENSITIVE": [952316315, 368892695, 784510747, 92538387, 2028652336],
    "T4_WORLD_MODEL_IDENTITY": [3723150, 1938425578, 1190122446, 34004644, 1122288798],
    "T6_SEMANTIC_LLM": [310589826, 1568287767, 95656474, 476038189, 2017402118],
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


def run_diagnostic_episode(template_key, seed, llm_config):
    """Run a single FULL_RAPHAEL episode and instrument Falsification/Defeater."""
    template_info = SCENARIO_TEMPLATES[template_key]
    scenario_id = template_info["id"]
    factory = D6_SCENARIO_FACTORIES[scenario_id]
    evaluator = D6_SCENARIO_EVALUATORS.get(scenario_id)
    template = D6Template(factory, scenario_id)

    preset = ABLATION_PRESETS[ARCHITECTURE]

    runner = AblationRunner(
        template=template,
        config=preset,
        seed=seed,
        split="validation",
        llm_config_override=llm_config,
    )

    runner.run()

    # Get arena_runner for component access
    arena_runner = getattr(runner, 'arena_runner', None)

    # ── 1. Falsification Activation ──
    contradiction_manager = getattr(arena_runner, 'contradiction_manager', None)
    contradictions_detected = {}
    discriminators_proposed = {}
    discriminators_executed = {}

    if contradiction_manager:
        # Contradictions detected
        all_cons = getattr(contradiction_manager, 'contradictions', {}) or {}
        contradictions_detected = {
            cid: {
                "claim_a": con.claim_a[:100] if hasattr(con, 'claim_a') else '?',
                "claim_b": con.claim_b[:100] if hasattr(con, 'claim_b') else '?',
                "contradiction_type": getattr(con, 'contradiction_type', '?'),
                "status": getattr(con, 'status', '?'),
            }
            for cid, con in all_cons.items()
        }

        # Discriminators proposed
        all_discs = getattr(contradiction_manager, 'discriminators', {}) or {}
        discriminators_proposed = {
            did: {
                "contradiction_id": getattr(d, 'contradiction_id', '?'),
                "proposed_action": getattr(d, 'proposed_action', '?'),
            }
            for did, d in all_discs.items()
        }

        # Check which discriminators were executed
        discriminators_executed = {
            did: {
                "executed": getattr(d, 'executed', False),
                "outcome": getattr(d, 'outcome', None),
            }
            for did, d in all_discs.items()
        }

    # ── 2. Falsification Output ──
    # Note: falsification_results is stored on arena_runner (self.arena_runner in _run_raphael),
    # not on the top-level AblationRunner. Verified at ablation_runner.py:1417-1419.
    falsification_results_raw = getattr(arena_runner, 'falsification_results', []) or []
    # Handle both dict and object results
    falsification_results_list = []
    for fr in falsification_results_raw:
        if hasattr(fr, 'to_dict'):
            falsification_results_list.append(fr.to_dict())
        elif isinstance(fr, dict):
            falsification_results_list.append(fr)
        else:
            falsification_results_list.append({
                "falsification_id": getattr(fr, 'falsification_id', str(fr)),
                "outcome": getattr(fr, 'outcome', '?'),
            })

    # Count falsification outcomes
    falsification_outcomes = {}
    for fr in falsification_results_list:
        outcome = fr.get("outcome", "?")
        if isinstance(outcome, FalsificationOutcome):
            outcome = outcome.value
        falsification_outcomes[outcome] = falsification_outcomes.get(outcome, 0) + 1

    # ── 3. Defeater Activation ──
    defeater_triggers = getattr(arena_runner, 'defeater_triggers', []) or []
    defeater_triggers_list = []
    for dt in defeater_triggers:
        if hasattr(dt, 'to_dict'):
            defeater_triggers_list.append(dt.to_dict())
        elif isinstance(dt, dict):
            defeater_triggers_list.append(dt)
        else:
            defeater_triggers_list.append({
                "defeater_id": getattr(dt, 'defeater_id', str(dt)),
                "condition_description": getattr(dt, 'condition_description', '?')[:100],
                "suggested_action_type": getattr(dt, 'suggested_action_type', '?'),
            })

    # Defeater results
    defeater_results = getattr(arena_runner, 'defeater_results', []) or []
    defeater_results_list = []
    for dr in defeater_results:
        if hasattr(dr, 'to_dict'):
            defeater_results_list.append(dr.to_dict())
        elif isinstance(dr, dict):
            defeater_results_list.append(dr)
        else:
            defeater_results_list.append({
                "result_id": getattr(dr, 'result_id', str(dr)),
                "outcome": getattr(dr, 'outcome', '?'),
            })

    # Count defeater outcomes
    defeater_outcomes = {}
    for dr in defeater_results_list:
        outcome = dr.get("outcome", "?")
        if isinstance(outcome, DefeaterOutcome):
            outcome = outcome.value
        defeater_outcomes[outcome] = defeater_outcomes.get(outcome, 0) + 1

    # ── 4. Consumption: HypothesisManager belief changes ──
    hypothesis_updates = []
    hypothesis_manager = getattr(arena_runner, 'hypothesis_manager', None)
    if hypothesis_manager:
        hyps = getattr(hypothesis_manager, 'hypotheses', {}) or {}
        for hid, hyp in hyps.items():
            hypothesis_updates.append({
                "hypothesis_id": hid,
                "statement": getattr(hyp, 'statement', '')[:150],
                "status": getattr(hyp, 'status', '?'),
                "confidence": getattr(hyp, 'current_confidence', None),
                "assumptions": getattr(hyp, 'assumptions', [])[:3],
                "entity_ids": list(getattr(hyp, 'entity_ids', []))[:3],
            })

    # Planner rationale codes
    plan_decisions = getattr(arena_runner, 'plan_decisions', None) or []
    planner_rationales = []
    falsification_rationale_count = 0
    defeater_rationale_count = 0
    for pd in plan_decisions:
        codes = list(getattr(pd, 'rationale_codes', []))
        planner_rationales.extend(codes)
        falsification_rationale_count += sum(1 for c in codes if 'falsif' in c.lower())
        defeater_rationale_count += sum(1 for c in codes if 'defeat' in c.lower())

    # ── Evaluation ──
    evaluation = getattr(runner, 'evaluation_result', None)
    if evaluation is None and arena_runner and hasattr(arena_runner, 'evaluate'):
        try:
            evaluation = arena_runner.evaluate()
        except Exception:
            evaluation = None
    score = getattr(evaluation, 'score', 0.0) if evaluation else 0.0

    return {
        "template": template_key,
        "seed": seed,
        "score": score,
        "falsification": {
            "contradictions_detected": contradictions_detected,
            "contradiction_count": len(contradictions_detected),
            "discriminators_proposed": len(discriminators_proposed),
            "discriminators_executed": discriminators_executed,
            "falsification_results_count": len(falsification_results_list),
            "falsification_results": falsification_results_list,
            "falsification_outcomes": falsification_outcomes,
        },
        "defeater": {
            "defeater_triggers_count": len(defeater_triggers_list),
            "defeater_triggers": defeater_triggers_list,
            "defeater_results_count": len(defeater_results_list),
            "defeater_results": defeater_results_list,
            "defeater_outcomes": defeater_outcomes,
        },
        "consumption": {
            "hypothesis_count": len(hypothesis_updates),
            "hypotheses": hypothesis_updates,
            "plan_decision_count": len(plan_decisions),
            "planner_rationale_codes": planner_rationales,
            "falsification_in_rationale": falsification_rationale_count,
            "defeater_in_rationale": defeater_rationale_count,
        },
    }


def main():
    llm_config = make_llm_config()
    results = []

    print("=" * 72)
    print("D10 FALSIFICATION & DEFEATER DIAGNOSTIC")
    print("=" * 72)
    print(f"Architecture: {ARCHITECTURE}")
    print(f"Provider: {llm_config.model_id}")
    print(f"Episodes: 15")
    print()

    for template_key in TEMPLATES:
        for seed in EPISODES[template_key]:
            label = f"{template_key}|{seed}"
            sys.stdout.write(f"  {label}... ")
            sys.stdout.flush()
            try:
                result = run_diagnostic_episode(template_key, seed, llm_config)
                results.append(result)

                # Print summary line
                con_count = result["falsification"]["contradiction_count"]
                fr_count = result["falsification"]["falsification_results_count"]
                dt_count = result["defeater"]["defeater_triggers_count"]
                dr_count = result["defeater"]["defeater_results_count"]
                score = result["score"]
                sys.stdout.write(
                    f"score={score:.2f} "
                    f"contra={con_count} "
                    f"fals_res={fr_count} "
                    f"def_trig={dt_count} "
                    f"def_res={dr_count}\n"
                )
            except Exception as e:
                print(f"❌ FAILED: {e}")
                traceback.print_exc()

    # ── Aggregate ──
    print()
    print("=" * 72)
    print("AGGREGATE DIAGNOSTIC REPORT")
    print("=" * 72)
    print()

    total_episodes = len(results)

    # Q1: Falsification Activation
    episodes_with_contradictions = sum(
        1 for r in results if r["falsification"]["contradiction_count"] > 0
    )
    total_contradictions = sum(r["falsification"]["contradiction_count"] for r in results)
    episodes_with_discriminators = sum(
        1 for r in results if r["falsification"]["discriminators_proposed"] > 0
    )
    total_discriminators = sum(r["falsification"]["discriminators_proposed"] for r in results)
    episodes_with_executed_discriminators = sum(
        1 for r in results
        if any(
            d.get("executed", False)
            for d in r["falsification"]["discriminators_executed"].values()
        )
    )

    print("── Q1: FALSIFICATION ACTIVATION ──")
    print(f"  Episodes with contradictions detected:  {episodes_with_contradictions}/{total_episodes}")
    print(f"  Total contradictions:                   {total_contradictions}")
    print(f"  Episodes with discriminators proposed:  {episodes_with_discriminators}/{total_episodes}")
    print(f"  Total discriminators proposed:           {total_discriminators}")
    print(f"  Episodes with executed discriminators:  {episodes_with_executed_discriminators}/{total_episodes}")
    print()

    # Q2: Falsification Output
    episodes_with_falsification_results = sum(
        1 for r in results if r["falsification"]["falsification_results_count"] > 0
    )
    total_falsification_results = sum(r["falsification"]["falsification_results_count"] for r in results)
    total_outcomes = {}
    for r in results:
        for outcome, count in r["falsification"]["falsification_outcomes"].items():
            total_outcomes[outcome] = total_outcomes.get(outcome, 0) + count

    print("── Q2: FALSIFICATION OUTPUT ──")
    print(f"  Episodes with falsification results:     {episodes_with_falsification_results}/{total_episodes}")
    print(f"  Total falsification results:              {total_falsification_results}")
    print(f"  Outcome distribution:                     {total_outcomes}")
    if total_falsification_results > 0:
        print()
        print("  Detailed per-episode:")
        for r in results:
            if r["falsification"]["falsification_results_count"] > 0:
                outcomes = r["falsification"]["falsification_outcomes"]
                print(f"    {r['template']}|{r['seed']}: {outcomes}")
                for fr in r["falsification"]["falsification_results"][:3]:
                    print(f"      - id={fr.get('falsification_id', '?')[:16]}..."
                          f" outcome={fr.get('outcome', '?')}")
    print()

    # Q3: Defeater Activation
    episodes_with_defeater_triggers = sum(
        1 for r in results if r["defeater"]["defeater_triggers_count"] > 0
    )
    total_defeater_triggers = sum(r["defeater"]["defeater_triggers_count"] for r in results)
    episodes_with_defeater_results = sum(
        1 for r in results if r["defeater"]["defeater_results_count"] > 0
    )
    total_defeater_results = sum(r["defeater"]["defeater_results_count"] for r in results)
    total_defeater_outcomes = {}
    for r in results:
        for outcome, count in r["defeater"]["defeater_outcomes"].items():
            total_defeater_outcomes[outcome] = total_defeater_outcomes.get(outcome, 0) + count

    print("── Q3: DEFEATER ACTIVATION ──")
    print(f"  Episodes with defeater triggers:         {episodes_with_defeater_triggers}/{total_episodes}")
    print(f"  Total defeater triggers generated:        {total_defeater_triggers}")
    print(f"  Episodes with defeater results:           {episodes_with_defeater_results}/{total_episodes}")
    print(f"  Total defeater results:                   {total_defeater_results}")
    print(f"  Outcome distribution:                     {total_defeater_outcomes}")
    if total_defeater_triggers > 0:
        print()
        print("  Sample trigger conditions:")
        seen_conditions = set()
        for r in results:
            for dt in r["defeater"]["defeater_triggers"]:
                cond = dt.get("condition_description", "")[:80]
                if cond and cond not in seen_conditions:
                    seen_conditions.add(cond)
                    sug = dt.get("suggested_action_type", "?")
                    print(f"    - \"{cond}\" → action={sug}")
    print()

    # Q4: Consumption
    episodes_with_falsification_in_rationale = sum(
        1 for r in results if r["consumption"]["falsification_in_rationale"] > 0
    )
    episodes_with_defeater_in_rationale = sum(
        1 for r in results if r["consumption"]["defeater_in_rationale"] > 0
    )
    total_falsification_in_rationale = sum(
        r["consumption"]["falsification_in_rationale"] for r in results
    )
    total_defeater_in_rationale = sum(
        r["consumption"]["defeater_in_rationale"] for r in results
    )

    print("── Q4: CONSUMPTION ──")
    print(f"  Episodes with 'falsif*' in planner rationale: {episodes_with_falsification_in_rationale}/{total_episodes}")
    print(f"  Total 'falsif*' rationale codes:               {total_falsification_in_rationale}")
    print(f"  Episodes with 'defeat*' in planner rationale:  {episodes_with_defeater_in_rationale}/{total_episodes}")
    print(f"  Total 'defeat*' rationale codes:               {total_defeater_in_rationale}")
    print()

    # Per-episode summary
    print("── PER-EPISODE DETAIL ──")
    for r in results:
        fr_count = r["falsification"]["falsification_results_count"]
        dt_count = r["defeater"]["defeater_triggers_count"]
        dr_count = r["defeater"]["defeater_results_count"]
        f_rationale = r["consumption"]["falsification_in_rationale"]
        d_rationale = r["consumption"]["defeater_in_rationale"]
        cons = r["falsification"]["contradiction_count"]
        disc = r["falsification"]["discriminators_proposed"]
        print(f"  {r['template']}|{r['seed']}: "
              f"score={r['score']:.2f} "
              f"contra={cons} disc={disc} "
              f"FR={fr_count} DT={dt_count} DR={dr_count} "
              f"R_fals={f_rationale} R_def={d_rationale}")
        if fr_count > 0:
            for fr in r["falsification"]["falsification_results"][:2]:
                print(f"    FR: outcome={fr.get('outcome','?')} id={fr.get('falsification_id','?')[:12]}...")
        if dr_count > 0:
            for dr in r["defeater"]["defeater_results"][:2]:
                print(f"    DR: outcome={dr.get('outcome','?')} id={dr.get('result_id','?')[:12]}...")

    # ── Summary ──
    print()
    print("=" * 72)
    print("VERDICT")
    print("=" * 72)
    print()

    q1_active = episodes_with_contradictions > 0
    q2_producing = episodes_with_falsification_results > 0
    q3_active = episodes_with_defeater_triggers > 0
    q4_consumed = episodes_with_falsification_in_rationale > 0 or episodes_with_defeater_in_rationale > 0

    print(f"[Q1] Falsification activated:  {'✅ YES' if q1_active else '❌ NO'} "
          f"({episodes_with_contradictions}/{total_episodes} episodes)")
    print(f"[Q2] Falsification outputs:    {'✅ YES' if q2_producing else '❌ NO'} "
          f"({total_falsification_results} results across {episodes_with_falsification_results} episodes)")
    print(f"[Q3] Defeater activated:       {'✅ YES' if q3_active else '❌ NO'} "
          f"({total_defeater_triggers} triggers across {episodes_with_defeater_triggers} episodes)")
    print(f"[Q4] Consumption by Planner:   {'✅ YES' if q4_consumed else '❌ NO'} "
          f"(falsif={total_falsification_in_rationale}, defeat={total_defeater_in_rationale} codes)")
    print()

    if q1_active and q2_producing and q3_active and q4_consumed:
        print("BOTH Falsification and Defeater pipelines are LIVE and CONSUMED.")
    elif q1_active and q2_producing:
        print("Falsification pipeline is live and producing results.")
        if not q3_active:
            print("Defeater pipeline is NOT active.")
        if not q4_consumed:
            print("Outputs are NOT being consumed by Planner.")
    elif not q1_active:
        print("Neither pipeline is active. Contradictions not being detected.")
    elif not q2_producing:
        print("Falsification detects contradictions but produces no results.")
    elif not q3_active:
        print("Defeater pipeline is NOT active.")
    else:
        print("Mixed status.")

    # Save report
    report_path = "/home/yaser/raphael-2.0/arena/results/d10_falsification_defeater_diagnostic.json"
    output = {
        "spec": "D10_FALSIFICATION_DEFEATER_DIAGNOSTIC",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "architecture": ARCHITECTURE,
        "total_episodes": total_episodes,
        "findings": {
            "q1_falsification_activated": q1_active,
            "q2_falsification_outputs": q2_producing,
            "q3_defeater_activated": q3_active,
            "q4_planner_consumption": q4_consumed,
        },
        "aggregate": {
            "episodes_with_contradictions": episodes_with_contradictions,
            "total_contradictions": total_contradictions,
            "episodes_with_discriminators": episodes_with_discriminators,
            "total_discriminators": total_discriminators,
            "episodes_with_executed_discriminators": episodes_with_executed_discriminators,
            "episodes_with_falsification_results": episodes_with_falsification_results,
            "total_falsification_results": total_falsification_results,
            "falsification_outcomes": total_outcomes,
            "episodes_with_defeater_triggers": episodes_with_defeater_triggers,
            "total_defeater_triggers": total_defeater_triggers,
            "episodes_with_defeater_results": episodes_with_defeater_results,
            "total_defeater_results": total_defeater_results,
            "defeater_outcomes": total_defeater_outcomes,
            "falsification_in_rationale": total_falsification_in_rationale,
            "defeater_in_rationale": total_defeater_in_rationale,
        },
        "episodes": results,
    }
    with open(report_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nFull diagnostic report saved to {report_path}")


if __name__ == "__main__":
    main()
