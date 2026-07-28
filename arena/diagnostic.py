#!/usr/bin/env python3
"""
Stage 2.5B diagnostic — pipeline table + first-failure classification.

Read-only: never modifies Raphael, environment, or evaluator code.
"""
from __future__ import annotations

import json
import re
import sys
import traceback as tb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arena.ablation_runner import AblationRunner
from arena.ablation import FULL_RAPHAEL
from arena.templates import TEMPLATE_REGISTRY, ScenarioSplit


GAP_TYPES = {
    "ENVIRONMENT_GAP": "ScenarioEnvironment does not produce the expected observation",
    "NORMALIZATION_GAP": "RawObservation → Evidence loses semantic content",
    "REASONING_GAP": "Stage-2 components fail to derive correct state",
    "ACTION_GENERATION_GAP": "No candidate action matching scenario requirements",
    "PLANNING_GAP": "Planner rejects/seque nces incorrectly",
    "AUTHORIZATION_EXPECTED": "Broker denies a necessary action",
    "EVALUATOR_GAP": "Evaluator regex fails on available evidence",
    "SCENARIO_DESIGN_GAP": "Template misconfigured (impossible/contradictory patterns)",
}


def trace_one(template_name: str, seed: int = 0, split: str = "dev") -> dict:
    """Run FULL_RAPHAEL on one template and produce full diagnostic data."""
    template = TEMPLATE_REGISTRY.get(template_name)
    if not template:
        raise ValueError(f"Unknown template: {template_name}")

    runner = AblationRunner(template=template, config=FULL_RAPHAEL, seed=seed, split=split)
    metrics = runner.run()

    # --- Evidence graph ---
    all_ev = runner.arena_runner.evidence_graph.get_all_evidence()
    evidence_items = [getattr(e, "raw_content", str(e)) for e in all_ev]

    # --- Scenario data ---
    scenario = getattr(runner, "scenario", None)
    et = getattr(scenario, "evaluator_truth", {}) if scenario else {}
    success_conditions = et.get("success_conditions", [])
    starting_assets = et.get("starting_assets", [])

    # --- Pipeline stages ---
    pc = metrics.pipeline_coverage or {}
    pipeline_stages = {
        "observation_ingestion": pc.get("observation_ingestion_count", 0) > 0,
        "evidence_creation": pc.get("evidence_creation_count", 0) > 0,
        "world_update": pc.get("world_update_count", 0) > 0,
        "hypothesis_created": pc.get("hypothesis_evaluation_count", 0) > 0,
        "contradiction_check": pc.get("contradiction_check_count", 0) > 0,
        "candidate_generation": pc.get("candidate_generation_count", 0) > 0,
        "planner_invocation": pc.get("planner_invocation_count", 0) > 0,
        "broker_invocation": pc.get("broker_invocation_count", 0) > 0,
        "action_executed": pc.get("execution_count", 0) > 0,
        "belief_update": pc.get("belief_update_count", 0) > 0,
    }

    # Feedback observations: total obs - initial briefings
    initial_briefing = sum(
        1 for e in evidence_items if "target briefing" in e.lower()
    )
    feedback_obs_count = pc.get("observation_ingestion_count", 0) - initial_briefing
    pipeline_stages["feedback_observation"] = feedback_obs_count > 0

    # --- Correct facts check ---
    correct_facts = []
    for cond in success_conditions:
        pattern = cond.get("evidence_pattern", "")
        check_prohibited = cond.get("check_prohibited_actions", False)
        found = False
        if check_prohibited:
            found = True  # Will verify separately below — prohibited actions check
        elif pattern and pattern != "NO_MATCH":
            found = any(re.search(pattern, ev, re.IGNORECASE) for ev in evidence_items)
        correct_facts.append({
            "pattern": pattern,
            "required": cond.get("required", True),
            "description": cond.get("description", ""),
            "found_in_evidence": found,
            "check_prohibited": check_prohibited,
        })

    # --- Episodes ---
    episodes_raw = []
    for ep in runner.episodes.episodes:
        episodes_raw.append({
            "seq": ep.sequence_number,
            "selected_action_type": ep.selected_action.get("action_type") if ep.selected_action else None,
            "selected_action_target": ep.selected_action.get("target") if ep.selected_action else None,
            "method": ep.selected_action.get("method") if ep.selected_action else None,
            "num_candidates": len(ep.candidate_actions),
            "observations_created": len(ep.observations_created),
            "evidence_created": len(ep.evidence_created),
        })

    # --- Hypotheses ---
    hm = getattr(runner.arena_runner, "hypothesis_manager", None)
    hypotheses = []
    if hm and hasattr(hm, "hypotheses"):
        for h in hm.hypotheses:
            hypotheses.append({
                "content": getattr(h, "content", str(h))[:200],
                "status": getattr(h, "status", "unknown"),
                "confidence": getattr(h, "confidence", None),
            })

    # --- World model ---
    wm = getattr(runner.arena_runner, "world_model", None)
    wm_state = []
    if wm and hasattr(wm, "get_world_state"):
        w_state = wm.get_world_state()
        if isinstance(w_state, list):
            wm_state = w_state

    # --- Evaluator ---
    ev_result = getattr(runner, "evaluation_result", None)
    evaluator_passed = getattr(ev_result, "passed_checks", [])
    evaluator_failed = getattr(ev_result, "failed_checks", [])

    # --- First failure ---
    first_failure = identify_first_failure(
        pipeline_stages, correct_facts, str(metrics.outcome.value)
        if hasattr(metrics.outcome, "value") else str(metrics.outcome),
        template_name, evidence_items, success_conditions,
    )

    return {
        "template": template_name,
        "seed": seed,
        "outcome": str(metrics.outcome.value) if hasattr(metrics.outcome, "value") else str(metrics.outcome),
        "pipeline_coverage": dict(pc),
        "pipeline_stages": pipeline_stages,
        "feedback_obs_count": feedback_obs_count,
        "evidence_count": len(evidence_items),
        "evidence_items": evidence_items,
        "hypotheses": hypotheses,
        "world_model_state": [str(s)[:100] for s in wm_state],
        "episodes": episodes_raw,
        "success_conditions": success_conditions,
        "correct_facts": correct_facts,
        "evaluator_passed": evaluator_passed,
        "evaluator_failed": evaluator_failed,
        "first_failure": first_failure,
    }


def identify_first_failure(
    stages: dict, correct_facts: list, outcome: str,
    template_name: str, evidence_items: list, success_conditions: list,
) -> dict:
    """Identify the first failure point and classify its gap type."""

    if not stages.get("evidence_creation"):
        return {
            "stage": "evidence_creation",
            "gap": "NORMALIZATION_GAP",
            "detail": "Initial observations not converted to Evidence items",
        }
    if not stages.get("world_update"):
        return {
            "stage": "world_update",
            "gap": "REASONING_GAP",
            "detail": "Evidence created but WorldModel not updating",
        }
    if not stages.get("hypothesis_created"):
        return {
            "stage": "hypothesis_creation",
            "gap": "REASONING_GAP",
            "detail": "No hypotheses created from evidence",
        }
    if not stages.get("candidate_generation"):
        return {
            "stage": "candidate_generation",
            "gap": "ACTION_GENERATION_GAP",
            "detail": "Hypotheses exist but no candidate actions",
        }
    if not stages.get("planner_invocation"):
        return {
            "stage": "planner_invocation",
            "gap": "PLANNING_GAP",
            "detail": "Candidates exist but planner not invoked",
        }
    if not stages.get("broker_invocation"):
        return {
            "stage": "broker_invocation",
            "gap": "AUTHORIZATION_EXPECTED",
            "detail": "Planner invoked but broker not reached",
        }
    if not stages.get("action_executed"):
        return {
            "stage": "action_execution",
            "gap": "AUTHORIZATION_EXPECTED",
            "detail": "Broker invoked but no actions executed (all denied?)",
        }
    if not stages.get("feedback_observation"):
        return {
            "stage": "feedback_observation",
            "gap": "ENVIRONMENT_GAP",
            "detail": f"Actions executed but env returned 0 observations (feedback_obs_count={stages.get('feedback_obs_count', '?')})",
        }
    if not stages.get("belief_update"):
        return {
            "stage": "belief_update",
            "gap": "REASONING_GAP",
            "detail": "Evidence exists but beliefs not updated",
        }

    # Check each required success condition
    for cf in correct_facts:
        if not cf["required"]:
            continue
        if cf["check_prohibited"]:
            continue  # Handled differently (checking broker logs)
        if cf["found_in_evidence"]:
            continue

        pattern = cf["pattern"]
        if not evidence_items:
            return {
                "stage": f"evidence_content: {cf['description'][:40]}",
                "gap": "ENVIRONMENT_GAP",
                "detail": "No evidence in graph",
            }

        # Near-miss analysis
        pattern_parts = [p.strip().lower() for p in pattern.split("|") if p.strip()]
        near_misses = []
        for ev in evidence_items:
            ev_lower = ev.lower()
            for part in pattern_parts:
                if part and any(word in ev_lower for word in part.replace("\\", "").split(r"\.")):
                    near_misses.append(ev)
                    break

        if near_misses:
            return {
                "stage": f"evaluator_miss: {cf['description'][:40]}",
                "gap": "EVALUATOR_GAP",
                "detail": f"Evidence has near-matches but regex fails. Pattern='{pattern}' Matches={near_misses[:3]}",
            }

        # Check content mismatch
        if evidence_items:
            return {
                "stage": f"evidence_missing: {cf['description'][:40]}",
                "gap": "ENVIRONMENT_GAP",
                "detail": f"Pattern='{pattern}' not in {len(evidence_items)} evidence items. Samples: {evidence_items[:3]}",
            }

    if outcome in ("INCORRECT", "INCONCLUSIVE"):
        return {
            "stage": "evaluator_final",
            "gap": "EVALUATOR_GAP",
            "detail": "All checks passed individually but evaluator returned INCORRECT",
        }

    return {"stage": "none", "gap": "NONE", "detail": "All stages pass"}


def run_diagnostics(
    templates: list[str] | None = None, seed: int = 0, split: str = "dev"
) -> list:
    """Run full diagnostic on all templates."""
    if templates is None:
        templates = list(TEMPLATE_REGISTRY.keys())

    results = []
    for tname in templates:
        print(f"\n{'='*70}")
        print(f"DIAGNOSTIC: {tname} (seed={seed})")
        print(f"{'='*70}")
        try:
            diag = trace_one(tname, seed=seed, split=split)
            results.append(diag)
            print(f"  Outcome: {diag['outcome']}")
            print(f"  Evidence: {diag['evidence_count']} items")
            for k, v in diag["pipeline_stages"].items():
                print(f"  {k:26s}: {'✅' if v else '❌'}")
            ff = diag["first_failure"]
            print(f"  First failure: stage='{ff['stage']}' gap={ff['gap']}")
            print(f"  Detail: {ff['detail']}")
            for cf in diag["correct_facts"]:
                if cf["pattern"]:
                    print(f"  Pattern '{cf['pattern'][:50]}': {'✅' if cf['found_in_evidence'] else '❌'} "
                          f"(req={cf['required']}) — {cf['description'][:40]}")
        except Exception as e:
            print(f"  CRASHED: {e}")
            tb.print_exc()
            results.append({"template": tname, "outcome": "CRASH", "error": str(e)})

    return results


def print_matrix(results: list) -> None:
    """Print pipeline matrix for all templates."""
    stages = [
        "observation_ingestion", "evidence_creation", "world_update",
        "hypothesis_created", "contradiction_check", "candidate_generation",
        "planner_invocation", "broker_invocation", "action_executed",
        "feedback_observation", "belief_update",
    ]

    print("\n\n" + "=" * 130)
    print("PIPELINE MATRIX — ALL TEMPLATES")
    print("=" * 130)
    header = f"{'Stage':28s}"
    for r in results:
        short = r["template"][:18]
        header += f" | {short:18s}"
    print(header)
    print("-" * len(header))

    for stage in stages:
        row = f"{stage:28s}"
        for r in results:
            val = r.get("pipeline_stages", {}).get(stage, False)
            row += f" | {'✅':>18s}" if val else f" | {'❌':>18s}"
        print(row)

    print("\n--- First failure classification ---")
    for r in results:
        ff = r.get("first_failure", {})
        print(f"  {r['template']:22s}: {ff.get('gap','?'):28s} | stage={ff.get('stage','?'):45s}")
        print(f"  {'':22s}  {ff.get('detail', '')}")

    print("\n--- Evidence samples per template ---")
    for r in results:
        evs = r.get("evidence_items", [])
        print(f"\n  {r['template']:22s} ({r.get('outcome','?')}): {len(evs)} items")
        for i, e in enumerate(evs[:4]):
            print(f"    [{i}] {e[:120]}")

    print("\n--- Hypotheses ---")
    for r in results:
        hs = r.get("hypotheses", [])
        if hs:
            print(f"\n  {r['template']}: {len(hs)} hypotheses")
            for h in hs[:3]:
                print(f"    status={h.get('status','?')} confidence={h.get('confidence','?')} content={h.get('content','')[:100]}")
        else:
            print(f"  {r['template']}: 0 hypotheses")


if __name__ == "__main__":
    results = run_diagnostics()
    print_matrix(results)

    out_path = Path(__file__).resolve().parent / "results" / "diagnostic_report.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nReport saved to {out_path}")
