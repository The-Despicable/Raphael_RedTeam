#!/usr/bin/env python3
"""
D13 Cognitive Efficacy Diagnostic Runner.
Executes Traces A, B, C, D — instrumentation only, no source modifications.
Archives raw data to arena/results/d13_traces/.

Usage:
    python3 arena/d13_diagnostic_runner.py

Per SENTINEL directive (GLM-5.2, 2026-07-27):
    Rule 42 — No Feature Escape. No repairs. Diagnosis only.
"""

import sys
import os
import json
import time
import traceback
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arena.d6_manifest import D6_SCENARIO_FACTORIES, D6_SCENARIO_EVALUATORS, SCENARIO_TEMPLATES
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.llm_service import LLMProviderConfig
from d6c_holdout_runner import D6Template

# ── Archive setup ────────────────────────────────────────────────
TRACES_DIR = Path(__file__).resolve().parent / "results" / "d13_traces"
TRACES_DIR.mkdir(parents=True, exist_ok=True)

# ── LLM Config ──────────────────────────────────────────────────
LLM_CONFIG = LLMProviderConfig(
    model_id='bjoernb/gemma4-31b-think:latest',
    provider='ollama_gemma4',
    api_base='http://localhost:11434/v1',
    api_key='',
    timeout_seconds=120,
    temperature=0.0,
    max_tokens=512,
)

PRESET = ABLATION_PRESETS['FULL_RAPHAEL']

# ── Trace specs ─────────────────────────────────────────────────
TRACES = [
    {
        "name": "Trace_A_T4",
        "label": "T4 Falsification Efficacy — Identity Contradiction",
        "template_key": "T4_WORLD_MODEL_IDENTITY",
        "seed": 3723150,
        "trace_points": [
            "falsification_candidate_creation",
            "discriminator_action_selection",
            "environment_http_get",
            "claim_matching",
            "falsification_result_creation",
        ],
    },
    {
        "name": "Trace_B_T3",
        "label": "T3 Falsification Efficacy — Version Contradiction",
        "template_key": "T3_FALSIFICATION_SENSITIVE",
        "seed": 952316315,
        "trace_points": [
            "falsification_candidate_creation",
            "discriminator_action_selection",
            "environment_http_get",
            "claim_matching",
            "falsification_result_creation",
        ],
    },
    {
        "name": "Trace_C_T6",
        "label": "T6 LLM Translation Gap",
        "template_key": "T6_SEMANTIC_LLM",
        "seed": 310589826,
        "trace_points": [
            "llm_inference_content",
            "planner_action_selection",
            "evaluation_result",
            "claim_text_analysis",
        ],
    },
]


def instrument_and_run(trace_spec: dict) -> dict:
    """
    Run a single diagnostic trace with temporary instrumentation.
    
    Uses monkey-patching to inspect intermediate values at trace points.
    Does NOT modify any source files.
    """
    print(f"\n{'='*70}")
    print(f"[D13] TRACE: {trace_spec['label']}")
    print(f"       Template: {trace_spec['template_key']}")
    print(f"       Seed:     {trace_spec['seed']}")
    print(f"{'='*70}")
    
    trace_data = {
        "trace_name": trace_spec["name"],
        "trace_label": trace_spec["label"],
        "template": trace_spec["template_key"],
        "seed": trace_spec["seed"],
        "trace_points": {},
        "plan_decisions": [],
        "observations": [],
        "falsification_results": [],
        "contradictions": [],
        "llm_inferences": [],
        "hypothesis_states": [],
        "evidence_snapshot": [],
        "evaluation_result": None,
        "errors": [],
    }
    
    # ── Import modules (after path-setup) ──
    import arena.ablation_runner as ar_module
    import arena.environment as env_module
    from arena.conclusion import FalsificationResult, FalsificationOutcome
    
    # ── Monkey-patch 1: _handle_http_get to log observation responses ──
    _original_handle_http_get = env_module.ScenarioEnvironment._handle_http_get
    
    def _diagnostic_handle_http_get(self, target, capability, method, receipt_id):
        """Wrapped to log HTTP response details."""
        result = _original_handle_http_get(self, target, capability, method, receipt_id)
        for obs in result:
            raw = obs.raw_output if hasattr(obs, 'raw_output') else ""
            status = "200 OK" if "200 OK" in raw else ("404 Not Found" if "404" in raw else "unknown")
            trace_data["trace_points"].setdefault("environment_http_get", []).append({
                "target": target,
                "capability": capability,
                "method": method,
                "receipt_id": receipt_id,
                "status": status,
                "raw_output_preview": raw[:300],
                "observation_id": obs.observation_id if hasattr(obs, 'observation_id') else None,
            })
        return result
    
    env_module.ScenarioEnvironment._handle_http_get = _diagnostic_handle_http_get
    
    # ── Monkey-patch 2: AblationRunner._generate_candidates to log falsification candidates ──
    _original_generate = ar_module.AblationRunner._generate_candidates
    
    def _diagnostic_generate(self, *args, **kwargs):
        """Wrapped to log falsification candidate creation.""" 
        result = _original_generate(self, *args, **kwargs)
        candidates, view = result if isinstance(result, tuple) else (result, None)
        
        falsification_candidates = [
            c for c in candidates if c.get("_is_falsification")
        ]
        if falsification_candidates:
            for fc in falsification_candidates:
                trace_data["trace_points"].setdefault("falsification_candidate_creation", []).append({
                    "action_id": fc.get("action_id"),
                    "action_type": fc.get("action_type"),
                    "target": fc.get("target"),
                    "capability": fc.get("capability"),
                    "discriminator_id": fc.get("discriminator_id"),
                    "contradiction_id": fc.get("contradiction_id"),
                    "rationale": fc.get("rationale"),
                })
        
        return result
    
    ar_module.AblationRunner._generate_candidates = _diagnostic_generate
    
    # ── Monkey-patch 3: Action loop discriminator execution ──
    # We need to instrument the run loop. The easiest way is to wrap
    # the _execute_action_impl or similar method.
    # The key trace point is at ablation_runner.py:1344-1419.
    # Since this is inside a complex method, we'll use a callback approach.
    
    # Store reference to the runner's process_observations for instrumentation
    _original_step = ar_module.AblationRunner._execute_action_impl if hasattr(ar_module.AblationRunner, '_execute_action_impl') else None
    
    # ── Build and run ──
    scenario_id = SCENARIO_TEMPLATES[trace_spec["template_key"]]['id']
    factory = D6_SCENARIO_FACTORIES[scenario_id]
    template = D6Template(factory, scenario_id)
    
    runner = AblationRunner(
        template=template,
        config=PRESET,
        seed=trace_spec["seed"],
        split='validation',
        llm_config_override=LLM_CONFIG,
    )
    
    start_time = time.time()
    
    try:
        # Run the episode — this calls build → execute → evaluate
        result = runner.run()
        
        trace_data["total_time"] = time.time() - start_time
        trace_data["run_id"] = getattr(runner, 'run_id', None)
        
        # ── Collect PlanDecisions ──
        if hasattr(runner, 'arena_runner') and runner.arena_runner:
            ar = runner.arena_runner
            pd_list = []
            if hasattr(ar, 'plan_decision') and ar.plan_decision:
                pd = ar.plan_decision
                pd_list.append({
                    "decision_id": getattr(pd, 'decision_id', None),
                    "selected_action_id": getattr(pd, 'selected_action_id', None),
                    "considered_action_ids": list(getattr(pd, 'considered_action_ids', [])),
                    "rejected_action_ids": list(getattr(pd, 'rejected_action_ids', [])),
                    "rationale_codes": list(getattr(pd, 'rationale_codes', [])),
                })
            # Also check action_history
            if hasattr(ar, 'action_history'):
                for act in ar.action_history:
                    if hasattr(act, 'action_type') and act.action_type == 'direct_probe':
                        pd_list.append({
                            "action_id": getattr(act, 'action_id', None) if hasattr(act, 'action_id') else None,
                            "action_type": getattr(act, 'action_type', None) if hasattr(act, 'action_type') else None,
                            "target": getattr(act, 'target', None) if hasattr(act, 'target') else None,
                            "rationale": getattr(act, 'rationale', None) if hasattr(act, 'rationale') else None,
                        })
            trace_data["plan_decisions"] = pd_list
        
        # ── Collect Observations (all) ──
        if hasattr(runner, 'arena_runner') and runner.arena_runner:
            ar = runner.arena_runner
            if hasattr(ar, 'evidence_graph'):
                eg = ar.evidence_graph
                all_ev = eg.get_all_evidence() if hasattr(eg, 'get_all_evidence') else []
                trace_data["evidence_snapshot"] = [
                    {
                        "evidence_id": getattr(e, 'evidence_id', None),
                        "target": getattr(e, 'target', None),
                        "evidence_type": getattr(e, 'evidence_type', None),
                        "raw_content_preview": (getattr(e, 'raw_content', None) or '')[:300],
                        "entity_hint": getattr(e, 'entity_hint', None),
                    }
                    for e in all_ev
                ]
        
        # ── Collect FalsificationResults ──
        fr_list = []
        # Check on arena_runner (where D-3 stores them)
        if hasattr(runner, 'arena_runner') and runner.arena_runner:
            ar = runner.arena_runner
            if hasattr(ar, 'falsification_results'):
                for fr in ar.falsification_results:
                    if hasattr(fr, 'to_dict'):
                        fr_dict = fr.to_dict()
                    elif isinstance(fr, dict):
                        fr_dict = fr
                    else:
                        fr_dict = {"raw": str(fr)[:200]}
                    fr_list.append(fr_dict)
        
        # Also check on runner.arena_runner.contradiction_manager
        if hasattr(runner, 'arena_runner') and runner.arena_runner:
            ar = runner.arena_runner
            if hasattr(ar, 'contradiction_manager'):
                cm = ar.contradiction_manager
                # Get discriminators
                if hasattr(cm, 'discriminators'):
                    for disc_id, disc in cm.discriminators.items() if hasattr(cm.discriminators, 'items') else []:
                        trace_data["trace_points"].setdefault("discriminator_inventory", []).append({
                            "discriminator_id": disc_id,
                            "contradiction_id": getattr(disc, 'contradiction_id', None),
                            "action_spec": getattr(disc, 'action_spec', {}),
                            "description": getattr(disc, 'description', '')[:200],
                        })
                # Get contradictions
                if hasattr(cm, 'contradictions'):
                    for con_id, con in cm.contradictions.items() if hasattr(cm.contradictions, 'items') else []:
                        con_dict = con.to_dict() if hasattr(con, 'to_dict') else {}
                        trace_data.setdefault("contradictions", []).append({
                            "contradiction_id": con_id,
                            "claim_a": con_dict.get('claim_a', getattr(con, 'claim_a', ''))[:200],
                            "claim_b": con_dict.get('claim_b', getattr(con, 'claim_b', ''))[:200],
                            "evidence_ids": list(con_dict.get('evidence_ids', getattr(con, 'evidence_ids', []))),
                        })
        
        trace_data["falsification_results"] = fr_list
        
        # ── Collect LLM Inferences ──
        if hasattr(runner, 'arena_runner') and runner.arena_runner:
            ar = runner.arena_runner
            if hasattr(ar, 'llm_service') and hasattr(ar.llm_service, 'inference_history'):
                inf_hist = ar.llm_service.inference_history
                for inf in inf_hist:
                    inf_dict = {}
                    if hasattr(inf, 'to_dict'):
                        inf_dict = inf.to_dict()
                    elif hasattr(inf, '_asdict'):
                        inf_dict = inf._asdict()
                    else:
                        inf_dict = {
                            "claim": getattr(inf, 'claim', str(inf))[:200],
                            "category": str(getattr(inf, 'category', '?')),
                            "confidence": getattr(inf, 'confidence', None),
                        }
                    trace_data["llm_inferences"].append(inf_dict)
        
        # ── Collect Hypothesis States ──
        if hasattr(runner, 'arena_runner') and runner.arena_runner:
            ar = runner.arena_runner
            if hasattr(ar, 'hypothesis_manager'):
                hm = ar.hypothesis_manager
                hyps = getattr(hm, 'hypotheses', {}) or {}
                for hid, hyp in hyps.items():
                    trace_data["hypothesis_states"].append({
                        "hypothesis_id": hid,
                        "statement": getattr(hyp, 'statement', '')[:200],
                        "status": str(getattr(hyp, 'status', '?')),
                        "confidence": getattr(hyp, 'current_confidence', None),
                    })
        
        # ── Collect Evaluation Result ──
        eval_result = getattr(runner, 'evaluation_result', None)
        if eval_result:
            trace_data["evaluation_result"] = {
                "score": getattr(eval_result, 'score', None),
                "verdict": str(getattr(eval_result, 'verdict', '?')),
                "passed_checks": getattr(eval_result, 'passed_checks', []),
                "failed_checks": getattr(eval_result, 'failed_checks', []),
                "details": getattr(eval_result, 'details', {}),
            }
        
        # ── Trace C specific: LLM prompt/response content ──
        if trace_spec["template_key"] == "T6_SEMANTIC_LLM":
            # Get the actual LLM prompt from the inference
            trace_data["trace_points"]["llm_inference_content"] = []
            for inf in trace_data["llm_inferences"]:
                trace_data["trace_points"]["llm_inference_content"].append({
                    "claim": inf.get("claim", "")[:500],
                    "category": inf.get("category", "?"),
                    "confidence": inf.get("confidence"),
                    "has_breach": "breach" in (inf.get("claim", "") or "").lower(),
                    "has_benign": "benign" in (inf.get("claim", "") or "").lower(),
                    "has_malicious": "malicious" in (inf.get("claim", "") or "").lower(),
                })
            
            # Check claim text for classification keywords
            all_claim_text = ""
            if trace_data["evaluation_result"]:
                all_claim_text = json.dumps(trace_data["evaluation_result"])
            for ev in trace_data["evidence_snapshot"]:
                all_claim_text += " " + (ev.get("raw_content_preview") or "")
            for inf in trace_data["llm_inferences"]:
                all_claim_text += " " + (inf.get("claim") or "")
            
            trace_data["trace_points"]["claim_text_analysis"] = {
                "contains_breach": "breach" in all_claim_text.lower(),
                "contains_benign": "benign" in all_claim_text.lower(),
                "contains_malicious": "malicious" in all_claim_text.lower(),
                "contains_info": "info" in all_claim_text.lower(),
                "contains_warn": "warn" in all_claim_text.lower(),
                "contains_error": "error" in all_claim_text.lower(),
                "contains_auditd": "auditd" in all_claim_text.lower(),
                "sample_text": all_claim_text[:1000],
            }
        
        # ── Trace D: Discriminator ID audit ──
        trace_data["trace_points"]["discriminator_id_propagation"] = {
            "candidate_entries": trace_data["trace_points"].get("falsification_candidate_creation", []),
            "discriminator_inventory": trace_data["trace_points"].get("discriminator_inventory", []),
            "falsification_results_count": len(fr_list),
            "falsification_results_disc_ids": [
                fr.get("discriminator_action_id", fr.get("discriminator_id", None))
                for fr in fr_list
            ],
        }
    
    except Exception as e:
        trace_data["errors"].append({
            "type": type(e).__name__,
            "message": str(e),
            "traceback": traceback.format_exc(),
        })
        trace_data["total_time"] = time.time() - start_time
    
    # ── Restore originals ──
    env_module.ScenarioEnvironment._handle_http_get = _original_handle_http_get
    ar_module.AblationRunner._generate_candidates = _original_generate
    
    return trace_data


def save_trace(trace_data: dict):
    """Save trace data to archive."""
    filename = f"{trace_data['trace_name']}_seed{trace_data['seed']}.json"
    filepath = TRACES_DIR / filename
    
    with open(filepath, 'w') as f:
        json.dump(trace_data, f, indent=2, default=str)
    
    print(f"  [SAVED] {filepath}")
    return filepath


def print_summary(trace_data: dict):
    """Print a concise summary of the trace findings."""
    name = trace_data["trace_name"]
    errors = trace_data.get("errors", [])
    frs = trace_data.get("falsification_results", [])
    ev = trace_data.get("evaluation_result", {})
    
    print(f"\n  ── {name} Summary ──")
    
    if errors:
        print(f"  ❌ ERRORS: {len(errors)}")
        for e in errors:
            print(f"     {e['type']}: {e['message'][:200]}")
    else:
        print(f"  ✅ No runtime errors")
    
    if frs:
        print(f"  FalsificationResults: {len(frs)}")
        for fr in frs:
            outcome = fr.get("outcome", "?")
            disc_id = fr.get("discriminator_action_id", fr.get("discriminator_id", None))
            post_conf = fr.get("posterior_confidence")
            print(f"    outcome={outcome} disc_id={disc_id} post_conf={post_conf}")
            con_ids = fr.get("contradictory_evidence_ids", [])
            sup_ids = fr.get("supporting_evidence_ids", [])
            print(f"    contradictory_evidence_ids={con_ids}")
            print(f"    supporting_evidence_ids={sup_ids}")
            print(f"    observation_ids={fr.get('discriminator_observation_ids', [])}")
    else:
        print(f"  FalsificationResults: 0")
    
    if ev:
        print(f"  Score: {ev.get('score')} | Verdict: {ev.get('verdict')}")
        print(f"  Passed: {ev.get('passed_checks', [])}")
        print(f"  Failed: {ev.get('failed_checks', [])}")
    
    # Print HTTP response details
    for tp_name, tp_data in trace_data.get("trace_points", {}).items():
        if tp_name == "environment_http_get" and tp_data:
            for entry in tp_data:
                print(f"  HTTP: {entry.get('target')} → {entry.get('status')}")
                preview = entry.get("raw_output_preview", "")[:200]
                print(f"    Response: {preview}")
        
        if tp_name == "falsification_candidate_creation" and tp_data:
            for entry in tp_data:
                print(f"  Falsif Candidate: target={entry.get('target')} "
                      f"disc_id={entry.get('discriminator_id')} "
                      f"con_id={entry.get('contradiction_id')}")
        
        if tp_name == "claim_text_analysis" and tp_data:
            print(f"  Claim Text Analysis:")
            for k, v in tp_data.items():
                if k != "sample_text":
                    print(f"    {k}: {v}")
    
    print()


def main():
    """Run all diagnostic traces."""
    print("=" * 70)
    print("D13 COGNITIVE EFFICACY DIAGNOSTIC RUNNER")
    print("Per SENTINEL directive (GLM-5.2, 2026-07-27)")
    print(f"Archiving to: {TRACES_DIR}")
    print("=" * 70)
    
    all_trace_data = {}
    
    for trace_spec in TRACES:
        trace_data = instrument_and_run(trace_spec)
        save_trace(trace_data)
        print_summary(trace_data)
        all_trace_data[trace_spec["name"]] = trace_data
    
    # ── Save consolidated summary ──
    summary = {
        "diagnostic_spec": "D13_COGNITIVE_EFFICACY_DIAGNOSIS_SPEC",
        "run_timestamp": time.time(),
        "total_traces": len(TRACES),
        "traces_completed": sum(1 for t in all_trace_data.values() if not t.get("errors")),
        "traces_with_errors": sum(1 for t in all_trace_data.values() if t.get("errors")),
        "trace_names": list(all_trace_data.keys()),
    }
    
    summary_path = TRACES_DIR / "diagnostic_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"Consolidated summary: {summary_path}")
    
    return all_trace_data


if __name__ == "__main__":
    main()
