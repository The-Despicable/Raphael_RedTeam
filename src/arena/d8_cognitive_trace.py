#!/usr/bin/env python3
"""
D8 Cognitive Value Diagnosis: Trace LLM SemanticInference causal chain.

Traces a single FULL_RAPHAEL episode (T3 seed 952316315) and captures:
  1. Evidence ingested by the LLM
  2. LLM SemanticInference output (claim, category, confidence)
  3. HypothesisManager consumption of the inference
  4. Whether the inference alters Planner scoring (semantic_inference_driven boost)
  5. Falsification discriminator proposals and outcomes
  6. Final PlanDecision rationale
"""

import sys
import json
import time
sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import D6_SCENARIO_FACTORIES, SCENARIO_TEMPLATES
from arena.ablation import ABLATION_PRESETS
from arena.ablation_runner import AblationRunner
from arena.llm_service import LLMProviderConfig
from arena.semantic_inference import SemanticInferenceSuccess, SemanticInferenceFailure
from d6c_holdout_runner import D6Template

# ── Instrument a single T3 episode ──
template_key = "T3_FALSIFICATION_SENSITIVE"
seed = 952316315
template_info = SCENARIO_TEMPLATES[template_key]
scenario_id = template_info["id"]

template = D6Template(D6_SCENARIO_FACTORIES[scenario_id], scenario_id)
llm_config = LLMProviderConfig(
    model_id="bjoernb/gemma4-31b-think:latest",
    provider="ollama_gemma4",
    api_base="http://localhost:11434/v1",
    api_key="",
    timeout_seconds=30,
    temperature=0.0,
    max_tokens=512,
)

runner = AblationRunner(
    template=template,
    config=ABLATION_PRESETS["FULL_RAPHAEL"],
    seed=seed,
    split="validation",
    llm_config_override=llm_config,
)

metrics = runner.run()
au = runner.arena_runner

# ── Phase 1: LLM Diagnostic Log ──
print("=" * 72)
print("PHASE 1: LLM SEMANTIC INFERENCE CALLS")
print("=" * 72)

llm_svc = getattr(runner, '_llm_service', None)
diagnostic = None
if llm_svc and hasattr(llm_svc, 'diagnostic_log'):
    diagnostic = llm_svc.diagnostic_log
    records = []
    if hasattr(diagnostic, 'get_all'):
        records = diagnostic.get_all()
    elif hasattr(diagnostic, '_records'):
        records = diagnostic._records
    print(f"Total LLM calls: {len(records)}")
    for i, rec in enumerate(records):
        rt = getattr(rec, 'result_type', 'unknown')
        rid = getattr(rec, 'inference_id_or_attempt', '?')
        raw = getattr(rec, 'raw_response_text', '')[:300]
        print(f"\n  Call {i+1}: type={rt}, id={rid}")
        print(f"  Raw response (truncated): {raw}")
        print(f"  Evidence IDs: {getattr(rec, 'source_evidence_ids', [])}")

# ── Phase 2: Evidence Graph ──
print("\n" + "=" * 72)
print("PHASE 2: EVIDENCE GRAPH (ALL EVIDENCE)")
print("=" * 72)

all_ev = au.evidence_graph.get_all_evidence() if au.evidence_graph else []
print(f"Total evidence items: {len(all_ev)}")
for ev in all_ev:
    eid = getattr(ev, 'evidence_id', '?')
    etype = getattr(ev, 'evidence_type', '?')
    content = (getattr(ev, 'raw_content', '') or '')[:120]
    print(f"  [{eid}] type={etype}: {content}")

# ── Phase 3: Hypotheses ──
print("\n" + "=" * 72)
print("PHASE 3: HYPOTHESIS MANAGER")
print("=" * 72)

hm = au.hypothesis_manager if au else None
if hm and hasattr(hm, 'hypotheses'):
    print(f"Total hypotheses: {len(hm.hypotheses)}")
    for hid, hyp in hm.hypotheses.items():
        stmt = getattr(hyp, 'statement', '?')[:100]
        status = getattr(hyp, 'status', '?')
        conf = getattr(hyp, 'confidence', '?')
        eids = getattr(hyp, 'evidence_ids', [])
        iids = getattr(hyp, 'inference_ids', [])
        sem_ids = getattr(hyp, 'semantic_inference_ids', [])
        sources = getattr(hyp, 'sources', [])
        print(f"\n  [{hid}]")
        print(f"    statement: {stmt}")
        print(f"    status: {status}, confidence: {conf}")
        print(f"    evidence_ids: {eids[:3]}...")
        print(f"    inference_ids: {iids[:3]}...")
        print(f"    semantic_inference_ids: {sem_ids}")
        print(f"    sources: {sources}")
        # Check if this hypothesis has semantic_inference_ids (LLM-derived)
        if sem_ids:
            print(f"    🛜 LLM-DERIVED: {len(sem_ids)} semantic inference(s) consumed")
        else:
            print(f"    ⚠️ NO semantic inference IDs — hypothesis was NOT LLM-derived")
else:
    print("No HypothesisManager or no hypotheses")

# ── Phase 4: Planner Decisions ──
print("\n" + "=" * 72)
print("PHASE 4: PLANNER DECISIONS")
print("=" * 72)

if hasattr(au, 'plan_decisions'):
    decisions = au.plan_decisions if isinstance(au.plan_decisions, list) else []
    print(f"Total PlanDecisions: {len(decisions)}")
    for i, pd in enumerate(decisions):
        sid = getattr(pd, 'selected_action_id', '?')
        rc = getattr(pd, 'rationale_codes', ())
        aid = getattr(pd, 'decision_id', '?')
        utility = getattr(pd, 'estimated_utility', 0.0)
        hids = getattr(pd, 'supporting_hypothesis_ids', ())
        evids = getattr(pd, 'supporting_evidence_ids', ())
        wqids = getattr(pd, 'supporting_world_query_ids', ())
        print(f"\n  Decision {i+1}: id={aid}")
        print(f"    selected: {sid}")
        print(f"    rationale_codes: {rc}")
        print(f"    estimated_utility: {utility}")
        print(f"    supporting_hypothesis_ids: {hids}")
        print(f"    supporting_evidence_ids: {evids[:3]}...")
        print(f"    supporting_world_query_ids: {wqids}")
        
        # Check if LLM influenced this decision
        if "semantic_inference_driven" in rc:
            print(f"    🛜 LLM INFLUENCED: semantic_inference_driven in rationale")
        else:
            print(f"    ⚠️ NO LLM influence in rationale codes")
        
        # Check if any hypothesis with semantic_inference_ids is referenced
        if hm and hasattr(hm, 'hypotheses'):
            llm_hyp_ids = [hid for hid in hids if hid in hm.hypotheses 
                          and getattr(hm.hypotheses[hid], 'semantic_inference_ids', [])]
            if llm_hyp_ids:
                print(f"    🛜 LLM-derived hypotheses consumed: {llm_hyp_ids}")
            elif hids:
                print(f"    ⚠️ All consumed hypotheses lack semantic_inference_ids")
else:
    print("No plan_decisions on arena_runner")

# ── Phase 5: Planner internal state ──
print("\n" + "=" * 72)
print("PHASE 5: PLANNER INTERNAL STATE")
print("=" * 72)

planner = au.planner if au else None
if planner and hasattr(planner, '_inner'):
    planner = planner._inner

if planner:
    print(f"feedback_records: {len(planner.feedback_records) if hasattr(planner, 'feedback_records') else 'N/A'}")
    print(f"unavailable_actions: {len(planner.unavailable_actions) if hasattr(planner, 'unavailable_actions') else 'N/A'}")
    print(f"suppressed_proposals: {len(planner.suppressed_proposals) if hasattr(planner, 'suppressed_proposals') else 'N/A'}")
else:
    print("No Planner")

# ── Phase 6: Falsification ──
print("\n" + "=" * 72)
print("PHASE 6: FALSIFICATION RESULTS")
print("=" * 72)

if hasattr(au, 'falsification_results'):
    results = au.falsification_results if isinstance(au.falsification_results, list) else []
    print(f"Total falsification results: {len(results)}")
    for i, fr in enumerate(results):
        outcome = getattr(fr, 'outcome', '?')
        hid = getattr(fr, 'hypothesis_id', '?')
        cid = getattr(fr, 'contradiction_id', '?')
        pre = getattr(fr, 'prior_confidence', '?')
        post = getattr(fr, 'posterior_confidence', '?')
        rc = getattr(fr, 'reason_codes', ())
        print(f"\n  Result {i+1}: outcome={outcome}")
        print(f"    hypothesis_id: {hid}")
        print(f"    contradiction_id: {cid}")
        print(f"    confidence: {pre} → {post}")
        print(f"    reason_codes: {rc}")
else:
    print("No falsification_results")

# ── Phase 7: Brokder Action Log ──
print("\n" + "=" * 72)
print("PHASE 7: BROKER ACTION LOG")
print("=" * 72)

if au and hasattr(au, 'broker') and hasattr(au.broker, 'get_action_log'):
    action_log = au.broker.get_action_log()
    print(f"Total action log entries: {len(action_log)}")
    for i, entry in enumerate(action_log):
        print(f"  {i+1}. {entry[:120] if isinstance(entry, str) else str(entry)[:120]}")
else:
    print("No broker action log")

# ── Phase 8: Defeater Results ──
print("\n" + "=" * 72)
print("PHASE 8: DEFEATER RESULTS")
print("=" * 72)

if hasattr(au, 'defeater_results'):
    drs = au.defeater_results if isinstance(au.defeater_results, list) else []
    print(f"Total defeater results: {len(drs)}")
    for i, dr in enumerate(drs):
        print(f"  {i+1}: {str(dr)[:150]}")
else:
    print("No defeater_results")

# ── Summary ──
print("\n" + "=" * 72)
print("COGNITIVE VALUE SUMMARY")
print("=" * 72)

llm_calls = 0
llm_success = 0
if diagnostic:
    recs = []
    if hasattr(diagnostic, 'get_all'):
        recs = diagnostic.get_all()
    elif hasattr(diagnostic, '_records'):
        recs = diagnostic._records
    llm_calls = len(recs)
    llm_success = sum(1 for r in recs if getattr(r, 'result_type', '') == 'success')

llm_hypotheses = 0
if hm and hasattr(hm, 'hypotheses'):
    llm_hypotheses = sum(1 for hyp in hm.hypotheses.values() 
                         if getattr(hyp, 'semantic_inference_ids', []))

llm_influenced_decisions = 0
if hasattr(au, 'plan_decisions'):
    for pd in (au.plan_decisions or []):
        if "semantic_inference_driven" in getattr(pd, 'rationale_codes', ()):
            llm_influenced_decisions += 1

print(f"LLM calls: {llm_calls} ({llm_success} success)")
print(f"LLM-derived hypotheses: {llm_hypotheses}")
print(f"LLM-influenced PlanDecisions: {llm_influenced_decisions}")
print(f"Total PlanDecisions: {len(getattr(au, 'plan_decisions', []) or [])}")
print(f"Falsification results: {len(getattr(au, 'falsification_results', []) or [])}")
print(f"prohibited_attempts: {au.prohibited_attempts}")
print(f"Score: {metrics.score if hasattr(metrics, 'score') else 'N/A'}")
print()

if llm_hypotheses == 0:
    print("🔴 FINDING: LLM output is NOT being consumed as hypotheses.")
    print("   The SemanticInferenceSuccess result is created but never reaches")
    print("   the HypothesisManager as a semantic_inference_id.")
elif llm_influenced_decisions == 0:
    print("🟡 FINDING: LLM-derived hypotheses exist but do not influence Planning.")
    print("   The Planner receives hypothesis_ids but does not use the")
    print("   semantic_inference_driven scoring boost.")
else:
    print("🟢 FINDING: LLM causally integrated.")
    print(f"   {llm_influenced_decisions}/{llm_calls} decisions show LLM influence.")
