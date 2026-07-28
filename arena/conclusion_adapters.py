"""conclusion_adapters.py — Thin adapters from internal state to RunConclusion.

Each adapter converts already-existing run state into the common RunConclusion
contract. Adapters must NOT:
  - perform environment actions
  - query evaluator truth
  - invoke Broker
  - run planning
  - create new observations
  - perform substantial hypothesis inference
  - recreate disabled reasoning capabilities

They are representation conversion layers, not replacement reasoning engines.
"""

import time
from typing import Any, Optional

from arena.runner import ArenaRunner
from arena.ablation import AblationConfig
from arena.conclusion import (
    RunConclusion, ConclusionClaim, ConclusionPredicate,
    ConclusionProvenance, DerivationType, DecisionOutcome,
    make_claim, make_runconclusion,
)
from orchestrator.brain.evidence import Evidence
from orchestrator.brain.world import Entity, Relationship
from orchestrator.brain.hypothesis import HypothesisManager, Hypothesis, HypothesisStatus
from orchestrator.brain.contradiction import ContradictionManager


# ── Shared helpers (used by multiple adapters) ─────────────────

def _collect_evidence_ids(
    evidence_graph,
    max_count: int = 20,
) -> tuple[str, ...]:
    """Collect evidence IDs from the evidence graph."""
    if evidence_graph is None:
        return ()
    try:
        all_ev = evidence_graph.get_all_evidence()
        return tuple(ev.evidence_id for ev in all_ev[:max_count])
    except Exception:
        return ()


def _decision_from_state(decision_text: str) -> DecisionOutcome:
    """Map a decision string to DecisionOutcome."""
    mapping = {
        "ACT": DecisionOutcome.ACT,
        "STOP_OBJECTIVE_REACHED": DecisionOutcome.STOP_OBJECTIVE_REACHED,
        "STOP_INSUFFICIENT_EVIDENCE": DecisionOutcome.STOP_INSUFFICIENT_EVIDENCE,
        "STOP_NO_AUTHORIZED_PATH": DecisionOutcome.STOP_NO_AUTHORIZED_PATH,
        "STOP_BUDGET_EXHAUSTED": DecisionOutcome.STOP_BUDGET_EXHAUSTED,
    }
    return mapping.get(decision_text, DecisionOutcome.STOP_BUDGET_EXHAUSTED)


# ── Planner-derived claims ────────────────────────────────────────

def _plan_decision_to_claims(plan_decision) -> list[ConclusionClaim]:
    """Convert a PlanDecision to structured claims.
    
    Thin conversion: reads existing PlanDecision, does NOT form new decisions.
    """
    claims = []
    if plan_decision is None:
        return claims
    
    try:
        # Claim about the decision itself
        claims.append(make_claim(
            subject_id=plan_decision.decision_id,
            predicate=ConclusionPredicate.OBSERVED_PROPERTY,
            object_value={"type": "plan_decision", "selected_action": plan_decision.selected_action_id},
            supporting_evidence_ids=plan_decision.supporting_evidence_ids,
            derivation_type=DerivationType.PLANNER_ANALYSIS,
            producer="planner",
            plan_decision_ids=(plan_decision.decision_id,),
        ))
        
        # Claims about rationale
        for rationale in plan_decision.rationale_codes:
            claims.append(make_claim(
                subject_id=plan_decision.decision_id,
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={"rationale": rationale},
                supporting_evidence_ids=plan_decision.supporting_evidence_ids,
                derivation_type=DerivationType.PLANNER_ANALYSIS,
                producer="planner",
                plan_decision_ids=(plan_decision.decision_id,),
            ))
        
        # Claim about cost/utility estimates
        if plan_decision.estimated_cost > 0 or plan_decision.estimated_utility > 0:
            claims.append(make_claim(
                subject_id=plan_decision.decision_id,
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={
                    "estimated_cost": plan_decision.estimated_cost,
                    "estimated_risk": plan_decision.estimated_risk,
                    "estimated_utility": plan_decision.estimated_utility,
                },
                supporting_evidence_ids=plan_decision.supporting_evidence_ids,
                derivation_type=DerivationType.PLANNER_ANALYSIS,
                producer="planner",
                plan_decision_ids=(plan_decision.decision_id,),
            ))
        
    except Exception:
        pass
    
    return claims


# ── Hypothesis-derived claims ──────────────────────────────────

def _hypothesis_to_claims(
    hypothesis_manager,
    evidence_ids: tuple[str, ...],
) -> list[ConclusionClaim]:
    """Convert active hypotheses to ConclusionClaims.
    
    Thin conversion: reads existing hypotheses, does NOT form new ones.
    """
    claims = []
    if hypothesis_manager is None:
        return claims
    
    try:
        hypotheses = getattr(hypothesis_manager, 'hypotheses', {})
        for hid, h in hypotheses.items():
            statement = getattr(h, 'statement', '') or ''
            status = str(getattr(h, 'status', 'unknown'))
            
            if status in ('falsified', 'abandoned', 'rejected'):
                continue  # Skip inactive hypotheses
            
            h_evidence_ids = tuple(
                getattr(h, 'evidence_ids', [])[:10]
            ) or evidence_ids
            
            # Get semantic inference IDs for model inference provenance
            h_si_ids = tuple(
                getattr(h, 'semantic_inference_ids', [])[:10]
            )
            
            # Parse statement into claim predicates where possible
            # This is intentionally simple — we extract key patterns
            # rather than doing full NLU
            _extract_claims_from_statement(
                statement, h_evidence_ids, claims, 
                hypothesis_id=hid, model_inference_ids=h_si_ids
            )
            
    except Exception:
        pass
    
    return claims


def _extract_claims_from_statement(
    statement: str,
    evidence_ids: tuple[str, ...],
    claims: list[ConclusionClaim],
    hypothesis_id: str = "",
    model_inference_ids: tuple[str, ...] = (),
):
    """Extract structured claims from a hypothesis statement.
    
    This is the ONLY place where hypothesis text is parsed.
    It runs during adapter construction, NOT during evaluation.
    The evaluator never sees raw hypothesis text.
    """
    import re as _re
    
    stmt_lower = statement.lower()
    
    # SAME HOST identity resolution
    if 'same host' in stmt_lower or 'same_entity_as' in stmt_lower:
        hid_match = _re.search(r'host_id=(\S+)', statement)
        subject = hid_match.group(1) if hid_match else "unknown"
        claims.append(make_claim(
            subject_id=subject,
            predicate=ConclusionPredicate.SAME_ENTITY_AS,
            object_value="dual-homed host",
            supporting_evidence_ids=evidence_ids,
            derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
            hypothesis_ids=(hypothesis_id,) if hypothesis_id else (),
            model_inference_ids=model_inference_ids,
        ))
    
    # DIFFERENT HOSTS
    if 'different host' in stmt_lower:
        claims.append(make_claim(
            subject_id="unknown",
            predicate=ConclusionPredicate.DIFFERENT_ENTITY_FROM,
            object_value="separate hosts",
            supporting_evidence_ids=evidence_ids,
            derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
        ))
    
    # Category classification
    cat_match = _re.search(r'Category\s+([A-D])\b', statement)
    if cat_match:
        cat = cat_match.group(1)
        if cat == 'A':
            claims.append(make_claim(
                subject_id="admin_endpoint",
                predicate=ConclusionPredicate.RESOURCE_ACCESSIBLE,
                object_value="accessible",
                supporting_evidence_ids=evidence_ids,
                derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
            ))
        elif cat == 'B':
            claims.append(make_claim(
                subject_id="admin_endpoint",
                predicate=ConclusionPredicate.RESOURCE_BLOCKED,
                object_value="blocked",
                supporting_evidence_ids=evidence_ids,
                derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
            ))
    
    # Service type identification
    for svc in ['ssh', 'http', 'https', 'tls', 'custom']:
        if svc in stmt_lower:
            claims.append(make_claim(
                subject_id="target",
                predicate=ConclusionPredicate.SERVICE_TYPE,
                object_value=svc,
                supporting_evidence_ids=evidence_ids,
                derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
            ))
    
    # Host identity anchor
    hid = _re.search(r'HOST-\w+-\w+', statement)
    if hid:
        claims.append(make_claim(
            subject_id="host",
            predicate=ConclusionPredicate.HOST_IDENTITY,
            object_value=hid.group(),
            supporting_evidence_ids=evidence_ids,
            derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
        ))


# ── Semantic Inference-derived claims ─────────────────────────────

def _semantic_inference_to_claims(
    hypothesis_manager,
    evidence_ids: tuple[str, ...],
) -> list[ConclusionClaim]:
    """Convert semantic inferences from hypotheses to MODEL_INFERENCE claims.
    
    Thin conversion: reads existing hypotheses, extracts semantic inference info.
    """
    claims = []
    if hypothesis_manager is None:
        return claims
    
    try:
        hypotheses = getattr(hypothesis_manager, 'hypotheses', {})
        for hid, h in hypotheses.items():
            status = str(getattr(h, 'status', 'unknown'))
            
            if status in ('falsified', 'abandoned', 'rejected'):
                continue  # Skip inactive hypotheses
            
            # Get semantic inference IDs from this hypothesis
            si_ids = tuple(
                getattr(h, 'semantic_inference_ids', [])[:10]
            )
            
            if not si_ids:
                continue
            
            # Get evidence IDs for this hypothesis
            h_evidence_ids = tuple(
                getattr(h, 'evidence_ids', [])[:10]
            )
            
            # Create a claim for each semantic inference
            for si_id in si_ids:
                # Get the statement (claim content)
                statement = getattr(h, 'statement', '') or ''
                
                # Create a claim with MODEL_INFERENCE derivation
                from arena.conclusion import make_claim, ConclusionPredicate, DerivationType
                claim = make_claim(
                    subject_id=si_id,
                    predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                    object_value={"semantic_claim": statement},
                    supporting_evidence_ids=evidence_ids,
                    derivation_type=DerivationType.LLM_INTERPRETATION,
                    hypothesis_ids=(hid,),
                    model_inference_ids=(si_id,),
                    confidence=0.0,  # Not calibrated
                )
                claims.append(claim)
                
    except Exception:
        pass
    
    return claims

def _world_model_to_claims(world_model) -> list[ConclusionClaim]:
    """Convert World Model entities and relationships to claims.
    
    Thin conversion: iterates existing WM state, does NOT query or infer.
    """
    claims = []
    if world_model is None:
        return claims
    
    try:
        # Entity resolution: same host_id across entities
        wm_entities = getattr(world_model, 'entities', None) or {}
        host_id_entities = {}
        for ent in wm_entities.values():
            hid = ent.identifiers.get('host_id', '')
            if hid:
                if hid not in host_id_entities:
                    host_id_entities[hid] = []
                host_id_entities[hid].append(ent)
        
        for hid, entities in host_id_entities.items():
            if len(entities) >= 2:
                ent_names = [e.primary_identifier or e.name for e in entities]
                claims.append(make_claim(
                    subject_id=ent_names[0] if ent_names else hid,
                    predicate=ConclusionPredicate.SAME_ENTITY_AS,
                    object_value=ent_names[1] if len(ent_names) > 1 else "unknown",
                    supporting_evidence_ids=tuple(
                        eid for e in entities
                        for eid in getattr(e, 'evidence_ids', [])
                    ) or (),
                    derivation_type=DerivationType.WORLD_MODEL_RELATIONSHIP,
                ))
                claims.append(make_claim(
                    subject_id="host",
                    predicate=ConclusionPredicate.HOST_IDENTITY,
                    object_value=hid,
                    derivation_type=DerivationType.WORLD_MODEL_RELATIONSHIP,
                ))
        
        # Relationships as service claims
        wm_relationships = getattr(world_model, 'relationships', None) or {}
        for rel in wm_relationships.values():
            if rel.relationship_type.value == 'runs_on':
                claims.append(make_claim(
                    subject_id=rel.source_entity_id,
                    predicate=ConclusionPredicate.HAS_SERVICE,
                    object_value={"entity": rel.target_entity_id},
                    supporting_evidence_ids=tuple(getattr(rel, 'evidence_ids', [])),
                    derivation_type=DerivationType.WORLD_MODEL_RELATIONSHIP,
                ))
    
    except Exception:
        pass
    
    return claims


# ── Evidence-derived claims ────────────────────────────────────

def _evidence_to_claims(
    evidence_graph,
    evidence_ids: tuple[str, ...],
) -> list[ConclusionClaim]:
    """Convert evidence observations to basic claims.
    
    This handles the deterministic extraction path.
    Does NOT perform hypothesis inference.
    """
    claims = []
    if evidence_graph is None:
        return claims
    
    try:
        all_ev = evidence_graph.get_all_evidence()
        evidence_texts = [getattr(e, 'raw_content', '') or '' for e in all_ev]
        combined = ' '.join(evidence_texts)
        
        import re as _re
        
        # Service detection from evidence
        for svc, pattern in [('http', r'http|HTTP|Apache|nginx'), 
                             ('ssh', r'SSH|OpenSSH|ssh[:-]'),
                             ('custom', r'CUSTOM|custom/'),
                             ('tls', r'TLS|tls|HTTPS')]:
            if _re.search(pattern, combined):
                claims.append(make_claim(
                    subject_id="target",
                    predicate=ConclusionPredicate.SERVICE_TYPE,
                    object_value=svc,
                    supporting_evidence_ids=evidence_ids,
                    derivation_type=DerivationType.DIRECT_OBSERVATION,
                ))
        
        # Host identity from evidence
        hid = _re.search(r'HOST-\w+-\w+', combined)
        if hid:
            claims.append(make_claim(
                subject_id="host",
                predicate=ConclusionPredicate.HOST_IDENTITY,
                object_value=hid.group(),
                supporting_evidence_ids=evidence_ids,
                derivation_type=DerivationType.DIRECT_OBSERVATION,
            ))
        
        # Port/service discovery
        port_matches = _re.findall(r'port\s+(\d+)\s+(\w+)', combined)
        for port, svc_name in port_matches[:3]:
            claims.append(make_claim(
                subject_id=f"target:{port}",
                predicate=ConclusionPredicate.HAS_SERVICE,
                object_value={"port": int(port), "type": svc_name.lower()},
                supporting_evidence_ids=evidence_ids,
                derivation_type=DerivationType.DIRECT_OBSERVATION,
            ))
    
    except Exception:
        pass
    
    return claims


# ── LLM-derived claims ─────────────────────────────────────────

def _evidence_to_llm_claims(
    evidence_graph,
    evidence_ids: tuple[str, ...],
) -> list[ConclusionClaim]:
    """Extract LLM MODEL_INFERENCE claims from evidence graph.
    
    Looks for evidence items with evidence_type='model_inference'
    and converts them to claims. This is a thin conversion — the
    LLM already ran; we're just reading its output.
    """
    claims = []
    if evidence_graph is None:
        return claims
    
    try:
        all_ev = evidence_graph.get_all_evidence()
        inference_evs = [
            ev for ev in all_ev
            if getattr(ev, 'evidence_type', '') == 'model_inference'
        ]
        
        for ev in inference_evs:
            content = getattr(ev, 'raw_content', '') or ''
            ev_id = ev.evidence_id
            
            import re as _re
            
            # Extract classification
            cat_match = _re.search(r'Category\s+([A-D])\b', content)
            if cat_match:
                cat = cat_match.group(1)
                predicate = ConclusionPredicate.RESOURCE_BLOCKED
                if cat == 'A':
                    predicate = ConclusionPredicate.RESOURCE_ACCESSIBLE
                elif cat == 'B':
                    predicate = ConclusionPredicate.RESOURCE_BLOCKED
                elif cat == 'C':
                    predicate = ConclusionPredicate.OBSERVED_PROPERTY
                
                claims.append(make_claim(
                    subject_id="admin_endpoint",
                    predicate=predicate,
                    object_value=f"Category {cat}",
                    supporting_evidence_ids=(ev_id,),
                    derivation_type=DerivationType.LLM_INTERPRETATION,
                    model_inference_ids=(ev_id,),
                ))
    
    except Exception:
        pass
    
    except Exception:
        pass
    
    return claims


# ── Plan Decision-derived claims ────────────────────────────────

def _plan_decision_to_claims(
    plan_decision: "PlanDecision",
    evidence_ids: tuple[str, ...] = (),
) -> list[ConclusionClaim]:
    """Convert a PlanDecision to ConclusionClaims.
    
    This is a thin conversion — the Planner already ran; we're just
    reading its structured output.
    """
    claims = []
    if plan_decision is None:
        return claims
    
    try:
        # Claim about the selected action
        if plan_decision.selected_action_id:
            claims.append(make_claim(
                subject_id=plan_decision.objective_id,
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={"selected_action": plan_decision.selected_action_id},
                supporting_evidence_ids=plan_decision.supporting_evidence_ids or evidence_ids,
                derivation_type=DerivationType.PLANNER_ANALYSIS,
                plan_decision_ids=(plan_decision.decision_id,),
            ))
        
        # Claim about the planning rationale
        if plan_decision.rationale_codes:
            rationale_str = ", ".join(plan_decision.rationale_codes)
            claims.append(make_claim(
                subject_id=plan_decision.objective_id,
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={"planning_rationale": rationale_str},
                supporting_evidence_ids=plan_decision.supporting_evidence_ids or evidence_ids,
                derivation_type=DerivationType.PLANNER_ANALYSIS,
                plan_decision_ids=(plan_decision.decision_id,),
            ))
        
        # Claim about considered alternatives
        if plan_decision.considered_action_ids:
            claims.append(make_claim(
                subject_id=plan_decision.objective_id,
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={"considered_actions": list(plan_decision.considered_action_ids)},
                supporting_evidence_ids=plan_decision.supporting_evidence_ids or evidence_ids,
                derivation_type=DerivationType.PLANNER_ANALYSIS,
                plan_decision_ids=(plan_decision.decision_id,),
            ))
        
        # Claim about rejected actions
        if plan_decision.rejected_action_ids:
            claims.append(make_claim(
                subject_id=plan_decision.objective_id,
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={"rejected_actions": list(plan_decision.rejected_action_ids)},
                supporting_evidence_ids=plan_decision.supporting_evidence_ids or evidence_ids,
                derivation_type=DerivationType.PLANNER_ANALYSIS,
                plan_decision_ids=(plan_decision.decision_id,),
            ))
        
    except Exception:
        pass
    
    return claims


# ── Falsification-derived claims ───────────────────────────────────

def _falsification_to_claims(
    falsification_results: list,
    evidence_ids: tuple[str, ...] = (),
) -> list[ConclusionClaim]:
    """Convert FalsificationResult objects to ConclusionClaims.
    
    This is a thin conversion — the falsification machinery already ran;
    we're just reading its structured output.
    """
    claims = []
    if not falsification_results:
        return claims
    
    try:
        for fr in falsification_results:
            if not fr:
                continue
            
            # Claim about the falsification outcome
            claims.append(make_claim(
                subject_id=fr.hypothesis_id if hasattr(fr, 'hypothesis_id') else "unknown",
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={
                    "falsification_outcome": fr.outcome.value if hasattr(fr, 'outcome') else "unknown",
                    "prior_confidence": getattr(fr, 'prior_confidence', None),
                    "posterior_confidence": getattr(fr, 'posterior_confidence', None),
                    "reason_codes": list(getattr(fr, 'reason_codes', ())),
                },
                supporting_evidence_ids=getattr(fr, 'supporting_evidence_ids', ()) or evidence_ids,
                derivation_type=DerivationType.FALSIFICATION_TEST,
                falsification_result_ids=(fr.falsification_id,) if hasattr(fr, 'falsification_id') else (),
            ))
            
            # Claim about the discriminator action that produced the result
            if getattr(fr, 'discriminator_action_id', None):
                claims.append(make_claim(
                    subject_id=fr.discriminator_action_id,
                    predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                    object_value={"falsification_discriminator": True},
                    supporting_evidence_ids=getattr(fr, 'discriminator_observation_ids', ()) or evidence_ids,
                    derivation_type=DerivationType.FALSIFICATION_TEST,
                    falsification_result_ids=(fr.falsification_id,) if hasattr(fr, 'falsification_id') else (),
                ))
            
            # Claim about belief transition if confidences available
            if hasattr(fr, 'prior_confidence') and hasattr(fr, 'posterior_confidence'):
                if fr.prior_confidence is not None and fr.posterior_confidence is not None:
                    delta = fr.posterior_confidence - fr.prior_confidence
                    claims.append(make_claim(
                        subject_id=fr.hypothesis_id if hasattr(fr, 'hypothesis_id') else "unknown",
                        predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                        object_value={
                            "belief_transition": True,
                            "prior_confidence": fr.prior_confidence,
                            "posterior_confidence": fr.posterior_confidence,
                            "delta": delta,
                        },
                        supporting_evidence_ids=getattr(fr, 'supporting_evidence_ids', ()) or evidence_ids,
                        derivation_type=DerivationType.FALSIFICATION_TEST,
                        falsification_result_ids=(fr.falsification_id,) if hasattr(fr, 'falsification_id') else (),
                    ))
    
    except Exception:
        pass
    return claims


# ── Defeater-derived claims (D-5) ───────────────────────────────────

def _defeater_to_claims(
    defeater_results: list,
    evidence_ids: tuple[str, ...] = (),
) -> list[ConclusionClaim]:
    """Convert DefeaterResult objects to ConclusionClaims.

    This is a thin conversion — the defeater machinery already ran;
    we're just reading its structured output.

    The adapter is architecture-blind: it receives existing DefeaterResult
    artifacts, never evaluator truth or hypothesis internals.
    INCONCLUSIVE and NOT_TESTABLE outcomes produce claims documenting the
    evaluation but never become evidence for or against the hypothesis.
    """
    claims = []
    if not defeater_results:
        return claims

    try:
        for dr in defeater_results:
            if not dr:
                continue

            # Claim about the defeater outcome
            outcome_value = dr.outcome.value if hasattr(dr, 'outcome') else "unknown"
            claims.append(make_claim(
                subject_id=dr.hypothesis_id,
                predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                object_value={
                    "defeater_outcome": outcome_value,
                    "defeater_condition": dr.defeater_id,
                    "prior_confidence": dr.prior_hypothesis_confidence,
                    "posterior_confidence": dr.posterior_hypothesis_confidence,
                    "reason_codes": list(getattr(dr, 'reason_codes', ())),
                },
                supporting_evidence_ids=getattr(dr, 'supporting_evidence_ids', ()) or evidence_ids,
                derivation_type=DerivationType.DEFEATER_TEST,
                defeater_result_ids=(dr.result_id,) if hasattr(dr, 'result_id') else (),
            ))

            # Claim about belief transition if confidence changed (TRIGGERED path)
            if (hasattr(dr, 'prior_hypothesis_confidence') and hasattr(dr, 'posterior_hypothesis_confidence')):
                if dr.prior_hypothesis_confidence is not None and dr.posterior_hypothesis_confidence is not None:
                    delta = dr.posterior_hypothesis_confidence - dr.prior_hypothesis_confidence
                    claims.append(make_claim(
                        subject_id=dr.hypothesis_id,
                        predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                        object_value={
                            "belief_transition": True,
                            "prior_confidence": dr.prior_hypothesis_confidence,
                            "posterior_confidence": dr.posterior_hypothesis_confidence,
                            "delta": delta,
                            "outcome": outcome_value,
                        },
                        supporting_evidence_ids=getattr(dr, 'supporting_evidence_ids', ()) or evidence_ids,
                        derivation_type=DerivationType.DEFEATER_TEST,
                        defeater_result_ids=(dr.result_id,) if hasattr(dr, 'result_id') else (),
                    ))

            # Claim about the discriminating action (if present)
            if getattr(dr, 'discriminating_action_id', None):
                claims.append(make_claim(
                    subject_id=dr.discriminating_action_id,
                    predicate=ConclusionPredicate.OBSERVED_PROPERTY,
                    object_value={"defeater_discriminator": True},
                    supporting_evidence_ids=getattr(dr, 'triggering_evidence_ids', ()) or evidence_ids,
                    derivation_type=DerivationType.DEFEATER_TEST,
                    defeater_result_ids=(dr.result_id,) if hasattr(dr, 'result_id') else (),
                ))

    except Exception:
        pass

    return claims


def _compute_decision(
    runner,
    metrics,
    evidence_graph,
) -> DecisionOutcome:
    """Determine the decision outcome from run state.
    
    This reads existing state, does NOT make decisions.
    """
    budget_exhausted = getattr(metrics, 'actions_started', 0) >= 5
    action_count = getattr(metrics, 'actions_started', 0)
    
    decision_text = getattr(metrics, 'decision', '')
    if decision_text:
        return _decision_from_state(decision_text)
    
    if budget_exhausted and action_count > 0:
        return DecisionOutcome.STOP_BUDGET_EXHAUSTED
    
    if action_count == 0:
        return DecisionOutcome.STOP_NO_AUTHORIZED_PATH
    
    return DecisionOutcome.ACT


# ── Architecture-specific adapters ─────────────────────────────

class FullConclusionAdapter:
    """Adapter for FULL_RAPHAEL architecture.
    
    Has access to: HypothesisManager, WorldModel, EvidenceGraph,
    LLM traces, Planner traces, Falsification.
    Uses all available state to produce claims.
    """
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(runner.evidence_graph)
        
        claims = []
        
        # 1. Hypothesis-derived claims
        hypothesis_claims = _hypothesis_to_claims(
            runner.hypothesis_manager, evidence_ids
        )
        claims.extend(hypothesis_claims)
        
        # 2. World Model claims
        wm_claims = _world_model_to_claims(runner.world_model)
        claims.extend(wm_claims)
        
        # 3. Evidence-derived claims (deterministic)
        ev_claims = _evidence_to_claims(runner.evidence_graph, evidence_ids)
        claims.extend(ev_claims)
        
        # 4. LLM MODEL_INFERENCE claims
        llm_claims = _evidence_to_llm_claims(runner.evidence_graph, evidence_ids)
        claims.extend(llm_claims)
        
        # 5. Semantic Inference claims (D-4)
        si_claims = _semantic_inference_to_claims(runner.hypothesis_manager, evidence_ids)
        claims.extend(si_claims)
        
        # 5. Planner-derived claims (D-2)
        plan_decisions = getattr(runner, 'plan_decisions', [])
        for pd in plan_decisions:
            pd_claims = _plan_decision_to_claims(pd)
            claims.extend(pd_claims)
        
        # 6. Falsification-derived claims (D-3)
        falsification_results = getattr(runner, 'falsification_results', [])
        if falsification_results:
            fr_claims = _falsification_to_claims(falsification_results, evidence_ids)
            claims.extend(fr_claims)
        
        # 7. Defeater-derived claims (D-5)
        if config.defeater_enabled:
            defeater_results = getattr(runner, 'defeater_results', [])
            if defeater_results:
                dr_claims = _defeater_to_claims(defeater_results, evidence_ids)
                claims.extend(dr_claims)
        
        return make_runconclusion(
            run_id=runner.run_id,
            scenario_id=runner.scenario.scenario_id,
            decision=_compute_decision(runner, metrics, runner.evidence_graph),
            claims=claims,
            abstention_reason=abstention_reason,
            architecture_id="FULL_RAPHAEL",
        )


class NoHypothesisConclusionAdapter:
    """Adapter for NO_HYPOTHESIS.
    
    Has everything EXCEPT HypothesisManager.
    """
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(runner.evidence_graph)
        
        claims = []
        
        # World Model claims (still available)
        wm_claims = _world_model_to_claims(runner.world_model)
        claims.extend(wm_claims)
        
        # Evidence-derived claims
        ev_claims = _evidence_to_claims(runner.evidence_graph, evidence_ids)
        claims.extend(ev_claims)
        
        # LLM claims (if available)
        llm_claims = _evidence_to_llm_claims(runner.evidence_graph, evidence_ids)
        claims.extend(llm_claims)
        
        return make_runconclusion(
            run_id=runner.run_id,
            scenario_id=runner.scenario.scenario_id,
            decision=_compute_decision(runner, metrics, runner.evidence_graph),
            claims=claims,
            abstention_reason=abstention_reason or "Hypothesis formation disabled",
            architecture_id="NO_HYPOTHESIS",
        )


class NoWorldModelConclusionAdapter:
    """Adapter for NO_WORLD_MODEL.
    
    Has everything EXCEPT WorldModel.
    """
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(runner.evidence_graph)
        
        claims = []
        
        # Hypothesis claims (still available)
        hypothesis_claims = _hypothesis_to_claims(
            runner.hypothesis_manager, evidence_ids
        )
        claims.extend(hypothesis_claims)
        
        # Evidence-derived claims
        ev_claims = _evidence_to_claims(runner.evidence_graph, evidence_ids)
        claims.extend(ev_claims)
        
        # LLM claims (if available)
        llm_claims = _evidence_to_llm_claims(runner.evidence_graph, evidence_ids)
        claims.extend(llm_claims)
        
        return make_runconclusion(
            run_id=runner.run_id,
            scenario_id=runner.scenario.scenario_id,
            decision=_compute_decision(runner, metrics, runner.evidence_graph),
            claims=claims,
            abstention_reason="World Model disabled — no identity resolution",
            architecture_id="NO_WORLD_MODEL",
        )


class NoPlannerConclusionAdapter:
    """Adapter for NO_PLANNER."""
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(runner.evidence_graph)
        
        claims = []
        
        hypothesis_claims = _hypothesis_to_claims(
            runner.hypothesis_manager, evidence_ids
        )
        claims.extend(hypothesis_claims)
        
        wm_claims = _world_model_to_claims(runner.world_model)
        claims.extend(wm_claims)
        
        ev_claims = _evidence_to_claims(runner.evidence_graph, evidence_ids)
        claims.extend(ev_claims)
        
        llm_claims = _evidence_to_llm_claims(runner.evidence_graph, evidence_ids)
        claims.extend(llm_claims)
        
        return make_runconclusion(
            run_id=runner.run_id,
            scenario_id=runner.scenario.scenario_id,
            decision=_compute_decision(runner, metrics, runner.evidence_graph),
            claims=claims,
            architecture_id="NO_PLANNER",
        )


class NoFalsificationConclusionAdapter:
    """Adapter for NO_FALSIFICATION."""
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(runner.evidence_graph)
        
        claims = []
        
        hypothesis_claims = _hypothesis_to_claims(
            runner.hypothesis_manager, evidence_ids
        )
        claims.extend(hypothesis_claims)
        
        wm_claims = _world_model_to_claims(runner.world_model)
        claims.extend(wm_claims)
        
        ev_claims = _evidence_to_claims(runner.evidence_graph, evidence_ids)
        claims.extend(ev_claims)
        
        llm_claims = _evidence_to_llm_claims(runner.evidence_graph, evidence_ids)
        claims.extend(llm_claims)
        
        return make_runconclusion(
            run_id=runner.run_id,
            scenario_id=runner.scenario.scenario_id,
            decision=_compute_decision(runner, metrics, runner.evidence_graph),
            claims=claims,
            architecture_id="NO_FALSIFICATION",
        )


class NoDefeaterConclusionAdapter:
    """Adapter for NO_DEFEATER.

    Has everything EXCEPT defeater-derived claims.
    BaseCandidates(FULL) == BaseCandidates(NO_DEFEATER).
    """
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(runner.evidence_graph)
        
        claims = []
        
        hypothesis_claims = _hypothesis_to_claims(
            runner.hypothesis_manager, evidence_ids
        )
        claims.extend(hypothesis_claims)
        
        wm_claims = _world_model_to_claims(runner.world_model)
        claims.extend(wm_claims)
        
        ev_claims = _evidence_to_claims(runner.evidence_graph, evidence_ids)
        claims.extend(ev_claims)
        
        llm_claims = _evidence_to_llm_claims(runner.evidence_graph, evidence_ids)
        claims.extend(llm_claims)
        
        si_claims = _semantic_inference_to_claims(runner.hypothesis_manager, evidence_ids)
        claims.extend(si_claims)
        
        plan_decisions = getattr(runner, 'plan_decisions', [])
        for pd in plan_decisions:
            pd_claims = _plan_decision_to_claims(pd)
            claims.extend(pd_claims)
        
        falsification_results = getattr(runner, 'falsification_results', [])
        if falsification_results:
            fr_claims = _falsification_to_claims(falsification_results, evidence_ids)
            claims.extend(fr_claims)
        
        # NOTE: No defeater-derived claims — this is NO_DEFEATER
        
        return make_runconclusion(
            run_id=runner.run_id,
            scenario_id=runner.scenario.scenario_id,
            decision=_compute_decision(runner, metrics, runner.evidence_graph),
            claims=claims,
            architecture_id="NO_DEFEATER",
        )


class NoLLMConclusionAdapter:
    """Adapter for NO_LLM.
    
    No LLM MODEL_INFERENCE claims available.
    """
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(runner.evidence_graph)
        
        claims = []
        
        hypothesis_claims = _hypothesis_to_claims(
            runner.hypothesis_manager, evidence_ids
        )
        claims.extend(hypothesis_claims)
        
        wm_claims = _world_model_to_claims(runner.world_model)
        claims.extend(wm_claims)
        
        ev_claims = _evidence_to_claims(runner.evidence_graph, evidence_ids)
        claims.extend(ev_claims)
        
        return make_runconclusion(
            run_id=runner.run_id,
            scenario_id=runner.scenario.scenario_id,
            decision=_compute_decision(runner, metrics, runner.evidence_graph),
            claims=claims,
            abstention_reason="LLM disabled — no semantic interpretation",
            architecture_id="NO_LLM",
        )


class ScriptedConclusionAdapter:
    """Adapter for SCRIPTED_BASELINE.
    
    Only has EvidenceGraph. No hypothesis, world model, LLM, etc.
    Produces only evidence-derived claims.
    
    Must NOT recreate any disabled reasoning capability.
    """
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(
            getattr(runner, 'evidence_graph', None)
        )
        
        claims = []
        
        # Only evidence-derived claims — no hypothesis, no WM, no LLM
        ev_claims = _evidence_to_claims(
            getattr(runner, 'evidence_graph', None),
            evidence_ids,
        )
        claims.extend(ev_claims)
        
        return make_runconclusion(
            run_id=getattr(runner, 'run_id', ''),
            scenario_id=getattr(getattr(runner, 'scenario', None), 'scenario_id', ''),
            decision=DecisionOutcome.STOP_BUDGET_EXHAUSTED,
            claims=claims,
            architecture_id="SCRIPTED_BASELINE",
        )


class LLMOnlyConclusionAdapter:
    """Adapter for LLM_ONLY.
    
    Has only LLM traces + EvidenceGraph. No other cognitive components.
    """
    
    def build(
        self,
        runner: ArenaRunner,
        metrics,
        config: AblationConfig,
        decision_text: str = "",
        abstention_reason: Optional[str] = None,
    ) -> RunConclusion:
        evidence_ids = _collect_evidence_ids(
            getattr(runner, 'evidence_graph', None)
        )
        
        claims = []
        
        # Evidence-derived claims
        ev_claims = _evidence_to_claims(
            getattr(runner, 'evidence_graph', None),
            evidence_ids,
        )
        claims.extend(ev_claims)
        
        # LLM MODEL_INFERENCE claims
        llm_claims = _evidence_to_llm_claims(
            getattr(runner, 'evidence_graph', None),
            evidence_ids,
        )
        claims.extend(llm_claims)
        
        return make_runconclusion(
            run_id=getattr(runner, 'run_id', ''),
            scenario_id=getattr(getattr(runner, 'scenario', None), 'scenario_id', ''),
            decision=DecisionOutcome.STOP_BUDGET_EXHAUSTED,
            claims=claims,
            architecture_id="LLM_ONLY",
        )


# ── Adapter Factory ────────────────────────────────────────────

def get_adapter(config_id: str):
    """Return the appropriate adapter for the given config."""
    mapping = {
        "FULL_RAPHAEL": FullConclusionAdapter,
        "NO_HYPOTHESIS": NoHypothesisConclusionAdapter,
        "NO_WORLD_MODEL": NoWorldModelConclusionAdapter,
        "NO_PLANNER": NoPlannerConclusionAdapter,
        "NO_FALSIFICATION": NoFalsificationConclusionAdapter,
        "NO_DEFEATER": NoDefeaterConclusionAdapter,
        "NO_LLM": NoLLMConclusionAdapter,
        "LLM_ONLY": LLMOnlyConclusionAdapter,
        "SCRIPTED_BASELINE": ScriptedConclusionAdapter,
    }
    cls = mapping.get(config_id, FullConclusionAdapter)
    return cls()
