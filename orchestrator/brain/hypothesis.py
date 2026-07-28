"""hypothesis.py — Hypothesis Manager with structured confidence and history.

Core philosophy:

A hypothesis is a mutable belief. Its confidence is NOT a single number
chosen by an LLM. It derives from structured factors:

    confidence = f(
        supporting_evidence,      # EvidenceGraph edges of type SUPPORTS
        contradicting_evidence,   # EvidenceGraph edges of type CONTRADICTS
        source_reliability,       # Mean trust_level of supporting sources
        independence,             # How many independent sources agree
        freshness,                # Time-weighted decay of evidence
        assumptions_required,     # Number/strength of unproven premises
        falsification_attempts,   # Number of failed attempts to falsify
    )

CRITICAL: The complete confidence history is preserved:
    0.30 → 0.57 → 0.81 → 0.42 → FALSIFIED
    with the reason for EVERY transition recorded.

This enables learning from being wrong — the most valuable signal.

Schema version: 1
"""

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional, Callable

from orchestrator.brain.evidence import EvidenceGraph, Evidence
from orchestrator.brain.trust import TrustLevel
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arena.semantic_inference import SemanticInferenceSuccess
    from arena.defeater import DefeaterResult


class HypothesisStatus(str, Enum):
    """Lifecycle states of a hypothesis."""
    PROPOSED = "proposed"           # Newly created, not yet evaluated
    ACTIVE = "active"               # Being actively maintained
    FALSIFIED = "falsified"         # Explicitly disproven
    ABANDONED = "abandoned"         # No longer maintained (stale, superseded)
    CONFIRMED = "confirmed"         # High confidence, treated as fact


class ConfidenceFactor(str, Enum):
    """Structured factors that contribute to confidence."""
    SUPPORTING_EVIDENCE = "supporting_evidence"
    CONTRADICTING_EVIDENCE = "contradicting_evidence"
    SOURCE_RELIABILITY = "source_reliability"
    INDEPENDENCE = "independence"
    FRESHNESS = "freshness"
    ASSUMPTIONS_REQUIRED = "assumptions_required"
    FALSIFICATION_ATTEMPTS = "falsification_attempts"


@dataclass
class ConfidenceSnapshot:
    """
    A single point-in-time confidence assessment with all contributing factors.
    
    This is the atomic unit of belief change — every confidence update
    creates a new snapshot with full factor breakdown and rationale.
    """
    timestamp: float = field(default_factory=time.time)
    overall_confidence: float = 0.0          # 0.0 to 1.0
    factors: dict[str, float] = field(default_factory=dict)  # ConfidenceFactor -> 0.0-1.0
    
    # Rationale
    rationale: str = ""                       # Human-readable explanation
    changed_by: str = ""                      # "evidence:eid", "reasoning:step", "falsification"
    change_reason: str = ""                   # Why this transition happened
    
    # Supporting detail
    supporting_count: int = 0
    contradicting_count: int = 0
    independent_sources: int = 0
    assumptions_count: int = 0
    falsification_attempts: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class Hypothesis:
    """
    A mutable belief with complete audit trail.
    
    Fields:
        hypothesis_id: Unique identifier
        statement: What is believed (e.g., "Role DevRole can access prod-bucket")
        status: Current lifecycle state
        entity_ids: WorldModel entities this hypothesis concerns
        evidence_ids: EvidenceGraph evidence IDs directly referenced
        
        # Confidence tracking
        current_confidence: 0.0-1.0 (derived from factors)
        factor_values: Current factor breakdown
        confidence_history: Complete list of ConfidenceSnapshot
        
        # Meta
        proposed_by: What proposed this (action_receipt_id, "reasoning", "llm")
        proposed_at: Timestamp
        falsified_by: What falsified it (if applicable)
        falsified_at: Timestamp
    """
    schema_version: int = 1
    hypothesis_id: str = field(default_factory=lambda: f"hyp_{uuid.uuid4().hex[:12]}")
    statement: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    
    # What this hypothesis is about
    entity_ids: list[str] = field(default_factory=list)  # WorldModel entity_ids
    evidence_ids: list[str] = field(default_factory=list)  # EvidenceGraph evidence_ids
    semantic_inference_ids: list[str] = field(default_factory=list)  # SemanticInference IDs (D-4)
    defeater_result_ids: list[str] = field(default_factory=list)  # DefeaterResult IDs (D-5)
    
    # Confidence tracking
    current_confidence: float = 0.0
    factor_values: dict[str, float] = field(default_factory=dict)
    confidence_history: list[ConfidenceSnapshot] = field(default_factory=list)
    
    # Meta
    proposed_by: str = ""
    proposed_at: float = field(default_factory=time.time)
    falsified_by: str = ""
    falsified_at: float = 0.0
    confirmed_at: float = 0.0
    
    # Assumptions this hypothesis depends on
    assumptions: list[str] = field(default_factory=list)  # Description of assumptions

    def add_snapshot(self, snapshot: ConfidenceSnapshot) -> None:
        """Add a confidence snapshot and update current state."""
        self.confidence_history.append(snapshot)
        self.current_confidence = snapshot.overall_confidence
        self.factor_values = snapshot.factors.copy()
        
        # Update status based on confidence
        if snapshot.overall_confidence >= 0.9 and self.status != HypothesisStatus.CONFIRMED:
            self.status = HypothesisStatus.CONFIRMED
        elif snapshot.overall_confidence <= 0.1 and self.status not in (HypothesisStatus.FALSIFIED, HypothesisStatus.ABANDONED):
            self.status = HypothesisStatus.FALSIFIED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["confidence_history"] = [s.to_dict() for s in self.confidence_history]
        return d


# ── Confidence Computation ─────────────────────────────────────────

# Trust level weights for source reliability
TRUST_WEIGHTS = {
    TrustLevel.SYSTEM_POLICY: 1.0,
    TrustLevel.OPERATOR_INSTRUCTION: 0.95,
    TrustLevel.ENGAGEMENT_CONFIG: 0.9,
    TrustLevel.TOOL_OBSERVATION: 0.8,
    TrustLevel.MODEL_INFERENCE: 0.4,
    TrustLevel.TARGET_CONTROLLED: 0.2,
}


def compute_source_reliability(evidence_graph: EvidenceGraph, evidence_ids: list[str]) -> float:
    """Compute mean source reliability from evidence trust levels."""
    if not evidence_ids:
        return 0.5
    
    total = 0.0
    count = 0
    for eid in evidence_ids:
        ev = evidence_graph.get_evidence(eid)
        if ev:
            total += TRUST_WEIGHTS.get(ev.trust_level, 0.5)
            count += 1
    return total / count if count > 0 else 0.5


def compute_independence(evidence_graph: EvidenceGraph, evidence_ids: list[str]) -> float:
    """
    Estimate independence of evidence sources.
    1.0 = fully independent (different tools, different collection times)
    0.0 = completely dependent (same tool, same run)
    """
    if len(evidence_ids) <= 1:
        return 1.0
    
    # Group by source_detail and time window
    sources = {}
    for eid in evidence_ids:
        ev = evidence_graph.get_evidence(eid)
        if ev:
            source = getattr(ev, 'source_detail', '') or getattr(ev, 'evidence_type', '') or 'unknown'
            key = (source, int(ev.collected_at // 3600))  # Same source, same hour
            sources.setdefault(key, 0)
            sources[key] += 1
    
    # More unique sources = more independent
    unique_sources = len(sources)
    max_possible = len(evidence_ids)
    return unique_sources / max_possible if max_possible > 0 else 0.5


def compute_freshness(evidence_graph: EvidenceGraph, evidence_ids: list[str], half_life_hours: float = 168.0) -> float:
    """
    Time-weighted freshness of evidence.
    Exponential decay with configurable half-life (default 1 week).
    """
    if not evidence_ids:
        return 0.0
    
    now = time.time()
    total_weight = 0.0
    count = 0
    
    for eid in evidence_ids:
        ev = evidence_graph.get_evidence(eid)
        if ev:
            age_hours = (now - ev.collected_at) / 3600.0
            # Exponential decay: weight = 0.5^(age / half_life)
            weight = 0.5 ** (age_hours / half_life_hours)
            total_weight += weight
            count += 1
    
    return total_weight / count if count > 0 else 0.0


def compute_supporting_evidence_factor(evidence_graph: EvidenceGraph, hypothesis: Hypothesis) -> float:
    """Factor for supporting evidence: more supporting evidence = higher confidence."""
    if not hypothesis.evidence_ids:
        return 0.0
    
    supporting = 0
    for eid in hypothesis.evidence_ids:
        # Check if evidence SUPPORTS this hypothesis
        # For simplicity, we count all attached evidence as supporting
        # In practice, would check EvidenceGraph relationships
        supporting += 1
    
    # Logarithmic scaling: diminishing returns
    return min(1.0, 0.3 + 0.7 * (supporting / max(1, supporting + 1)))


def compute_contradicting_evidence_factor(evidence_graph: EvidenceGraph, hypothesis: Hypothesis) -> float:
    """Factor for contradicting evidence: more contradictions = lower confidence."""
    # Check EvidenceGraph for CONTRADICTS relationships targeting this hypothesis's evidence
    # For now, return 1.0 (no contradictions found)
    # In practice, would query: for each e in hypothesis.evidence_ids, count CONTRADICTS
    return 1.0


def compute_assumptions_factor(hypothesis: Hypothesis) -> float:
    """Factor for assumptions: more unproven assumptions = lower confidence."""
    if not hypothesis.assumptions:
        return 1.0
    # Each assumption reduces confidence
    return max(0.1, 1.0 - 0.15 * len(hypothesis.assumptions))


def compute_falsification_factor(hypothesis: Hypothesis) -> float:
    """Factor for falsification attempts: more failed attempts to falsify = higher confidence."""
    # Count snapshots where status was FALSIFIED but then recovered (shouldn't happen)
    # Or count explicit falsification attempts
    attempts = hypothesis.factor_values.get(ConfidenceFactor.FALSIFICATION_ATTEMPTS.value, 0)
    # More attempts = more confidence (survived scrutiny)
    if attempts == 0:
        return 0.5
    return min(1.0, 0.5 + 0.1 * attempts)


def compute_confidence(evidence_graph: EvidenceGraph, hypothesis: Hypothesis) -> ConfidenceSnapshot:
    """
    Compute structured confidence from all factors.
    
    Returns a ConfidenceSnapshot with factor breakdown and overall confidence.
    """
    # Supporting evidence
    support = compute_supporting_evidence_factor(evidence_graph, hypothesis)
    
    # Contradicting evidence
    contradiction = compute_contradicting_evidence_factor(evidence_graph, hypothesis)
    
    # Source reliability
    source_rel = compute_source_reliability(evidence_graph, hypothesis.evidence_ids)
    
    # Independence
    independence = compute_independence(evidence_graph, hypothesis.evidence_ids)
    
    # Freshness
    freshness = compute_freshness(evidence_graph, hypothesis.evidence_ids)
    
    # Assumptions
    assumptions_factor = compute_assumptions_factor(hypothesis)
    
    # Falsification attempts
    falsification_factor = compute_falsification_factor(hypothesis)
    
    # Weighted combination (weights sum to 1.0)
    weights = {
        ConfidenceFactor.SUPPORTING_EVIDENCE.value: 0.25,
        ConfidenceFactor.CONTRADICTING_EVIDENCE.value: 0.20,
        ConfidenceFactor.SOURCE_RELIABILITY.value: 0.15,
        ConfidenceFactor.INDEPENDENCE.value: 0.10,
        ConfidenceFactor.FRESHNESS.value: 0.10,
        ConfidenceFactor.ASSUMPTIONS_REQUIRED.value: 0.10,
        ConfidenceFactor.FALSIFICATION_ATTEMPTS.value: 0.10,
    }
    
    factors = {
        ConfidenceFactor.SUPPORTING_EVIDENCE.value: support,
        ConfidenceFactor.CONTRADICTING_EVIDENCE.value: contradiction,
        ConfidenceFactor.SOURCE_RELIABILITY.value: source_rel,
        ConfidenceFactor.INDEPENDENCE.value: independence,
        ConfidenceFactor.FRESHNESS.value: freshness,
        ConfidenceFactor.ASSUMPTIONS_REQUIRED.value: assumptions_factor,
        ConfidenceFactor.FALSIFICATION_ATTEMPTS.value: falsification_factor,
    }
    
    overall = sum(factors[k] * weights[k] for k in weights)
    
    # Count evidence
    supporting_count = len(hypothesis.evidence_ids)
    contradicting_count = 0  # Would query EvidenceGraph for CONTRADICTS
    independent_sources = 0  # Would compute from evidence sources
    
    return ConfidenceSnapshot(
        overall_confidence=max(0.0, min(1.0, overall)),
        factors=factors,
        rationale=f"support={support:.2f} contra={contradiction:.2f} reliability={source_rel:.2f} "
                  f"indep={independence:.2f} fresh={freshness:.2f} "
                  f"assumptions={assumptions_factor:.2f} falsification={falsification_factor:.2f}",
        changed_by="compute_confidence",
        change_reason="Automatic confidence recomputation",
        supporting_count=supporting_count,
        contradicting_count=contradicting_count,
        independent_sources=independent_sources,
        assumptions_count=len(hypothesis.assumptions),
        falsification_attempts=0,  # Would track separately
    )


# ── Hypothesis Manager ────────────────────────────────────────────

class HypothesisManager:
    """
    Manages the lifecycle of hypotheses.
    
    Integrates with EvidenceGraph and WorldModel for evidence queries.
    """
    
    def __init__(self, evidence_graph: EvidenceGraph, world_model: 'WorldModel'):
        self.evidence_graph = evidence_graph
        self.world_model = world_model
        self.hypotheses: dict[str, Hypothesis] = {}
        
        # Index by entity
        self._by_entity: dict[str, set[str]] = {}  # entity_id -> {hypothesis_id}

    def propose(
        self,
        statement: str,
        entity_ids: list[str],
        evidence_ids: list[str],
        proposed_by: str,
        assumptions: list[str] = None,
        initial_factors: dict = None,
    ) -> Hypothesis:
        """Create a new hypothesis."""
        hyp = Hypothesis(
            statement=statement,
            status=HypothesisStatus.PROPOSED,
            entity_ids=entity_ids,
            evidence_ids=evidence_ids or [],
            proposed_by=proposed_by,
            assumptions=assumptions or [],
        )
        
        # Initialize factor values if provided
        if initial_factors:
            hyp.factor_values = initial_factors
        
        # Initial confidence computation
        snapshot = compute_confidence(self.evidence_graph, hyp)
        hyp.add_snapshot(snapshot)
        hyp.status = HypothesisStatus.ACTIVE
        
        self.hypotheses[hyp.hypothesis_id] = hyp
        
        # Index
        for eid in entity_ids:
            if eid not in self._by_entity:
                self._by_entity[eid] = set()
            self._by_entity[eid].add(hyp.hypothesis_id)
        
        return hyp

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        return self.hypotheses.get(hypothesis_id)

    def get_by_entity(self, entity_id: str) -> list[Hypothesis]:
        ids = self._by_entity.get(entity_id, set())
        return [self.hypotheses[hid] for hid in ids if hid in self.hypotheses]

    def update_confidence(
        self,
        hypothesis_id: str,
        trigger: str,
        reason: str,
        evidence_graph: EvidenceGraph = None,
    ) -> ConfidenceSnapshot | None:
        """
        Recompute confidence for a hypothesis and record the transition.
        
        Returns the new snapshot.
        """
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return None
        
        eg = evidence_graph or self.evidence_graph
        
        # Update evidence_ids from EvidenceGraph if linked
        # (In practice, would check for new SUPPORTS/CONTRADICTS edges)
        
        # Recompute
        snapshot = compute_confidence(eg, hyp)
        snapshot.changed_by = trigger
        snapshot.change_reason = reason
        
        hyp.add_snapshot(snapshot)
        return snapshot

    def add_evidence(self, hypothesis_id: str, evidence_id: str) -> None:
        """Link new supporting evidence to a hypothesis."""
        hyp = self.hypotheses.get(hypothesis_id)
        if hyp and evidence_id not in hyp.evidence_ids:
            hyp.evidence_ids.append(evidence_id)

    def add_contradiction(self, hypothesis_id: str, contradicting_evidence_id: str) -> None:
        """Record that evidence contradicts this hypothesis."""
        # Would add CONTRADICTS edge in EvidenceGraph
        # For now, just trigger re-evaluation
        hyp = self.hypotheses.get(hypothesis_id)
        if hyp:
            self.update_confidence(hypothesis_id, f"evidence:{contradicting_evidence_id}", 
                                   f"New contradicting evidence: {contradicting_evidence_id}")

    def consume_semantic_inference(
        self,
        si: "SemanticInferenceSuccess",
        entity_ids: list[str],
        evidence_ids: list[str],
    ) -> Hypothesis:
        """Consume a SemanticInferenceSuccess and create/update a hypothesis.

        Creates a new hypothesis from the semantic inference, linking it
        to the source evidence and the semantic inference itself.

        Args:
            si: The SemanticInferenceSuccess to consume.
            entity_ids: WorldModel entity IDs related to the inference.
            evidence_ids: EvidenceGraph evidence IDs that were input to the LLM.

        Returns:
            The created or updated Hypothesis, with the SI ID stored in
            semantic_inference_ids.
        """
        # Create a new hypothesis from the semantic inference
        statement = f"Semantic inference: {si.claim}"
        hyp = Hypothesis(
            statement=statement,
            status=HypothesisStatus.PROPOSED,
            entity_ids=entity_ids,
            evidence_ids=evidence_ids or [],
            semantic_inference_ids=[si.inference_id],
            proposed_by=f"semantic_inference:{si.inference_id}",
            assumptions=[f"Based on LLM semantic interpretation (category: {si.category.value}, confidence: {si.confidence:.2f})"],
        )

        # Initialize factor values - MODEL_INFERENCE has lower trust weight
        hyp.factor_values = {
            "source_reliability": 0.4,  # TRUST_WEIGHTS[TrustLevel.MODEL_INFERENCE]
            "supporting_evidence": 0.5,
            "independence": 0.5,
        }

        # Initial confidence computation
        snapshot = compute_confidence(self.evidence_graph, hyp)
        hyp.add_snapshot(snapshot)
        hyp.status = HypothesisStatus.ACTIVE

        self.hypotheses[hyp.hypothesis_id] = hyp

        # Index by entity
        for eid in entity_ids:
            if eid not in self._by_entity:
                self._by_entity[eid] = set()
            self._by_entity[eid].add(hyp.hypothesis_id)

        return hyp

    def apply_defeater_result(
        self,
        hypothesis_id: str,
        defeater_result: "DefeaterResult",
    ) -> Optional["BeliefTransition"]:
        """Apply a DefeaterResult to a hypothesis using the frozen V2 transition policy.

        This is the dedicated semantic boundary for defeater belief updates.
        It does NOT use update_confidence() — it applies the frozen transition
        table directly, then records the defeater_result_id for traceability.

        Returns a BeliefTransition artifact proving the causal link from
        DefeaterResult to hypothesis change.

        Args:
            hypothesis_id: The hypothesis to update.
            defeater_result: The DefeaterResult with outcome and evidence.

        Returns:
            BeliefTransition if the hypothesis was found and outcome
            was TRIGGERED or NOT_TRIGGERED, None otherwise.
        """
        from arena.defeater import apply_belief_transition, DefeaterOutcome, BeliefTransition

        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return None

        prior_confidence = hyp.current_confidence
        prior_state = hyp.status.value.upper() if hasattr(hyp.status, 'value') else str(hyp.status)

        # INCONCLUSIVE and NOT_TESTABLE do not produce BeliefTransition
        if defeater_result.outcome in (DefeaterOutcome.INCONCLUSIVE, DefeaterOutcome.NOT_TESTABLE):
            return None

        # Apply frozen transition policy
        post_confidence, post_state_str = apply_belief_transition(
            prior_state=prior_state,
            prior_confidence=prior_confidence,
            outcome=defeater_result.outcome,
        )

        # Map state string to HypothesisStatus
        from orchestrator.brain.hypothesis import HypothesisStatus
        state_map = {
            "POSTULATED": HypothesisStatus.ACTIVE,
            "DOUBTFUL": HypothesisStatus.ACTIVE,
            "ABANDONED": HypothesisStatus.ABANDONED,
            "ACTIVE": HypothesisStatus.ACTIVE,
            "PROPOSED": HypothesisStatus.PROPOSED,
            "CONFIRMED": HypothesisStatus.CONFIRMED,
        }
        new_status = state_map.get(post_state_str.upper(), hyp.status)

        # Record the defeater_result_id
        if defeater_result.result_id not in hyp.defeater_result_ids:
            hyp.defeater_result_ids.append(defeater_result.result_id)

        # Create BeliefTransition artifact
        transition = BeliefTransition(
            hypothesis_id=hypothesis_id,
            defeater_result_id=defeater_result.result_id,
            outcome=defeater_result.outcome,
            prior_confidence=prior_confidence,
            posterior_confidence=post_confidence,
            prior_state=prior_state,
            posterior_state=post_state_str,
        )

        # Also create ConfidenceSnapshot for history
        snapshot = ConfidenceSnapshot(
            overall_confidence=post_confidence,
            factors=hyp.factor_values.copy(),
            rationale=(
                f"Defeater {defeater_result.outcome.value}: "
                f"{prior_confidence:.3f} → {post_confidence:.3f} "
                f"({prior_state} → {post_state_str})"
            ),
            changed_by=f"defeater:{defeater_result.result_id}",
            change_reason=(
                f"Defeater {defeater_result.outcome.value}: "
                f"{defeater_result.reason_codes}"
            ),
        )
        hyp.add_snapshot(snapshot)
        hyp.status = new_status

        return transition

    def falsify(self, hypothesis_id: str, falsified_by: str, reason: str) -> bool:
        """Explicitly falsify a hypothesis."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return False
        
        hyp.status = HypothesisStatus.FALSIFIED
        hyp.falsified_by = falsified_by
        hyp.falsified_at = time.time()
        
        # Record falsification in history
        snapshot = ConfidenceSnapshot(
            overall_confidence=0.0,
            factors={k: 0.0 for k in ConfidenceFactor.__members__.values()},
            rationale=f"FALSIFIED: {reason}",
            changed_by=falsified_by,
            change_reason=f"Explicit falsification: {reason}",
        )
        hyp.add_snapshot(snapshot)
        return True

    def abandon(self, hypothesis_id: str, reason: str = "") -> bool:
        """Mark hypothesis as abandoned (stale/superseded)."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return False
        
        hyp.status = HypothesisStatus.ABANDONED
        snapshot = ConfidenceSnapshot(
            overall_confidence=hyp.current_confidence,
            factors=hyp.factor_values.copy(),
            rationale=f"ABANDONED: {reason}",
            changed_by="manager",
            change_reason=f"Abandoned: {reason}",
        )
        hyp.add_snapshot(snapshot)
        return True

    def get_confidence_history(self, hypothesis_id: str) -> list[ConfidenceSnapshot]:
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return []
        return hyp.confidence_history

    def get_active_hypotheses(self, min_confidence: float = 0.0) -> list[Hypothesis]:
        return [h for h in self.hypotheses.values() 
                if h.status in (HypothesisStatus.ACTIVE, HypothesisStatus.CONFIRMED) 
                and h.current_confidence >= min_confidence]

    def stats(self) -> dict:
        return {
            "total": len(self.hypotheses),
            "active": len([h for h in self.hypotheses.values() if h.status == HypothesisStatus.ACTIVE]),
            "confirmed": len([h for h in self.hypotheses.values() if h.status == HypothesisStatus.CONFIRMED]),
            "falsified": len([h for h in self.hypotheses.values() if h.status == HypothesisStatus.FALSIFIED]),
            "abandoned": len([h for h in self.hypotheses.values() if h.status == HypothesisStatus.ABANDONED]),
        }


# Module-level singleton
_hypothesis_manager: HypothesisManager | None = None


def get_hypothesis_manager() -> HypothesisManager:
    """Get or create the global hypothesis manager."""
    global _hypothesis_manager
    if _hypothesis_manager is None:
        from orchestrator.brain.evidence import get_evidence_graph
        _hypothesis_manager = HypothesisManager(get_evidence_graph(), None)
    return _hypothesis_manager


def set_hypothesis_manager(manager: HypothesisManager) -> None:
    """Set the global hypothesis manager."""
    global _hypothesis_manager
    _hypothesis_manager = manager