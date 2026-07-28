"""conclusion.py — Stage 2.5D-0: Typed RunConclusion contract.

Every architecture (FULL, NO_HYPOTHESIS, NO_WORLD_MODEL, NO_PLANNER,
NO_FALSIFICATION, NO_LLM, LLM_ONLY, SCRIPTED) produces a RunConclusion
containing structured ConclusionClaims. The evaluator consumes ONLY this
contract — it does not inspect HypothesisManager, WorldModel, EvidenceGraph,
Planner, LLM, or AblationConfig to determine correctness.

Design invariants:
  1. Claims use structured predicates, not prose.
  2. Claim truth is separate from claim provenance.
  3. Every non-abstention factual claim must cite supporting evidence.
  4. Confidence is optional (None if system cannot calibrate).
  5. Adaptors are thin serialization boundaries; they do NOT recreate
     disabled reasoning capabilities.
"""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ── Falsification Result ──────────────────────────────────────────────

class FalsificationOutcome(str, Enum):
    """Outcome of a falsification attempt."""
    FALSIFIED = "falsified"           # Hypothesis was disproven
    SURVIVED = "survived"             # Hypothesis withstood the test
    INCONCLUSIVE = "inconclusive"     # Discriminator executed but result unclear
    NOT_TESTABLE = "not_testable"     # No discriminator could be executed


@dataclass(frozen=True)
class FalsificationResult:
    """
    Structured output of a falsification attempt — the causal intermediate between
    contradiction detection and belief revision.
    
    Contradiction detection ≠ falsification. A contradiction creates a reason to
    investigate. Falsification requires a discriminating action that produces
    evidence bearing on the competing claims.
    
    Causal chain:
      ContradictionManager detects contradiction
        → Proposes discriminator action
        → CandidateGenerator adds discriminator to CandidateSet
        → Planner scores/selects discriminator
        → PlanDecision references falsification_id
        → Broker authorizes, ExecutionEngine executes
        → Observation produced
        → ContradictionManager produces FalsificationResult
        → Hypothesis updated/rejected
        → RunConclusion claims carry falsification_result_ids
    
    Every falsification gets a unique falsification_id for causal traceability.
    """
    falsification_id: str = field(default_factory=lambda: f"FR_{uuid.uuid4().hex[:12]}")
    hypothesis_id: str = ""
    
    # The contradiction that triggered this falsification
    contradiction_id: str = ""
    
    # Evidence
    contradictory_evidence_ids: tuple[str, ...] = ()
    supporting_evidence_ids: tuple[str, ...] = ()
    
    # Discriminator action
    discriminator_action_id: str | None = None
    discriminator_observation_ids: tuple[str, ...] = ()
    
    # Confidence before/after
    prior_confidence: Optional[float] = None
    posterior_confidence: Optional[float] = None
    
    # Outcome and rationale
    outcome: FalsificationOutcome = FalsificationOutcome.INCONCLUSIVE
    reason_codes: tuple[str, ...] = ()
    
    # Metadata
    generated_at: float = field(default_factory=time.time)
    planner_decision_id: str = ""  # trace back to PlanDecision
    
    def to_dict(self) -> dict:
        return {
            "falsification_id": self.falsification_id,
            "hypothesis_id": self.hypothesis_id,
            "contradiction_id": self.contradiction_id,
            "contradictory_evidence_ids": list(self.contradictory_evidence_ids),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "discriminator_action_id": self.discriminator_action_id,
            "discriminator_observation_ids": list(self.discriminator_observation_ids),
            "prior_confidence": self.prior_confidence,
            "posterior_confidence": self.posterior_confidence,
            "outcome": self.outcome.value,
            "reason_codes": list(self.reason_codes),
            "generated_at": self.generated_at,
            "planner_decision_id": self.planner_decision_id,
        }


# ── Plan Decision ────────────────────────────────────────────────────

@dataclass(frozen=True)
class PlanDecision:
    """
    Structured output of the Planner — the causal intermediate between
    candidate generation and action execution.
    
    Candidate generation happens BEFORE planning. The Planner receives
    a CandidateSet and produces a PlanDecision. ExecutionEngine then
    references the PlanDecision for traceability.
    
    Causal chain:
      CandidateGenerator -> CandidateSet
        -> Planner -> PlanDecision (PRODUCED)
        -> ExecutionEngine references plan_decision_id (REFERENCED)
        -> ActionReceipt selected_via_plan_decision_id (DECISION_RELEVANT)
    
    Every decision gets a unique decision_id for causal traceability.
    Candidates record: selected_via_plan_decision_id = "PD17"
    """
    decision_id: str = field(default_factory=lambda: f"PD_{uuid.uuid4().hex[:12]}")
    objective_id: str = ""
    
    # What was considered
    considered_action_ids: tuple[str, ...] = ()
    rejected_action_ids: tuple[str, ...] = ()
    selected_action_id: str = ""
    
    # Why this was chosen
    rationale_codes: tuple[str, ...] = ()  # e.g., "lowest_cost", "highest_utility", "novelty"
    estimated_cost: float = 0.0
    estimated_risk: float = 0.0
    estimated_utility: float = 0.0
    
    # Supporting evidence
    supporting_evidence_ids: tuple[str, ...] = ()
    supporting_world_query_ids: tuple[str, ...] = ()
    supporting_hypothesis_ids: tuple[str, ...] = ()
    
    # D-5: Defeater transition consumption tracking
    consumed_transition_ids: tuple[str, ...] = ()  # BeliefTransition IDs consumed by this decision
    
    # Metadata
    generated_at: float = field(default_factory=time.time)
    planner_invocation_id: str = ""  # trace back to planner trace
    
    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "objective_id": self.objective_id,
            "considered_count": len(self.considered_action_ids),
            "rejected_count": len(self.rejected_action_ids),
            "selected_action_id": self.selected_action_id,
            "rationale_codes": list(self.rationale_codes),
            "estimated_cost": self.estimated_cost,
            "estimated_risk": self.estimated_risk,
            "estimated_utility": self.estimated_utility,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "supporting_world_query_ids": list(self.supporting_world_query_ids),
            "supporting_hypothesis_ids": list(self.supporting_hypothesis_ids),
            "generated_at": self.generated_at,
            "planner_invocation_id": self.planner_invocation_id,
            "consumed_transition_ids": list(self.consumed_transition_ids),
        }


# ── World Query Result ─────────────────────────────────────────────

@dataclass(frozen=True)
class WorldQueryResult:
    """
    Read-only projection of WorldModel state at a point in time.

    This is the causal intermediate between WorldModel mutation and
    candidate generation. It is NOT an inference mechanism — it simply
    exposes what WorldModel already knows at query time.

    Every query gets a unique query_id for causal traceability.
    Candidates that consume this result record:
        derived_from_world_query_ids = ("WQ17",)

    Causal chain: INVOKED (query call) -> PRODUCED (WQR object)
                  -> REFERENCED (candidate records query_id)
                  -> DECISION_RELEVANT (affects downstream choice)
    """
    query_id: str = field(default_factory=lambda: f"WQ_{uuid.uuid4().hex[:12]}")
    entities: tuple = ()          # tuple of Entity objects (read-only view)
    relationships: tuple = ()     # tuple of Relationship objects
    resolutions: tuple = ()       # tuple of EntityResolution objects
    supporting_evidence_ids: tuple[str, ...] = ()
    confidence: Optional[float] = None
    generated_at: float = field(default_factory=time.time)
    query_params: tuple[tuple[str, str], ...] = ()  # (param_name, value) for reproducibility

    def to_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "entity_count": len(self.entities),
            "relationship_count": len(self.relationships),
            "resolution_count": len(self.resolutions),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "confidence": self.confidence,
            "generated_at": self.generated_at,
            "query_params": dict(self.query_params),
        }


# ── Predicate Registry ──────────────────────────────────────────────

class ConclusionPredicate(Enum):
    """Typed predicates for structured claims.

    Only predicates actually required by the current DEV scenarios
    are defined. Expand only when new scenarios demand it.
    """
    PORT_STATE = "port_state"
    SERVICE_TYPE = "service_type"
    SERVICE_ROLE = "service_role"
    HAS_SERVICE = "has_service"
    SAME_ENTITY_AS = "same_entity_as"
    DIFFERENT_ENTITY_FROM = "different_entity_from"
    RESOURCE_ACCESSIBLE = "resource_accessible"
    RESOURCE_BLOCKED = "resource_blocked"
    HOST_IDENTITY = "host_identity"
    OBSERVED_PROPERTY = "observed_property"


# ── Derivation Types ───────────────────────────────────────────────

class DerivationType(Enum):
    """How a claim was derived."""
    HYPOTHESIS_INFERENCE = "hypothesis_inference"
    WORLD_MODEL_RELATIONSHIP = "world_model_relationship"
    LLM_INTERPRETATION = "llm_interpretation"
    DETERMINISTIC_RULE = "deterministic_rule"
    DIRECT_OBSERVATION = "direct_observation"
    SCRIPTED_BASELINE = "scripted_baseline"
    PLANNER_ANALYSIS = "planner_analysis"
    FALSIFICATION_TEST = "falsification_test"
    DEFEATER_TEST = "defeater_test"  # D-5: Defeater-derived claims


# ── Decision Outcomes ──────────────────────────────────────────────

class DecisionOutcome(str, Enum):
    """Outcome of the run's decision process."""
    ACT = "ACT"
    STOP_OBJECTIVE_REACHED = "STOP_OBJECTIVE_REACHED"
    STOP_INSUFFICIENT_EVIDENCE = "STOP_INSUFFICIENT_EVIDENCE"
    STOP_NO_AUTHORIZED_PATH = "STOP_NO_AUTHORIZED_PATH"
    STOP_BUDGET_EXHAUSTED = "STOP_BUDGET_EXHAUSTED"
    STOP_UNRESOLVED_CONTRADICTION = "STOP_UNRESOLVED_CONTRADICTION"


# ── Provenance ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class ConclusionProvenance:
    """Epistemic history of a claim — separate from claim truth.

    This allows analysis like:
      FULL:   claim <- world relationship <- E1,E2
      NO_WORLD: claim <- direct evidence <- E1,E2
    Same outcome, different causal path.
    """
    producer: str = ""  # e.g., "hypothesis_manager", "world_model", "llm", "deterministic"
    derivation_type: DerivationType = DerivationType.DETERMINISTIC_RULE

    # Evidence and internal object IDs that support this claim
    evidence_ids: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()
    world_relation_ids: tuple[str, ...] = ()
    model_inference_ids: tuple[str, ...] = ()
    world_query_ids: tuple[str, ...] = ()  # D-1: WorldQueryResult IDs that fed this claim
    plan_decision_ids: tuple[str, ...] = ()  # D-2: PlanDecision IDs that fed this claim
    falsification_result_ids: tuple[str, ...] = ()  # D-3: FalsificationResult IDs that fed this claim
    defeater_result_ids: tuple[str, ...] = ()  # D-5: DefeaterResult IDs that fed this claim

    def __post_init__(self):
        if not self.producer:
            object.__setattr__(self, "producer", self.derivation_type.value)


# ── Claim ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ConclusionClaim:
    """A single structured claim about the environment.

    INVARIANT: Every non-abstention factual claim must cite at least one
    supporting evidence item (supporting_evidence_ids != empty) UNLESS
    the predicate is explicitly allowed to be prior-derived.
    """
    claim_id: str = field(default_factory=lambda: f"cl_{uuid.uuid4().hex[:12]}")

    # The claim itself
    subject_id: str = ""          # e.g., "10.0.1.10:22", "host-A"
    predicate: Optional[ConclusionPredicate] = None
    object_value: Any = None      # e.g., "ssh", {"port": 22, "state": "open"}

    # Confidence (None = not calibrated)
    confidence: Optional[float] = None

    # Supporting and contradicting evidence
    supporting_evidence_ids: tuple[str, ...] = ()
    contradicting_evidence_ids: tuple[str, ...] = ()

    # Epistemic provenance
    provenance: Optional[ConclusionProvenance] = None


# ── Run Conclusion ─────────────────────────────────────────────────

@dataclass(frozen=True)
class RunConclusion:
    """The structured output of a complete run.

    This is the ONLY input to the outcome evaluator (alongside truth).
    The evaluator does NOT receive HypothesisManager, WorldModel,
    EvidenceGraph, Planner, LLM, or AblationConfig.
    """
    run_id: str = ""
    scenario_id: str = ""

    # What the system decided to do
    decision: DecisionOutcome = DecisionOutcome.STOP_BUDGET_EXHAUSTED

    # All claims the system believes about the environment
    claims: tuple[ConclusionClaim, ...] = ()

    # Raphael's own assessment (NOT used by evaluator for scoring)
    agent_believes_objective_satisfied: Optional[bool] = None

    # Why the system stopped / cannot conclude
    abstention_reason: Optional[str] = None

    # When this was generated
    generated_at: float = field(default_factory=time.time)

    # Producer architecture (for traceability, NOT used by evaluator)
    _architecture_id: str = ""


# ── Validation ─────────────────────────────────────────────────────

def validate_conclusion(conclusion: RunConclusion) -> list[str]:
    """Validate RunConclusion invariants.

    Returns list of issues (empty = valid).
    """
    issues = []

    for claim in conclusion.claims:
        # Every non-trivial claim must have supporting evidence
        if not claim.supporting_evidence_ids and claim.predicate is not None:
            issues.append(
                f"Claim {claim.claim_id}: {claim.predicate.value} "
                f"has no supporting evidence"
            )

        # Must have a subject
        if not claim.subject_id and claim.predicate is not None:
            issues.append(
                f"Claim {claim.claim_id}: no subject_id for {claim.predicate.value}"
            )

        # Must have provenance
        if claim.provenance is None:
            issues.append(f"Claim {claim.claim_id}: missing provenance")

    return issues


# ── Helpers for creating claims ─────────────────────────────────────

def make_claim(
    subject_id: str,
    predicate: ConclusionPredicate,
    object_value: Any,
    supporting_evidence_ids: tuple[str, ...] = (),
    contradicting_evidence_ids: tuple[str, ...] = (),
    confidence: Optional[float] = None,
    producer: str = "",
    derivation_type: DerivationType = DerivationType.DETERMINISTIC_RULE,
    hypothesis_ids: tuple[str, ...] = (),
    world_relation_ids: tuple[str, ...] = (),
    model_inference_ids: tuple[str, ...] = (),
    world_query_ids: tuple[str, ...] = (),
    plan_decision_ids: tuple[str, ...] = (),
    falsification_result_ids: tuple[str, ...] = (),
    defeater_result_ids: tuple[str, ...] = (),
) -> ConclusionClaim:
    """Create a typed ConclusionClaim with provenance."""
    return ConclusionClaim(
        subject_id=subject_id,
        predicate=predicate,
        object_value=object_value,
        confidence=confidence,
        supporting_evidence_ids=supporting_evidence_ids,
        contradicting_evidence_ids=contradicting_evidence_ids,
        provenance=ConclusionProvenance(
            producer=producer or derivation_type.value,
            derivation_type=derivation_type,
            evidence_ids=supporting_evidence_ids,
            hypothesis_ids=hypothesis_ids,
            world_relation_ids=world_relation_ids,
            model_inference_ids=model_inference_ids,
            world_query_ids=world_query_ids,
            plan_decision_ids=plan_decision_ids,
            falsification_result_ids=falsification_result_ids,
            defeater_result_ids=defeater_result_ids,
        ),
    )


def make_runconclusion(
    run_id: str,
    scenario_id: str,
    decision: DecisionOutcome,
    claims: list[ConclusionClaim],
    agent_believes_objective_satisfied: Optional[bool] = None,
    abstention_reason: Optional[str] = None,
    architecture_id: str = "",
) -> RunConclusion:
    """Create a RunConclusion with timestamp."""
    return RunConclusion(
        run_id=run_id,
        scenario_id=scenario_id,
        decision=decision,
        claims=tuple(claims),
        agent_believes_objective_satisfied=agent_believes_objective_satisfied,
        abstention_reason=abstention_reason,
        _architecture_id=architecture_id,
    )