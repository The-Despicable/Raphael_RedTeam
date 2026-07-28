"""defeater.py — D-5 Defeater / Counterfactual Reasoning Causal Integration.

Implements the seven-gate model:
  INVOKED → PRODUCED → REFERENCED → EVALUATED → BELIEF_UPDATED
    → DECISION_RELEVANT → CONCLUSION

Architecture invariants (SENTINEL-approved):
  1. Defeaters challenge RELIABILITY CONDITIONS supporting H, not ¬H.
  2. Generator depends only on cognitive-visible state.
  3. Identical cognitive-visible state + different hidden evaluator truth
     → equivalent defeater triggers (excluding IDs/timestamps).
  4. BaseCandidates(FULL) == BaseCandidates(NO_DEFEATER).
     DefeaterCandidates are append-only, never modify base set.
  5. Belief-update table is a literal constant — no post-result tuning.
  6. apply_defeater_result() is the dedicated semantic boundary.
"""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from arena.conclusion import ConclusionPredicate


# ── Defeater Outcome ──────────────────────────────────────────

class DefeaterOutcome(str, Enum):
    """Outcome of a defeater evaluation against evidence."""
    NOT_TRIGGERED = "not_triggered"   # Evidence contradicts the defeating condition
    TRIGGERED = "triggered"           # Defeating condition observed
    INCONCLUSIVE = "inconclusive"     # Evidence cannot determine the condition
    NOT_TESTABLE = "not_testable"     # No authorized discriminating action exists


# ── DefeaterTrigger (input) ───────────────────────────────────

@dataclass(frozen=True)
class DefeaterTrigger:
    """A proposed reliability condition for hypothesis H.

    This is NOT a hypothesis. It is a structured predicate:
    "If X is observed, the reliability condition supporting H is violated."

    A DefeaterTrigger is a PROPOSAL, never an authorization.
    The suggested action MUST pass through CapabilityBroker.
    """
    defeater_id: str = field(default_factory=lambda: f"df_{uuid.uuid4().hex[:12]}")
    hypothesis_id: str = ""

    # Human-readable: "What would make H unreliable"
    condition_description: str = ""

    # The specific predicate that would trigger this defeater
    target_predicate: Optional[ConclusionPredicate] = None
    target_entity: str = ""

    # How confident we are this condition would actually invalidate H
    relevance_confidence: float = 0.0  # [0.0, 1.0]

    # Suggested discriminating action (proposal only — must pass Broker)
    suggested_action_type: str = ""
    suggested_target: str = ""

    # Provenance (externally assigned)
    generated_at: float = field(default_factory=time.time)
    generated_by: str = "defeater_generator"
    source_evidence_ids: tuple[str, ...] = ()
    source_hypothesis_id: str = ""

    def to_dict(self) -> dict:
        return {
            "defeater_id": self.defeater_id,
            "hypothesis_id": self.hypothesis_id,
            "condition_description": self.condition_description,
            "target_predicate": self.target_predicate.value if self.target_predicate else None,
            "target_entity": self.target_entity,
            "relevance_confidence": self.relevance_confidence,
            "suggested_action_type": self.suggested_action_type,
            "suggested_target": self.suggested_target,
            "generated_at": self.generated_at,
            "generated_by": self.generated_by,
            "source_evidence_ids": list(self.source_evidence_ids),
        }


# ── DefeaterResult (output) ──────────────────────────────────

@dataclass(frozen=True)
class DefeaterResult:
    """The causal intermediate between evidence collection and belief revision.

    Causal chain:
      DefeaterTrigger → DiscriminatingAction → Observation
        → Evidence → DefeaterResult → Hypothesis change → Planner change
    """
    result_id: str = field(default_factory=lambda: f"dr_{uuid.uuid4().hex[:12]}")
    defeater_id: str = ""
    hypothesis_id: str = ""
    outcome: DefeaterOutcome = DefeaterOutcome.INCONCLUSIVE

    # Evidence that triggered or supported
    triggering_evidence_ids: tuple[str, ...] = ()
    supporting_evidence_ids: tuple[str, ...] = ()

    # Action that produced the evidence
    discriminating_action_id: str = ""
    discriminating_observation_ids: tuple[str, ...] = ()

    # Confidence/relevance update
    prior_hypothesis_confidence: Optional[float] = None
    posterior_hypothesis_confidence: Optional[float] = None
    defeater_relevance_updated: Optional[float] = None

    # Rationale
    reason_codes: tuple[str, ...] = ()

    # Traceability
    generated_at: float = field(default_factory=time.time)
    plan_decision_id: str = ""

    def to_dict(self) -> dict:
        return {
            "result_id": self.result_id,
            "defeater_id": self.defeater_id,
            "hypothesis_id": self.hypothesis_id,
            "outcome": self.outcome.value,
            "triggering_evidence_ids": list(self.triggering_evidence_ids),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "discriminating_action_id": self.discriminating_action_id,
            "prior_hypothesis_confidence": self.prior_hypothesis_confidence,
            "posterior_hypothesis_confidence": self.posterior_hypothesis_confidence,
            "defeater_relevance_updated": self.defeater_relevance_updated,
            "reason_codes": list(self.reason_codes),
            "generated_at": self.generated_at,
            "plan_decision_id": self.plan_decision_id,
        }


# ── Belief-Update Transition Table (PREREGISTERED — literal constant) ──
# Per spec 5.5.2 and 5.5.3: This is a literal constant.
# No post-result tuning. No config file loading.
# Changes require SENTINEL approval and new spec version.

# Identifies the exact frozen transition policy version (D-5 V2)
POLICY_VERSION = "D5_V2_2026-07-26"

HYPOTHESIS_STATES = ["POSTULATED", "DOUBTFUL", "ABANDONED"]

# Frozen transition policy for TRIGGERED outcome
TRIGGERED_TRANSITIONS = {
    # (prior_state, prior_confidence_threshold) -> (posterior_confidence_fn, posterior_state)
    ("POSTULATED", 0.5): (lambda c: c * 0.5, "DOUBTFUL"),
    ("POSTULATED", None): (lambda c: c * 0.3, "ABANDONED"),  # confidence < 0.5
    ("DOUBTFUL", None): (lambda c: c * 0.3, "ABANDONED"),
    ("ABANDONED", None): (lambda c: c, "ABANDONED"),
}

# Frozen transition policy for NOT_TRIGGERED outcome
NOT_TRIGGERED_TRANSITIONS = {
    ("POSTULATED", None): (lambda c: min(1.0, c * 1.2), "POSTULATED"),
    ("DOUBTFUL", 0.3): (lambda c: c * 1.2, "POSTULATED"),
    ("DOUBTFUL", None): (lambda c: c, "DOUBTFUL"),  # confidence < 0.3
    ("ABANDONED", None): (lambda c: c, "ABANDONED"),
}

# INCONCLUSIVE: no belief change
INCONCLUSIVE_TRANSITION = (lambda c: c, None)  # None = keep current state


def apply_belief_transition(
    prior_state: str,
    prior_confidence: float,
    outcome: DefeaterOutcome,
) -> tuple[float, str]:
    """Apply the frozen belief-update policy.

    Args:
        prior_state: Current hypothesis state string.
        prior_confidence: Current confidence value.
        outcome: The DefeaterOutcome.

    Returns:
        (posterior_confidence, posterior_state)

    Raises:
        ValueError if outcome is unrecognized.
    """
    if outcome == DefeaterOutcome.INCONCLUSIVE:
        return (prior_confidence, prior_state)

    if outcome == DefeaterOutcome.NOT_TESTABLE:
        # NOT_TESTABLE does not change belief — no evidence was gathered
        return (prior_confidence, prior_state)

    if outcome == DefeaterOutcome.TRIGGERED:
        # Check state-specific rules
        state_upper = prior_state.upper()
        if state_upper == "POSTULATED":
            if prior_confidence < 0.5:
                fn, new_state = TRIGGERED_TRANSITIONS[("POSTULATED", None)]
            else:
                fn, new_state = TRIGGERED_TRANSITIONS[("POSTULATED", 0.5)]
        elif state_upper == "DOUBTFUL":
            fn, new_state = TRIGGERED_TRANSITIONS[("DOUBTFUL", None)]
        elif state_upper == "ABANDONED":
            fn, new_state = TRIGGERED_TRANSITIONS[("ABANDONED", None)]
        else:
            # Unknown state — conservative: reduce but don't abandon
            return (prior_confidence * 0.7, "DOUBTFUL")
        return (fn(prior_confidence), new_state)

    if outcome == DefeaterOutcome.NOT_TRIGGERED:
        state_upper = prior_state.upper()
        if state_upper == "POSTULATED":
            fn, new_state = NOT_TRIGGERED_TRANSITIONS[("POSTULATED", None)]
        elif state_upper == "DOUBTFUL":
            if prior_confidence >= 0.3:
                fn, new_state = NOT_TRIGGERED_TRANSITIONS[("DOUBTFUL", 0.3)]
            else:
                fn, new_state = NOT_TRIGGERED_TRANSITIONS[("DOUBTFUL", None)]
        elif state_upper == "ABANDONED":
            fn, new_state = NOT_TRIGGERED_TRANSITIONS[("ABANDONED", None)]
        else:
            return (min(1.0, prior_confidence * 1.1), "POSTULATED")
        return (fn(prior_confidence), new_state)

    raise ValueError(f"Unknown DefeaterOutcome: {outcome}")


# ── BeliefTransition (typed causal artifact) ──────────────────

@dataclass(frozen=True)
class BeliefTransition:
    """A typed artifact proving a defeater-driven belief change.

    Every TRIGGERED or NOT_TRIGGERED outcome that changes hypothesis
    confidence or state produces exactly one BeliefTransition.

    INCONCLUSIVE outcomes MUST NOT produce a BeliefTransition.

    Causal chain:
      DefeaterResult → BeliefTransition → Hypothesis state change
        → Planner consumes post-transition state
    """
    transition_id: str = field(default_factory=lambda: f"bt_{uuid.uuid4().hex[:12]}")
    hypothesis_id: str = ""
    defeater_result_id: str = ""
    outcome: DefeaterOutcome = DefeaterOutcome.INCONCLUSIVE

    prior_confidence: float = 0.0
    posterior_confidence: float = 0.0
    prior_state: str = ""
    posterior_state: str = ""

    # Identifies the frozen policy that produced this transition
    policy_version: str = POLICY_VERSION

    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "transition_id": self.transition_id,
            "hypothesis_id": self.hypothesis_id,
            "defeater_result_id": self.defeater_result_id,
            "outcome": self.outcome.value,
            "prior_confidence": self.prior_confidence,
            "posterior_confidence": self.posterior_confidence,
            "prior_state": self.prior_state,
            "posterior_state": self.posterior_state,
            "policy_version": self.policy_version,
            "generated_at": self.generated_at,
        }


# ── Candidate Origin Constants ────────────────────────────────

CANDIDATE_ORIGIN_BASE = "BASE"
CANDIDATE_ORIGIN_DEFEATER = "DEFEATER"


# ── DefeaterGenerator ─────────────────────────────────────────

class DefeaterGenerator:
    """Generates DefeaterTrigger objects for hypotheses.

    Invariant: depends ONLY on cognitive-visible state:
      - Hypothesis H and its explicit assumptions
      - Supporting/contradicting evidence
      - Existing WorldModel state (entities, relationships)
      - Preregistered generic reliability rules

    Does NOT import or reference:
      - evaluator_truth, expected_outcome, EvaluationResult
      - scoring state, score thresholds
      - ArenaScenario beyond scenario_id
    """

    def __init__(self):
        self._invocation_count = 0

    def generate(
        self,
        hypothesis_id: str,
        hypothesis_statement: str,
        hypothesis_entity_ids: list[str],
        hypothesis_assumptions: list[str],
        evidence_ids: list[str],
        world_entities: Optional[list[dict]] = None,
        known_services: Optional[dict[str, list]] = None,
        tracer=None,
    ) -> list[DefeaterTrigger]:
        """Generate DefeaterTriggers for a hypothesis.

        Only cognitive-visible state is used. No evaluator truth
        or scenario metadata beyond what's visible in evidence.

        Args:
            hypothesis_id: The hypothesis to challenge.
            hypothesis_statement: The hypothesis statement text.
            hypothesis_entity_ids: Entity IDs the hypothesis concerns.
            hypothesis_assumptions: Assumptions the hypothesis depends on.
            evidence_ids: Evidence IDs supporting this hypothesis.
            world_entities: WorldModel entity dicts (cognitive-visible).
            known_services: Known services per target (cognitive-visible).
            tracer: Optional trace collector for causal tracing.

        Returns:
            List of DefeaterTrigger objects (empty if none applicable).
        """
        self._invocation_count += 1

        if tracer:
            tracer.trace("defeater", "invoked",
                         input_ids=[hypothesis_id],
                         output_ids=[f"inv_{self._invocation_count}"])

        triggers: list[DefeaterTrigger] = []
        stmt_lower = hypothesis_statement.lower()

        # ── Reliability Rule 1: Entity identity — if H depends on
        # a specific entity being at a specific location, challenge that.
        if hypothesis_entity_ids:
            for eid in hypothesis_entity_ids[:3]:
                triggers.append(DefeaterTrigger(
                    hypothesis_id=hypothesis_id,
                    condition_description=(
                        f"Entity {eid} may not have the properties "
                        f"that H assigns to it"
                    ),
                    target_entity=eid,
                    relevance_confidence=0.5,
                    suggested_action_type="direct_probe",
                    suggested_target=eid,
                    source_evidence_ids=tuple(evidence_ids[:5]),
                    generated_by="defeater_generator",
                ))

        # ── Reliability Rule 2: Service mismatch — if H claims a
        # service type, challenge by testing for that service.
        for svc in ["ssh", "http", "https", "custom", "tls"]:
            if svc in stmt_lower:
                triggers.append(DefeaterTrigger(
                    hypothesis_id=hypothesis_id,
                    condition_description=(
                        f"Service {svc} claimed by H may not be "
                        f"present or may behave differently"
                    ),
                    target_predicate=None,
                    target_entity="target",
                    relevance_confidence=0.6,
                    suggested_action_type="banner_grab",
                    suggested_target="target",
                    source_evidence_ids=tuple(evidence_ids[:5]),
                    generated_by="defeater_generator",
                ))
                break

        # ── Reliability Rule 3: Version disagreement — if H relies
        # on specific version info, challenge with targeted probe.
        import re as _re
        versions = _re.findall(r'\d+\.\d+\.\d+', hypothesis_statement)
        if versions:
            triggers.append(DefeaterTrigger(
                hypothesis_id=hypothesis_id,
                condition_description=(
                    f"Version data ({', '.join(versions[:2])}) in H "
                    f"may be inaccurate"
                ),
                target_entity="target",
                relevance_confidence=0.4,
                suggested_action_type="scan",
                suggested_target="target",
                source_evidence_ids=tuple(evidence_ids[:5]),
                generated_by="defeater_generator",
            ))

        # ── Reliability Rule 4: Contradiction sensitivity — if H
        # was formed in the presence of contradictions, challenge
        # the reliability of its evidence base.
        if hypothesis_assumptions:
            for assump in hypothesis_assumptions:
                if "contradiction" in assump.lower() or "conflict" in assump.lower():
                    triggers.append(DefeaterTrigger(
                        hypothesis_id=hypothesis_id,
                        condition_description=(
                            f"H depends on evidence that has contradictions"
                        ),
                        target_entity="target",
                        relevance_confidence=0.7,
                        suggested_action_type="direct_probe",
                        suggested_target="target",
                        source_evidence_ids=tuple(evidence_ids[:5]),
                        generated_by="defeater_generator",
                    ))
                    break

        # Trace PRODUCED for each trigger
        if tracer:
            for t in triggers:
                tracer.trace("defeater", "produced",
                             output_ids=[t.defeater_id],
                             input_ids=[hypothesis_id])

        return triggers


# ── DefeaterEvaluator ─────────────────────────────────────────

class DefeaterEvaluator:
    """Evaluates evidence against a DefeaterTrigger to produce DefeaterResult.

    Produces DefeaterResult with outcome:
      - NOT_TRIGGERED: Evidence contradicts the defeating condition
      - TRIGGERED: Defeating condition observed
      - INCONCLUSIVE: Evidence cannot determine
      - NOT_TESTABLE: No discriminating action was executed

    Does NOT import or reference:
      - evaluator_truth, expected_outcome, EvaluationResult
      - scoring state, score thresholds
    """

    def __init__(self):
        self._eval_count = 0

    def evaluate(
        self,
        trigger: DefeaterTrigger,
        observation_text: str = "",
        observation_evidence_ids: tuple[str, ...] = (),
        discriminator_action_id: str = "",
        plan_decision_id: str = "",
        prior_hypothesis_confidence: Optional[float] = None,
        tracer=None,
    ) -> DefeaterResult:
        """Evaluate evidence against a DefeaterTrigger.

        Args:
            trigger: The DefeaterTrigger to evaluate.
            observation_text: Text from the discriminating action.
            observation_evidence_ids: Evidence IDs produced.
            discriminator_action_id: Action ID that produced evidence.
            plan_decision_id: PlanDecision that selected the action.
            prior_hypothesis_confidence: Confidence before evaluation.
            tracer: Optional trace collector.

        Returns:
            DefeaterResult with outcome and supporting evidence.
        """
        self._eval_count += 1

        # Determine outcome from observation text
        outcome = self._determine_outcome(trigger, observation_text)
        reason_codes = [f"defeater_{outcome.value}"]

        # If not_testable, no evidence was gathered
        if outcome == DefeaterOutcome.NOT_TESTABLE:
            return DefeaterResult(
                defeater_id=trigger.defeater_id,
                hypothesis_id=trigger.hypothesis_id,
                outcome=outcome,
                prior_hypothesis_confidence=prior_hypothesis_confidence,
                posterior_hypothesis_confidence=prior_hypothesis_confidence,
                reason_codes=tuple(reason_codes),
                generated_at=time.time(),
                plan_decision_id=plan_decision_id,
            )

        # For outcomes with evidence
        result = DefeaterResult(
            defeater_id=trigger.defeater_id,
            hypothesis_id=trigger.hypothesis_id,
            outcome=outcome,
            triggering_evidence_ids=(
                observation_evidence_ids if outcome == DefeaterOutcome.TRIGGERED
                else ()
            ),
            supporting_evidence_ids=(
                observation_evidence_ids if outcome == DefeaterOutcome.NOT_TRIGGERED
                else observation_evidence_ids
            ),
            discriminating_action_id=discriminator_action_id,
            discriminating_observation_ids=observation_evidence_ids,
            prior_hypothesis_confidence=prior_hypothesis_confidence,
            reason_codes=tuple(reason_codes),
            generated_at=time.time(),
            plan_decision_id=plan_decision_id,
        )

        # Compute posterior confidence from frozen transition policy
        if prior_hypothesis_confidence is not None:
            post_conf, _ = apply_belief_transition(
                prior_state="POSTULATED",  # Will be overridden by caller
                prior_confidence=prior_hypothesis_confidence,
                outcome=outcome,
            )
            object.__setattr__(result, "posterior_hypothesis_confidence", post_conf)

        if tracer:
            tracer.trace("defeater", "evaluated",
                         input_ids=[trigger.defeater_id],
                         output_ids=[result.result_id])

        return result

    def _determine_outcome(
        self,
        trigger: DefeaterTrigger,
        observation_text: str,
    ) -> DefeaterOutcome:
        """Determine DefeaterOutcome from observation text.

        Uses generic text matching against the condition description.
        Does NOT access evaluator truth or expected outcomes.

        This is intentionally simple — a production system would use
        more sophisticated evidence evaluation.
        """
        if not observation_text.strip():
            return DefeaterOutcome.NOT_TESTABLE

        obs_lower = observation_text.lower()
        cond_lower = trigger.condition_description.lower()

        # Check for explicit negations (NOT_TRIGGERED signals)
        not_triggered_signals = [
            "not found", "no evidence", "does not match",
            "unreachable", "refused connection",
        ]
        for signal in not_triggered_signals:
            if signal in obs_lower:
                return DefeaterOutcome.NOT_TRIGGERED

        # Check for explicit confirmations (TRIGGERED signals)
        triggered_signals = [
            "match found", "confirmed", "detected",
            "version", "banner", "open",
        ]
        for signal in triggered_signals:
            if signal in obs_lower:
                return DefeaterOutcome.TRIGGERED

        # Check if condition-related terms appear
        cond_terms = set(cond_lower.split())
        obs_terms = set(obs_lower.split())
        overlap = cond_terms.intersection(obs_terms)

        if len(overlap) >= 2:
            # Some evidence relates to the condition
            return DefeaterOutcome.TRIGGERED

        # Default: inconclusive
        return DefeaterOutcome.INCONCLUSIVE



