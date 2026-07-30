"""
THE STUDENT — WAF-aware technique proposal and payload mutation.

P1 Stealth & Evasion integration:
  - technique_proposer() queries WAFDetector before proposing candidates
  - propose_mutations() uses PayloadMutator to generate WAF-bypass variants

Architecture:
    WAFDetector.fingerprint(target)
        -> Student.technique_proposer(target, profile)
            -> StudentCandidateGenerator.generate_candidates(target, profile, waf_info)
                -> list[dict] (Candidates tagged with waf_type)

    PayloadMutator.mutate(payload, waf_type, technique)
        -> Student.propose_mutations(original_candidate, waf_type)
            -> list[dict] (Mutated Candidates for Planner)
"""

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Optional imports ──────────────────────────────────────────────

try:
    from orchestrator.brain.waf_detector import WAFDetector, WAFType
    HAS_WAF_DETECTOR = True
except ImportError:
    HAS_WAF_DETECTOR = False
    WAFDetector = None
    WAFType = None

try:
    from orchestrator.student.payload_mutator import PayloadMutator, MutationResult
    HAS_PAYLOAD_MUTATOR = True
except ImportError:
    HAS_PAYLOAD_MUTATOR = False
    PayloadMutator = None
    MutationResult = None

try:
    from orchestrator.brain.candidate_generators.student_generator import (
        StudentCandidateGenerator,
        CANDIDATE_ORIGIN_STUDENT,
    )
    HAS_STUDENT_GENERATOR = True
except ImportError:
    HAS_STUDENT_GENERATOR = False
    StudentCandidateGenerator = None
    CANDIDATE_ORIGIN_STUDENT = "STUDENT"


class Student:
    """
    Autonomous pentest learning agent — WAF-aware technique proposer.

    Wraps StudentCandidateGenerator with WAF detection and payload mutation.
    Provides the integration surface for P1 Stealth & Evasion.

    Usage:
        student = Student(waf_detector=waf, payload_mutator=mutator, candidate_generator=gen)
        candidates = student.technique_proposer(target="10.0.1.10", profile={...})
        mutations = student.propose_mutations(original_candidate, waf_type="cloudflare")
    """

    def __init__(
        self,
        waf_detector: Optional[Any] = None,
        payload_mutator: Optional[Any] = None,
        candidate_generator: Optional[Any] = None,
        world_model: Optional[Any] = None,
    ):
        self.waf_detector = waf_detector
        self.payload_mutator = payload_mutator
        self.candidate_generator = candidate_generator or (
            StudentCandidateGenerator() if HAS_STUDENT_GENERATOR else None
        )
        self.world_model = world_model

    # ── WAF-aware technique proposal ──────────────────────────────

    def technique_proposer(
        self,
        target: str,
        profile: dict,
        max_candidates: int = 15,
        min_confidence: float = 0.2,
    ) -> list[dict]:
        """
        Propose techniques for a target, optionally with WAF awareness.

        If a WAFDetector is configured, fingerprints the target first and
        tags candidates with WAF type and confidence. If no WAF detector,
        delegates directly to StudentCandidateGenerator.

        Args:
            target: Target IP, hostname, or identifier
            profile: Target profile dict with 'stack_components' list
            max_candidates: Maximum number of candidates
            min_confidence: Minimum confidence threshold

        Returns:
            List of Candidate dicts (same format as Planner.decide()),
            each tagged with optional waf_info metadata.
        """
        if not self.candidate_generator:
            logger.warning("[Student] No candidate generator available")
            return []

        # Step 1: Detect WAF if detector available
        waf_info = self._detect_waf(target)

        # Step 2: Generate candidates with WAF context
        candidates = self.candidate_generator.generate_candidates(
            target=target,
            profile=profile,
            max_candidates=max_candidates,
            min_confidence=min_confidence,
        )

        # Step 3: Tag candidates with WAF metadata
        if waf_info and waf_info.get("waf_type", "none") != "none":
            waf_type = waf_info["waf_type"]
            for candidate in candidates:
                candidate["waf_type"] = waf_type
                candidate["waf_confidence"] = waf_info.get("confidence", 0.0)
                candidate["waf_details"] = waf_info.get("details", {})
                # Adjust confidence: WAF presence reduces certainty
                if waf_info.get("confidence", 0) > 0.5:
                    candidate["confidence"] = candidate.get("confidence", 0.5) * 0.85
                candidate["rationale"] += f" [WAF: {waf_type} (conf={waf_info.get('confidence', 0):.2f})]"

        logger.info(
            "[Student] technique_proposer: %d candidates for %s (WAF: %s)",
            len(candidates),
            target,
            waf_info.get("waf_type", "none") if waf_info else "unknown",
        )
        return candidates

    def _detect_waf(self, target: str) -> Optional[dict]:
        """Run WAF detection on target. Returns waf_info dict or None."""
        if not self.waf_detector or not HAS_WAF_DETECTOR:
            return None

        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                waf_info = loop.run_until_complete(
                    self.waf_detector.fingerprint(target)
                )
            finally:
                loop.close()

            # Store in WorldModel if available
            if self.world_model and waf_info:
                waf_type = waf_info.get("waf_type", "unknown")
                if waf_type and waf_type != "none":
                    try:
                        self.world_model.store_target_attribute(
                            target=target,
                            key="waf_type",
                            value=waf_type,
                            source="waf_detector",
                            confidence=waf_info.get("confidence", 0.5),
                        )
                    except Exception as e:
                        logger.debug(f"[Student] Failed to store WAF in WorldModel: {e}")

            return waf_info

        except Exception as e:
            logger.warning(f"[Student] WAF detection failed for {target}: {e}")
            return None

    # ── Payload mutation ──────────────────────────────────────────

    def propose_mutations(
        self,
        original_candidate: dict,
        waf_type: str = "unknown",
        technique: str = "",
    ) -> list[dict]:
        """
        Generate mutated variants of a blocked candidate payload.

        Called when FalsificationManager detects a WAF block (403/406/509).
        Uses PayloadMutator to generate alternative encodings, then wraps
        them as new Candidates for the Planner.

        Args:
            original_candidate: The Candidate dict that was blocked
            waf_type: Detected WAF type (e.g., "cloudflare", "modsecurity")
            technique: Technique identifier (e.g., "sqli_union_basic")

        Returns:
            List of new Candidate dicts with mutated payloads
        """
        if not self.payload_mutator or not HAS_PAYLOAD_MUTATOR:
            logger.warning("[Student] No PayloadMutator available for mutation")
            return []

        # Extract original payload from candidate action_spec
        action_spec = original_candidate.get("action_spec", {})
        original_payload = action_spec.get("payload", "")
        if not original_payload:
            logger.debug("[Student] No payload in candidate to mutate")
            return []

        if not technique:
            technique = original_candidate.get("technique_id", "unknown")

        # Generate mutations
        try:
            mutation_results = self.payload_mutator.mutate(
                payload=original_payload,
                waf_type=waf_type,
                technique=technique,
            )
        except Exception as e:
            logger.warning(f"[Student] Payload mutation failed: {e}")
            return []

        if not mutation_results:
            logger.debug("[Student] No mutations generated")
            return []

        # Wrap mutations as new Candidates
        import uuid
        mutated_candidates = []
        for mr in mutation_results:
            new_action_spec = dict(action_spec)
            new_action_spec["payload"] = mr.mutated_payload
            new_action_spec["original_payload"] = original_payload
            new_action_spec["mutation_method"] = mr.method
            new_action_spec["mutation_round"] = mr.round_num

            mutated_candidate = dict(original_candidate)
            mutated_candidate["action_id"] = f"mut_{technique}_{uuid.uuid4().hex[:6]}"
            mutated_candidate["action_spec"] = new_action_spec
            mutated_candidate["rationale"] = (
                f"Mutation round {mr.round_num}: {mr.method} bypass for {waf_type}"
            )
            mutated_candidate["confidence"] = mr.confidence * original_candidate.get("confidence", 0.5)
            mutated_candidate["candidate_origin"] = f"{CANDIDATE_ORIGIN_STUDENT}_MUTATION"
            mutated_candidate["mutation_info"] = {
                "method": mr.method,
                "round": mr.round_num,
                "original_payload": original_payload,
                "mutated_payload": mr.mutated_payload,
                "waf_type": waf_type,
            }
            mutated_candidates.append(mutated_candidate)

        logger.info(
            "[Student] propose_mutations: %d variants for technique %s (WAF: %s, round: %d)",
            len(mutated_candidates),
            technique,
            waf_type,
            mutation_results[0].round_num if mutation_results else 0,
        )
        return mutated_candidates

    # ── Convenience ───────────────────────────────────────────────

    def stats(self) -> dict:
        """Return Student stats."""
        return {
            "has_waf_detector": self.waf_detector is not None,
            "has_payload_mutator": self.payload_mutator is not None,
            "has_candidate_generator": self.candidate_generator is not None,
            "has_world_model": self.world_model is not None,
        }
