"""Planner — selects the next action based on target model and capability model."""
from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional
from raphael.models.engagement_state import EngagementState
from raphael.models.target_model import TargetModel, ConstraintDelta
from raphael.models.capability_model import CapabilityModel
from raphael.techniques import TECHNIQUE_REGISTRY, Technique
from raphael.memory.statistical_prior import expected_value
from raphael.cortex.model_refiner import get_refiner
from raphael.cortex.hypothesizer import get_hypothesizer

logger = logging.getLogger("raphael.planner")


@dataclass
class Action:
    """What the planner decided to do next."""
    action_type: str  # "execute" | "acquire_capability" | "stuck" | "re_evaluate" | "prepared"
    technique: Optional[str] = None  # technique name to execute
    reason: str = ""
    target: Optional[str] = None  # capability to acquire

    def __repr__(self) -> str:
        if self.action_type == "execute":
            return f"Action(execute, technique={self.technique})"
        elif self.action_type == "acquire_capability":
            return f"Action(acquire, capability={self.target})"
        return f"Action({self.action_type}, reason={self.reason})"


class Planner:
    """
    Core decision loop.
    1. Filter technique DB by target feasibility
    2. Filter by capability executability
    3. Rank by memory prior
    4. Return highest-ranked or fallback
    """

    def __init__(self):
        self.ranking_weights: dict[str, float] = {
            "recon": 1.0,
            "exploit": 1.0,
        }
        self._recently_executed: set[str] = set()
        self._executed_without_result: set[str] = set()
        self._exhaustion_counts: dict[str, int] = {}
        self._technique_productions: dict[str, set] = {}
        # Track technique exhaustion: technique_name -> count of consecutive no-new-info executions
        self._exhaustion_count: dict[str, int] = {}
        self._exhaustion_threshold: int = 2  # mark exhausted after 2 consecutive no-new-info runs
        self._last_produced: dict[str, set[str]] = {}  # technique -> last affordances produced

    @staticmethod
    def _provide_is_covered(provide: str, affordances: set[str]) -> bool:
        if provide in affordances:
            return True
        for aff in affordances:
            if aff.startswith(provide + ":") or aff.startswith(provide + "_"):
                return True
            if aff == provide:
                return True
        return False

    def _is_exhausted(self, technique_name: str, new_affordances: set[str]) -> bool:
        """Check if technique has exhausted its potential."""
        count = self._exhaustion_count.get(technique_name, 0)
        if count >= self._exhaustion_threshold:
            return True
        # Also check if it's producing the exact same affordances repeatedly
        last = self._last_produced.get(technique_name, set())
        if last and last == new_affordances and new_affordances:
            return True
        return False

    def _update_exhaustion(self, technique_name: str, produced_new_info: bool, new_affordances: set[str] = None):
        """Update exhaustion tracking after technique execution."""
        if not produced_new_info:
            self._exhaustion_count[technique_name] = self._exhaustion_count.get(technique_name, 0) + 1
        else:
            self._exhaustion_count[technique_name] = 0
        
        if new_affordances is not None:
            self._last_produced[technique_name] = new_affordances.copy()

    def _reset_exhaustion(self, technique_name: str):
        """Reset exhaustion for a technique (e.g., when target profile changes)."""
        self._exhaustion_count.pop(technique_name, None)
        self._last_produced.pop(technique_name, None)

    async def select_next_step(self, state: EngagementState, available_affordances: set[str],
                                available_constraints: set[str]) -> Action:
        """
        Select the best next action given current state.
        """
        cycle = state.current_cycle
        target = state.target
        capabilities = state.capabilities
        domain = "network"

        # Step 1: Filter by target feasibility
        target_viable: list[Technique] = []
        for technique in TECHNIQUE_REGISTRY.values():
            # Check prerequisites (all must be in affordances)
            prereqs_met = all(
                p in available_affordances for p in technique.prerequisites
            ) if technique.prerequisites else True

            # Check blockers (none should be in constraints OR affordances)
            blockers_clear = not any(
                b in available_constraints or b in available_affordances for b in technique.blockers
            ) if technique.blockers else True

            # Check negative cache
            not_dead = not target.is_technique_dead(
                technique.name, cycle,
                technique.prerequisites, technique.blockers
            )

            # Check exhaustion
            not_exhausted = not self._is_exhausted(technique.name, set())

            if prereqs_met and blockers_clear and not_dead and not_exhausted:
                # Repeat prevention: skip if already executed with no new info gained
                if technique.name in self._recently_executed:
                    # If it previously ran and produced nothing, skip it
                    if technique.name in self._executed_without_result:
                        logger.debug(f"Skipping {technique.name} — previously produced no new info")
                        continue
                    # Check if technique's provides are already covered
                    still_relevant = any(
                        not self._provide_is_covered(p, available_affordances) for p in technique.provides
                    )
                    # Also check if it would just resolve the same unknowns again
                    if not still_relevant and not technique.prerequisites:
                        logger.debug(f"Skipping {technique.name} — already executed, no new affordances expected")
                        continue
                target_viable.append(technique)
            elif not_exhausted and (not blockers_clear or not prereqs_met):
                # Log why it's not viable for debugging
                pass

        if not target_viable:
            return await self._handle_stuck(state)

        # Step 2: Filter by capability executability
        executable: list[Technique] = []
        queued: list[tuple[Technique, float]] = []
        gapped: list[tuple[Technique, list[str]]] = []

        for technique in target_viable:
            missing = [c for c in technique.required_capabilities
                       if not capabilities.is_owned(c)]
            if not missing:
                executable.append(technique)
            elif all(capabilities.is_acquiring(m) for m in missing):
                etas = [capabilities.eta(m) for m in missing if capabilities.eta(m) is not None]
                max_eta = max(etas) if etas else 999.0
                queued.append((technique, max_eta))
            else:
                gapped.append((technique, missing))

        # Step 3: Rank and return
        if executable:
            best = max(
                executable,
                key=lambda t: expected_value(t.name, t.category) * self.ranking_weights.get(t.category, 1.0)
            )
            logger.info(f"Planner selected: {best.name} (executable, weight={self.ranking_weights.get(best.category, 1.0):.2f})")
            return Action("execute", technique=best.name, reason="highest ranked executable technique")

        elif queued:
            return await self._while_queued(state)

        elif gapped:
            # Pick the highest priority gap to acquire
            sorted_gaps = sorted(
                gapped,
                key=lambda x: expected_value(x[0].name, x[0].category) / max(len(x[1]), 1),
                reverse=True
            )
            best_gap = sorted_gaps[0]
            target_cap = best_gap[1][0]  # acquire the first missing capability
            logger.info(f"Planner queued capability acquisition: {target_cap}")
            return Action("acquire_capability", target=target_cap,
                          reason=f"need capability for {best_gap[0].name}")

        else:
            return await self._handle_stuck(state)

    def mark_executed(self, technique_name: str, produced_new_info: bool = True, new_affordances: set[str] = None):
        """Track that a technique was recently executed."""
        self._recently_executed.add(technique_name)
        if not produced_new_info:
            self._executed_without_result.add(technique_name)
        elif technique_name in self._executed_without_result:
            self._executed_without_result.discard(technique_name)
        
        # Update exhaustion tracking
        self._update_exhaustion(technique_name, produced_new_info, new_affordances)

    async def _handle_stuck(self, state: EngagementState) -> Action:
        """
        When no technique is viable, run ModelRefiner and Hypothesizer in parallel.
        The fastest valid result wins.
        """
        logger.warning(f"Planner stuck at cycle {state.current_cycle}")

        # Run ModelRefiner and Hypothesizer in parallel
        refiner = get_refiner()
        hypothesizer = get_hypothesizer()

        refiner_task = refiner.refine(state)
        hyp_task = hypothesizer.hypothesize(state)

        # Wait for both, take the first valid result
        done, pending = await asyncio.wait(
            [asyncio.create_task(refiner_task), asyncio.create_task(hyp_task)],
            return_when=asyncio.FIRST_COMPLETED,
            timeout=30,
        )

        # Cancel pending
        for task in pending:
            task.cancel()

        # Process results
        for task in done:
            try:
                result = task.result()
                if result is None:
                    continue
                
                if isinstance(result, ConstraintDelta):
                    # ModelRefiner found something
                    if not result.is_empty():
                        state.target.absorb(result, state.current_cycle)
                        logger.info(f"ModelRefiner: {len(result.new_affordances)} new affordances")
                        return Action("model_refined", reason="inward recon produced new data")

                elif isinstance(result, dict):
                    # Hypothesizer generated a suggestion
                    action_type = result.get("action_type")
                    if action_type == "execute":
                        technique = result.get("technique")
                        logger.info(f"Hypothesizer suggested: {technique}")
                        return Action("execute", technique=technique,
                                       reason=result.get("reason", "LLM hypothesis"))

            except Exception as e:
                logger.debug(f"Stuck handler task failed: {e}")

        # If both produced nothing, run heuristic fallback
        fallback = hypothesizer._heuristic_fallback(state)
        if fallback:
            action_type = fallback.get("action_type")
            if action_type == "execute":
                logger.info(f"Heuristic fallback: {fallback.get('technique')}")
                return Action("execute", technique=fallback.get("technique"),
                               reason=fallback.get("reason", "heuristic fallback"))

        return Action("stuck", reason="all escape hatches exhausted")

    async def _while_queued(self, state: EngagementState) -> Action:
        """When techniques are queued waiting for capabilities."""
        logger.info("Techniques queued waiting for capability acquisition")
        # For Wave 2: try hypothesizer while waiting
        hypothesizer = get_hypothesizer()
        result = await hypothesizer.hypothesize(state)
        if result and result.get("action_type") == "execute":
            return Action("execute", technique=result["technique"],
                           reason=result.get("reason", "hypothesis while queued"))
        return Action("stuck", reason="techniques queued, capabilities in acquisition")
