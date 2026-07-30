"""ParallelRecon — runs independent recon techniques concurrently, merges deltas."""
from __future__ import annotations
import asyncio
import logging
from typing import List, Set, Tuple

from raphael.models.target_model import ConstraintDelta, DomainState
from raphael.models.engagement_state import EngagementState
from raphael.techniques import TECHNIQUE_REGISTRY
from raphael.executor.executor import Executor

logger = logging.getLogger("raphael.parallel_recon")


def merge_deltas(deltas: List[ConstraintDelta]) -> ConstraintDelta:
    """Merge multiple deltas into one, deduplicating by domain."""
    merged = ConstraintDelta()
    for d in deltas:
        merged.new_affordances.update(d.new_affordances)
        merged.new_constraints.update(d.new_constraints)
        merged.resolved_unknowns.update(d.resolved_unknowns)
        merged.new_unknowns.update(d.new_unknowns)
    return merged


def find_independent_recon(affordances: Set[str], constraints: Set[str]) -> List[str]:
    """Return names of recon techniques whose prerequisites are met and blockers absent."""
    candidates = []
    for name, tech in TECHNIQUE_REGISTRY.items():
        if tech.type != "recon":
            continue
        prereqs_met = all(p in affordances for p in tech.prerequisites)
        blockers_active = any(b in constraints for b in tech.blockers)
        if prereqs_met and not blockers_active:
            candidates.append(name)
    return candidates


class ParallelRecon:
    """Fires all available recon techniques concurrently on first cycle."""

    def __init__(self, executor: Executor):
        self._executor = executor

    async def run_batch(self, state: EngagementState) -> ConstraintDelta:
        net = state.target.domains.get("network")
        if not net:
            return ConstraintDelta.empty()

        techniques = find_independent_recon(net.affordances, net.constraints)
        if not techniques:
            return ConstraintDelta.empty()

        logger.info(f"ParallelRecon: running {len(techniques)} techniques concurrently: {techniques}")

        results = await asyncio.gather(
            *[self._executor.execute(state, t) for t in techniques],
            return_exceptions=True
        )

        deltas = []
        for t, r in zip(techniques, results):
            if isinstance(r, Exception):
                logger.warning(f"ParallelRecon: {t} failed: {r}")
                continue
            delta, produced = r
            if produced:
                deltas.append(delta)

        merged = merge_deltas(deltas)
        if not merged.is_empty():
            logger.info(
                f"ParallelRecon: merged {len(merged.new_affordances)} affordances, "
                f"{len(merged.new_constraints)} constraints"
            )
            state.target.absorb(merged, state.current_cycle)

        return merged
