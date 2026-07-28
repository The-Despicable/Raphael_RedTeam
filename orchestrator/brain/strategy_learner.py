import random
import logging
from typing import Any

logger = logging.getLogger("strategy_learner")


class StrategyLearner:
    def __init__(self) -> None:
        self.q_table: dict[str, dict[str, float]] = {}
        self.default_phases = [
            "harvest", "recon", "scan", "exploit", "postex",
            "lateral", "credential", "exfil", "phish",
        ]

    def get_best_strategy(self, mode: str, findings: list[Any]) -> list[str] | None:
        if mode == "none":
            return None

        if not self.q_table:
            # No historical data yet — return defaults
            return self.default_phases.copy()

        # Score each phase based on Q-table: higher success Q-value is better,
        # high failure Q-value is penalized. Unknown phases get neutral score.
        scored = []
        for phase in self.default_phases:
            q_success = self.q_table.get(phase, {}).get("success", 0.0)
            q_fail = self.q_table.get(phase, {}).get("fail", 0.0)
            # Score: success Q minus penalty for failure Q
            # Default 0.5 for unseen phases (neutral, slightly optimistic)
            score = q_success - (q_fail * 0.5) if phase in self.q_table else 0.5
            scored.append((score, phase))

        # Sort by score descending (highest expected success first)
        scored.sort(key=lambda x: x[0], reverse=True)

        # Optionally filter out phases with very low scores
        if findings and scored:
            best_score = scored[0][0]
            # Only exclude phases that are significantly worse than the best
            filtered = [phase for score, phase in scored if score >= best_score - 1.0]
            if filtered:
                return filtered

        return [phase for score, phase in scored]

    def record_outcome(
        self, success: bool, findings: list[Any],
        phase: str, latency: float, timeout: bool = False, breaker: bool = False,
    ) -> None:
        state = phase
        action = "success" if success else "fail"
        if state not in self.q_table:
            self.q_table[state] = {}
        old_q = self.q_table[state].get(action, 0.0)
        reward = 1.0 if success else -0.5
        if timeout:
            reward -= 0.3
        if breaker:
            reward -= 0.5
        alpha = 0.1
        self.q_table[state][action] = old_q + alpha * (reward - old_q)
        logger.debug(
            f"record_outcome phase={phase} success={success} "
            f"latency={latency:.1f}s q[{state}][{action}]={self.q_table[state][action]:.3f}"
        )


_learner: StrategyLearner | None = None


def get_strategy_learner() -> StrategyLearner:
    global _learner
    if _learner is None:
        _learner = StrategyLearner()
    return _learner
