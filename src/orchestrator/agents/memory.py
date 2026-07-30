import json, logging, time
from collections import defaultdict
from typing import Optional

from orchestrator.agents.base import Finding, GoalType, Task

logger = logging.getLogger("agent_memory")


class AgentMemory:
    """Shared memory across agents for a single engagement.

    Three stores:
      1. findings — all findings keyed by (target, goal_type)
      2. context — engagement-level key-value store for cross-agent data
      3. history — ordered event log per engagement
    With size caps to prevent OOM.
    """

    MAX_FINDINGS_PER_TARGET: int = 5000
    MAX_CONTEXT_ENTRIES: int = 500
    MAX_HISTORY: int = 10000

    def __init__(self):
        self._findings: dict[str, list[Finding]] = defaultdict(list)
        self._context: dict[str, dict] = defaultdict(dict)
        self._history: list[dict] = []

    def store_finding(self, finding: Finding):
        key = f"{finding.target}:{finding.goal_type.value}"
        bucket = self._findings[key]
        if len(bucket) < self.MAX_FINDINGS_PER_TARGET:
            bucket.append(finding)
        self._history.append({
            "ts": finding.timestamp,
            "type": "finding",
            "agent": finding.agent,
            "target": finding.target,
            "goal_type": finding.goal_type.value,
            "description": finding.description[:100],
        })
        if len(self._history) > self.MAX_HISTORY:
            self._history = self._history[-self.MAX_HISTORY:]

    def get_findings(self, target: str = "", goal_type: Optional[GoalType] = None,
                     limit: int = 100) -> list[Finding]:
        results = []
        for key, bucket in self._findings.items():
            if target and target not in key:
                continue
            if goal_type and goal_type.value not in key:
                continue
            results.extend(bucket)
        results.sort(key=lambda f: f.timestamp, reverse=True)
        return results[:limit]

    def get_findings_by_goal_type(self, goal_type: GoalType) -> list[Finding]:
        return self.get_findings(goal_type=goal_type)

    def get_findings_by_target(self, target: str) -> list[Finding]:
        return self.get_findings(target=target)

    def set_context(self, key: str, value, engagement_id: str = ""):
        store = self._context[engagement_id or "default"]
        if len(store) < self.MAX_CONTEXT_ENTRIES:
            store[key] = {"value": value, "ts": time.time()}
        self._history.append({
            "ts": time.time(), "type": "context", "key": key,
        })
        if len(self._history) > self.MAX_HISTORY:
            self._history = self._history[-self.MAX_HISTORY:]

    def get_context(self, key: str, engagement_id: str = ""):
        store = self._context[engagement_id or "default"]
        entry = store.get(key)
        if entry:
            return entry["value"]
        return None

    def get_history(self, limit: int = 100) -> list[dict]:
        return self._history[-limit:]

    def stats(self) -> dict:
        return {
            "findings": sum(len(v) for v in self._findings.values()),
            "context_keys": sum(len(v) for v in self._context.values()),
            "history": len(self._history),
        }
