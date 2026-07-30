"""Agent-based engagement entry point — used by REPL and CI API."""

import asyncio, json, logging, time
from typing import Optional

from orchestrator.agents.base import (
    GoalType, Task, TaskStatus, AgentContext, Finding,
)
from orchestrator.agents.memory import AgentMemory
from orchestrator.agents.orchestrator import OrchestratorAgent
from orchestrator.agents.recon import ReconAgent
from orchestrator.agents.scan import ScanAgent
from orchestrator.agents.exploit import ExploitAgent
from orchestrator.agents.postex import PostExAgent
from orchestrator.agents.stealth import StealthController
from orchestrator.agents.supervisor import AgentSupervisor
from orchestrator.events import EventBus, event_bus

logger = logging.getLogger("agent_engage")


def build_orchestrator(
    bus: Optional[EventBus] = None,
    persona: str = "",
    memory: Optional[AgentMemory] = None,
    stealth: Optional[StealthController] = None,
) -> OrchestratorAgent:
    """Create an OrchestratorAgent with all 4 specialist agents registered."""
    bus = bus or event_bus
    memory = memory or AgentMemory()
    stealth = stealth or StealthController()
    supervisor = AgentSupervisor(bus=bus)

    orch = OrchestratorAgent(bus=bus, supervisor=supervisor, persona=persona,
                             memory=memory, stealth=stealth)
    orch.register_agent(GoalType.RECON, ReconAgent(bus=bus, persona=persona))
    orch.register_agent(GoalType.SCAN, ScanAgent(bus=bus, persona=persona))
    orch.register_agent(GoalType.EXPLOIT, ExploitAgent(bus=bus, persona=persona))
    orch.register_agent(GoalType.POSTEX, PostExAgent(bus=bus, persona=persona))

    return orch


async def run_agent_engage(target: str, objective: str = "compromise",
                           persona: str = "", phases: Optional[list[str]] = None) -> dict:
    """Run a full multi-agent engagement against target. Returns structured results."""
    t0 = time.time()

    bus = EventBus()
    bus.start()
    await asyncio.sleep(0.1)

    orch = build_orchestrator(bus=bus, persona=persona)

    if phases:
        from orchestrator.agents.goal_tree import GoalTree, GoalNode
        phase_set = set(phases)
        root = GoalNode(type=GoalType.RECON, target=target,
                        description=f"Phase-limited engagement against {target}",
                        status=TaskStatus.DONE)
        for gt in GoalType:
            if gt == GoalType.REPORT:
                continue
            if gt.value in phase_set:
                root.add_child(GoalNode(type=gt, target=target, description=f"{gt.value} phase"))
        tree = GoalTree(root=root)
        orch._goal_tree = tree
    else:
        tree = await orch.decompose(objective, target, persona=persona)

    ctx = AgentContext(engagement_id=tree.engagement_id, target=target)
    completed = await orch.tick(ctx)

    elapsed = time.time() - t0
    findings_list = []
    for t in completed:
        for f in t.findings:
            findings_list.append(f.to_dict())

    bus.stop()

    return {
        "target": target,
        "objective": objective,
        "persona": persona,
        "goal_tree": tree.to_dict(),
        "tasks_completed": len(completed),
        "total_findings": len(findings_list),
        "findings": findings_list[:100],
        "memory_stats": orch.memory.stats(),
        "stealth_stats": orch.stealth.stats(target),
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": time.time(),
    }
