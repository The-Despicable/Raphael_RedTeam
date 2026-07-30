import asyncio, json, logging, time, uuid
from typing import Optional

from orchestrator.agents.base import (
    BaseAgent, GoalType, Task, TaskStatus, AgentContext, Finding, ToolDef,
)
from orchestrator.agents.goal_tree import (
    GoalTree, GoalNode, GoalValidator, recon_sweep,
)
from orchestrator.agents.memory import AgentMemory
from orchestrator.agents.stealth import StealthController
from orchestrator.agents.supervisor import AgentSupervisor
from orchestrator.events import EventBus, event_bus
from orchestrator.providers import call_model, resolve_persona_override


def _check_hitl_orchestrator(goal_type: GoalType, target: str) -> bool:
    """Orchestrator-level HITL gate for high-risk goals."""
    import os
    if os.getenv("RAPHAEL_HITL_BYPASS"):
        return True
    if goal_type in (GoalType.EXPLOIT, GoalType.POSTEX, GoalType.LATERAL, GoalType.EXFIL):
        print(f"\n⚠ HITL GATE — {goal_type.value} phase against {target}")
        print("  Proceed? [y/N] ", end="", flush=True)
        try:
            return input().strip().lower() == "y"
        except (EOFError, KeyboardInterrupt):
            return False
    return True

logger = logging.getLogger("orchestrator_agent")

GOAL_DECOMPOSE_PROMPT = (
    "You are a red team lead planning an engagement. Your job is to decompose the objective "
    "into a structured goal tree. Each node must have:\n"
    "  - type: one of recon, scan, exploit, postex, lateral, credential, exfil, phish, report\n"
    "  - target: a specific host, domain, or CIDR range\n"
    "  - description: what to accomplish\n\n"
    "Output ONLY valid JSON with this structure:\n"
    '{"goals": [{"type": "recon", "target": "...", "description": "..."}, ...]}\n\n'
    "Rules:\n"
    "  - First goal must be recon\n"
    "  - Each subsequent goal should build on previous results\n"
    "  - Max 8 goals total\n"
    "  - Be specific about targets (hostnames, IPs, CIDRs)\n"
    "  - Do NOT include destructive actions (rm -rf, format, mkfs, dd)\n"
    "  - If you cannot decompose, return {\"fallback\": true}"
)


class OrchestratorAgent(BaseAgent):
    name: str = "orchestrator"
    system_prompt: str = GOAL_DECOMPOSE_PROMPT
    max_iterations: int = 200
    max_consecutive_failures: int = 3

    def __init__(self, bus: Optional[EventBus] = None, supervisor: Optional[AgentSupervisor] = None,
                 persona: str = "", memory: Optional[AgentMemory] = None,
                 stealth: Optional[StealthController] = None):
        super().__init__(bus)
        self.supervisor = supervisor or AgentSupervisor(bus=self.bus)
        self.memory = memory or AgentMemory()
        self.stealth = stealth or StealthController()
        self.persona = persona
        self._system_override = resolve_persona_override(persona) if persona else None
        self._active_tasks: dict[str, Task] = {}
        self._goal_tree: Optional[GoalTree] = None
        self._agents: dict[str, BaseAgent] = {}

    def register_agent(self, goal_type: GoalType, agent: BaseAgent):
        self._agents[goal_type.value] = agent

    async def decompose(self, objective: str, target: str, persona: str = "") -> GoalTree:
        if persona and not self._system_override:
            self._system_override = resolve_persona_override(persona)
            self.persona = persona

        messages = [{"role": "user", "content": json.dumps({
            "objective": objective,
            "target": target,
            "persona": persona or "default",
        })}]

        llm_output = await call_model("auto", messages, max_tokens=1024,
                                      temperature=0.3, system_override=self._system_override)

        tree = self._parse_goal_tree(llm_output, target)
        self._goal_tree = tree
        return tree

    def _parse_goal_tree(self, llm_output: str, target: str) -> GoalTree:
        try:
            data = json.loads(llm_output)
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"LLM output not valid JSON, using fallback recon sweep")
            return recon_sweep(target)

        if data.get("fallback"):
            logger.info("LLM requested fallback, using recon sweep")
            return recon_sweep(target)

        goals = data.get("goals", [])
        if not goals:
            logger.warning("No goals in LLM output, using fallback recon sweep")
            return recon_sweep(target)

        validator = GoalValidator()
        root = GoalNode(type=GoalType.RECON, target=target, description=f"Engagement against {target}")
        root.status = TaskStatus.DONE

        for g in goals:
            try:
                goal_type = GoalType(g["type"])
            except (ValueError, KeyError):
                logger.warning(f"Skipping invalid goal type: {g.get('type')}")
                continue

            node = GoalNode(
                type=goal_type,
                target=g.get("target", target),
                description=g.get("description", f"{goal_type.value} phase"),
            )

            valid, msg = validator.validate_node(node)
            if not valid:
                logger.warning(f"Goal validation failed: {msg} — using fallback")
                return recon_sweep(target)

            root.add_child(node)

        return GoalTree(root=root)

    async def tick(self, context: AgentContext) -> list[Task]:
        if not self._goal_tree:
            return []

        completed_tasks = []
        for leaf in self._goal_tree.leaves():
            if leaf.status == TaskStatus.PENDING:
                agent = self._agents.get(leaf.type.value)
                if not agent:
                    logger.warning(f"No agent registered for {leaf.type.value}, marking failed")
                    leaf.status = TaskStatus.FAILED
                    leaf.error = f"No agent for {leaf.type.value}"
                    continue

                if not _check_hitl_orchestrator(leaf.type, leaf.target):
                    logger.info(f"Orchestrator HITL rejected {leaf.type.value} against {leaf.target}")
                    leaf.status = TaskStatus.CANCELLED
                    leaf.error = "Rejected by HITL"
                    continue

                task = Task(
                    id=self._new_task_id(),
                    goal_type=leaf.type,
                    target=leaf.target,
                    agent_name=agent.name,
                )
                self._active_tasks[task.id] = task
                leaf.status = TaskStatus.RUNNING
                context.tasks.append(task)

                result = await agent.run(task, context, system_override=self._system_override)
                leaf.status = result.status
                leaf.findings = [f.to_dict() for f in result.findings]
                if result.status == TaskStatus.FAILED:
                    leaf.error = result.error

                for f in result.findings:
                    self.memory.store_finding(f)

                await self.bus.publish("orchestrator", "task_complete", {
                    "task_id": task.id,
                    "goal_type": leaf.type.value,
                    "status": leaf.status.value,
                    "findings_count": len(result.findings),
                })

                if result.status == TaskStatus.DONE:
                    completed_tasks.append(task)

                del self._active_tasks[task.id]

        return completed_tasks

    async def run(self, task: Task, context: AgentContext,
                  system_override: Optional[str] = None) -> Task:
        await self.decompose(
            objective=task.description or "compromise",
            target=task.target,
            persona=self.persona,
        )
        completed = await self.tick(context)
        task.findings = [Finding(
            agent="orchestrator",
            goal_type=GoalType.REPORT,
            target=task.target,
            description=json.dumps(self._goal_tree.to_dict() if self._goal_tree else {}),
        )]
        task.status = TaskStatus.DONE if not any(
            n.status == TaskStatus.FAILED for n in (self._goal_tree.all_nodes() if self._goal_tree else [])
        ) else TaskStatus.FAILED
        return task
