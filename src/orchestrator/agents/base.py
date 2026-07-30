import asyncio, logging, time, uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from orchestrator.events import EventBus, event_bus

logger = logging.getLogger("agent_base")


class GoalType(str, Enum):
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POSTEX = "postex"
    LATERAL = "lateral"
    CREDENTIAL = "credential"
    EXFIL = "exfil"
    PHISH = "phish"
    REPORT = "report"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ToolDef:
    name: str
    description: str
    parameters: dict = field(default_factory=dict)


@dataclass
class Finding:
    agent: str
    goal_type: GoalType
    target: str
    description: str
    severity: str = "info"
    evidence: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "goal_type": self.goal_type.value,
            "target": self.target,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence[:500],
            "timestamp": self.timestamp,
        }


@dataclass
class Task:
    id: str
    goal_type: GoalType
    target: str
    agent_name: str
    status: TaskStatus = TaskStatus.PENDING
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()


@dataclass
class Thought:
    actions: list[dict]
    reasoning: str = ""


@dataclass
class AgentContext:
    engagement_id: str
    target: str
    tasks: list[Task] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    iteration: int = 0
    consecutive_failures: int = 0


class BaseAgent:
    name: str = ""
    system_prompt: str = ""
    tools: list[ToolDef] = []
    max_consecutive_failures: int = 3
    max_iterations: int = 50
    heartbeat_interval: float = 5.0

    def __init__(self, bus: Optional[EventBus] = None):
        self.bus = bus or event_bus
        self._task_id_counter = 0

    def _new_task_id(self) -> str:
        self._task_id_counter += 1
        return f"{self.name}-{self._task_id_counter}-{uuid.uuid4().hex[:6]}"

    async def think(self, task: Task, context: AgentContext, system_override: Optional[str] = None) -> Thought:
        raise NotImplementedError("Subclasses must implement think()")

    async def execute(self, action: dict) -> list[Finding]:
        raise NotImplementedError("Subclasses must implement execute()")

    def should_terminate(self, context: AgentContext) -> bool:
        return context.iteration >= self.max_iterations

    async def run(self, task: Task, context: AgentContext, system_override: Optional[str] = None) -> Task:
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        context.iteration = 0
        context.consecutive_failures = 0
        logger.info(f"[{self.name}] Starting task {task.id} ({task.goal_type.value} @ {task.target})")

        while context.iteration < self.max_iterations:
            context.iteration += 1

            await self.bus.publish("agent", "heartbeat", {
                "agent": self.name,
                "task_id": task.id,
                "iteration": context.iteration,
                "timestamp": time.time(),
            })

            try:
                thought = await self.think(task, context, system_override)
            except Exception as e:
                logger.warning(f"[{self.name}] think() failed: {e}")
                context.consecutive_failures += 1
                if context.consecutive_failures >= self.max_consecutive_failures:
                    task.status = TaskStatus.FAILED
                    task.error = f"Max consecutive failures ({self.max_consecutive_failures})"
                    break
                await asyncio.sleep(1)
                continue

            if not thought.actions:
                context.consecutive_failures += 1
                if context.consecutive_failures >= self.max_consecutive_failures:
                    task.status = TaskStatus.FAILED
                    task.error = "No actions produced"
                    break
                await asyncio.sleep(1)
                continue

            context.consecutive_failures = 0

            for action in thought.actions:
                try:
                    findings = await self.execute(action)
                    task.findings.extend(findings)
                    context.findings.extend(findings)
                    for f in findings:
                        await self.bus.publish("agent", "finding", f.to_dict())
                except Exception as e:
                    logger.warning(f"[{self.name}] execute({action.get('tool','?')}) failed: {e}")
                    await self.bus.publish("agent", "error", {
                        "agent": self.name, "task_id": task.id,
                        "action": action, "error": str(e),
                    })

            await self.bus.publish("agent", "progress", {
                "agent": self.name, "task_id": task.id,
                "iteration": context.iteration,
                "findings_count": len(task.findings),
                "timestamp": time.time(),
            })

            if self.should_terminate(context):
                break

            await asyncio.sleep(0.5)

        if task.status != TaskStatus.FAILED:
            task.status = TaskStatus.DONE
        task.completed_at = time.time()
        logger.info(f"[{self.name}] Task {task.id} finished: {task.status.value} "
                     f"({len(task.findings)} findings)")
        return task
