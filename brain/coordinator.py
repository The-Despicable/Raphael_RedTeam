"""Per-task coordinator: planner -> execute -> reflect loop.

Each task runs as an asyncio task under a global semaphore (concurrency cap ~2).
The loop:
  1. Plan a sequence of Actions (via LLM reasoning_chain / strategy helpers).
  2. For each Action: policy gate -> execute via ToolsService -> record findings
     & evidence -> reflect -> contradiction check -> checkpoint.
  3. Honor pause/resume/abort and manual approve_step.

Concurrency-safety notes (hardened after review):
  - The semaphore slot is RELEASED while a task blocks on a manual pause or an
    approval gate, so paused tasks can never starve out the whole worker pool.
  - Terminal tasks are evicted from the in-memory registry (no leak) and are
    read back from SQLite afterwards.
  - `resume` on a task that only exists in the DB (e.g. recovered after a
    restart) rehydrates it from its persisted plan and re-spawns it.
  - A step whose approval times out is SKIPPED, never executed.

The coordinator never raises out of its task: failures are recorded as findings
and step statuses. Optional subsystems are skipped silently when unavailable.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import Settings, get_settings
from .db import BrainDB
from .evidence_service import EvidenceService
from .llm_service import LLMService
from .tools_service import ToolsService

log = logging.getLogger("brain.coordinator")

# Task states that no longer accept control actions.
TERMINAL_STATES = {"completed", "failed", "aborted"}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@dataclass
class Action:
    step_id: str
    name: str
    tool: Optional[str] = None
    args: List[str] = field(default_factory=list)
    target: Optional[str] = None
    status: str = "pending"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    result_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "tool": self.tool,
            "args": self.args,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result_summary": self.result_summary,
        }


@dataclass
class Task:
    task_id: str
    target: str
    mode: str
    goal: Optional[str]
    constraints: Dict[str, Any]
    budget_limit: Optional[int]
    state: str = "pending"
    current_step: Optional[str] = None
    plan: List[Action] = field(default_factory=list)
    findings_count: int = 0
    budget_used: int = 0
    risk: Optional[str] = None
    engagement_id: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    resumed: bool = False  # True when rehydrated from the DB after a restart
    # Control signals. Pause and approval use SEPARATE events so that approving
    # a step cannot accidentally un-pause a manually paused task and vice versa.
    _pause_event: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _abort_event: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _approval_event: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _approval_step: Optional[str] = None  # step awaiting approval
    _budget_note_recorded: bool = False

    def __post_init__(self) -> None:
        # Start unpaused.
        self._pause_event.set()

    def to_view(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "state": self.state,
            "step": self.current_step,
            "mode": self.mode,
            "target": self.target,
            "goal": self.goal,
            "plan": [a.to_dict() for a in self.plan],
            "findings_count": self.findings_count,
            "risk": self.risk,
            "budget_used": self.budget_used,
            "budget_limit": self.budget_limit,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class TaskRegistry:
    """In-memory registry of live Task objects + their asyncio tasks.

    Entries are evicted automatically once the background task finishes and the
    task state is terminal, so long-running processes do not leak memory.
    """

    def __init__(self) -> None:
        self.tasks: Dict[str, Task] = {}
        self.bg_tasks: Dict[str, asyncio.Task] = {}

    def add(self, task: Task, bg_task: asyncio.Task) -> None:
        self.tasks[task.task_id] = task
        self.bg_tasks[task.task_id] = bg_task
        bg_task.add_done_callback(lambda _t, tid=task.task_id: self.evict_if_done(tid))

    def get(self, task_id: str) -> Optional[Task]:
        return self.tasks.get(task_id)

    def has(self, task_id: str) -> bool:
        return task_id in self.tasks

    def remove(self, task_id: str) -> None:
        self.tasks.pop(task_id, None)
        bg = self.bg_tasks.pop(task_id, None)
        if bg and not bg.done():
            bg.cancel()

    def all(self) -> List[Task]:
        return list(self.tasks.values())

    def evict_if_done(self, task_id: str) -> None:
        task = self.tasks.get(task_id)
        bg = self.bg_tasks.get(task_id)
        if task is None or bg is None:
            return
        # Consume the exception (if any) so asyncio does not log
        # "exception was never retrieved" warnings for cancelled tasks.
        if bg.done():
            try:
                bg.exception()
            except (asyncio.CancelledError, asyncio.InvalidStateError):
                pass
        if bg.done() and task.state in TERMINAL_STATES:
            self.tasks.pop(task_id, None)
            self.bg_tasks.pop(task_id, None)
            log.debug("evicted terminal task %s from registry", task_id)


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------


class Coordinator:
    """Coordinates per-task planning & execution. One instance per process."""

    def __init__(
        self,
        db: BrainDB,
        tools: ToolsService,
        llm: LLMService,
        evidence: EvidenceService,
        settings: Optional[Settings] = None,
    ):
        self.db = db
        self.tools = tools
        self.llm = llm
        self.evidence = evidence
        self.settings = settings or get_settings()
        self.registry = TaskRegistry()
        self._semaphore = asyncio.Semaphore(self.settings.task_concurrency)

    # --------------------------------------------------------- lifecycle
    async def create_task(
        self,
        target: str,
        mode: str,
        goal: Optional[str],
        constraints: Optional[Dict[str, Any]] = None,
        budget: Optional[int] = None,
        engagement_id: Optional[str] = None,
    ) -> Task:
        task_id = _new_id("t")
        task = Task(
            task_id=task_id,
            target=target,
            mode=mode,
            goal=goal or "Compromise target within scope",
            constraints=constraints or {},
            budget_limit=budget,
            engagement_id=engagement_id,
            created_at=_utcnow_iso(),
            updated_at=_utcnow_iso(),
        )
        await self.db.insert_task(
            {
                "task_id": task_id,
                "engagement_id": engagement_id,
                "target": target,
                "goal": task.goal,
                "mode": mode,
                "state": "pending",
                "step": None,
                "constraints": task.constraints,
                "budget_limit": budget,
                "budget_used": 0,
                "risk": None,
            }
        )
        await self.db.audit("coordinator", "task.create", task_id, f"target={target} mode={mode}")
        return task

    def spawn(self, task: Task, resumed: bool = False) -> None:
        if resumed:
            task.resumed = True
        bg = asyncio.create_task(self._run_task(task))
        self.registry.add(task, bg)

    async def control(self, task_id: str, action: str, step_id: Optional[str] = None) -> Dict[str, Any]:
        task = self.registry.get(task_id)
        resuming_from_db = False

        if task is None:
            row = await self.db.get_task(task_id)
            if row is None:
                return {"task_id": task_id, "action": action, "accepted": False, "message": "task not found"}
            if row["state"] in TERMINAL_STATES:
                return {
                    "task_id": task_id, "action": action, "accepted": False,
                    "message": f"task already finished ({row['state']})",
                }
            if action == "resume" and row["state"] == "paused":
                # Rehydrate a task that only exists in the DB (e.g. recovered
                # after a restart) so the operator can actually resume it.
                task = await self._rehydrate(task_id)
                if task is None:
                    return {"task_id": task_id, "action": action, "accepted": False, "message": "task could not be rehydrated"}
                resuming_from_db = True
            else:
                return {"task_id": task_id, "action": action, "accepted": False, "message": "task not running"}

        # Guard: never accept control actions on a terminal in-memory task.
        if task.state in TERMINAL_STATES:
            return {
                "task_id": task_id, "action": action, "accepted": False,
                "message": f"task already finished ({task.state})",
            }

        if action == "pause":
            task._pause_event.clear()
            task.state = "paused"
            await self.db.update_task_state(task_id, "paused")
            await self.db.audit("coordinator", "task.pause", task_id)
            return {"task_id": task_id, "action": action, "accepted": True, "message": "paused"}

        if action == "resume":
            task._pause_event.set()
            task.state = "running"
            await self.db.update_task_state(task_id, "running")
            await self.db.audit("coordinator", "task.resume", task_id)
            if resuming_from_db:
                self.spawn(task, resumed=True)
                return {"task_id": task_id, "action": action, "accepted": True, "message": "rehydrated and resumed"}
            return {"task_id": task_id, "action": action, "accepted": True, "message": "resumed"}

        if action == "abort":
            task._abort_event.set()
            # Unblock any gate the task is sitting in so it notices the abort.
            task._pause_event.set()
            task._approval_event.set()
            task.state = "aborted"
            await self.db.update_task_state(task_id, "aborted")
            await self.db.audit("coordinator", "task.abort", task_id)
            return {"task_id": task_id, "action": action, "accepted": True, "message": "aborted"}

        if action == "approve_step":
            if not task._approval_step:
                return {"task_id": task_id, "action": action, "accepted": False, "message": "no step awaiting approval"}
            if step_id and step_id != task._approval_step:
                return {
                    "task_id": task_id, "action": action, "accepted": False,
                    "message": f"step {step_id} is not awaiting approval (expected {task._approval_step})",
                }
            task._approval_step = None
            task._approval_event.set()
            await self.db.audit("coordinator", "step.approve", step_id or task_id)
            return {"task_id": task_id, "action": action, "accepted": True, "message": f"approved {step_id or task.current_step}"}

        return {"task_id": task_id, "action": action, "accepted": False, "message": "unknown action"}

    # ------------------------------------------------------- main loop
    async def _run_task(self, task: Task) -> None:
        sem = self._semaphore
        try:
            await sem.acquire()
            try:
                task.state = "running"
                await self.db.update_task_state(task.task_id, "running")

                # 1) Plan (resumed tasks reuse the plan loaded from the DB).
                if task.resumed:
                    plan = task.plan
                else:
                    plan = await self._plan(task)
                    task.plan = plan
                    for action in plan:
                        await self.db.insert_step(
                            {
                                "step_id": action.step_id,
                                "task_id": task.task_id,
                                "name": action.name,
                                "tool": action.tool,
                                "status": "pending",
                                "args": action.args,
                            }
                        )

                # 2) Execute each action
                for action in plan:
                    if task._abort_event.is_set():
                        if action.status not in ("done", "failed", "skipped"):
                            action.status = "skipped"
                            await self.db.update_step(action.step_id, "skipped", "aborted")
                        continue
                    # Already settled by a previous run (resumed tasks).
                    if action.status in ("done", "failed", "skipped"):
                        continue

                    # Pause / approval gate; releases the semaphore slot while
                    # the task blocks so paused tasks cannot starve the pool.
                    proceed = await self._await_approval(task, action, sem)
                    if not proceed:
                        if action.status != "skipped":
                            action.status = "skipped"
                            await self.db.update_step(action.step_id, "skipped", "gate rejected")
                        continue

                    # Token budget gate (spec: honor budget).
                    if self._budget_exhausted(task):
                        await self._record_budget_exhaustion(task)
                        action.status = "skipped"
                        await self.db.update_step(action.step_id, "skipped", "token budget exhausted")
                        continue

                    await self._execute_action(task, action)

                    # Checkpoint after each step.
                    await self.db.insert_checkpoint(
                        label=f"after-{action.step_id}",
                        task_id=task.task_id,
                        note=action.result_summary or "",
                        payload={"step": action.to_dict()},
                    )

                # 3) Final state
                if not task._abort_event.is_set():
                    task.state = "completed"
                    await self.db.update_task_state(task.task_id, "completed")
                else:
                    task.state = "aborted"
                    await self.db.update_task_state(task.task_id, "aborted")
            finally:
                sem.release()
        except asyncio.CancelledError:
            log.info("task %s cancelled", task.task_id)
            task.state = "aborted"
            await self.db.update_task_state(task.task_id, "aborted")
            raise
        except Exception as e:  # noqa: BLE001
            log.exception("task %s crashed: %s", task.task_id, e)
            task.state = "failed"
            await self.db.update_task_state(task.task_id, "failed")
            await self.db.insert_finding(
                {
                    "task_id": task.task_id,
                    "target": task.target,
                    "severity": "high",
                    "title": "Coordinator failure",
                    "description": f"Task {task.task_id} failed: {e}",
                    "confidence": 1.0,
                }
            )

    # ----------------------------------------------------------- planning
    async def _plan(self, task: Task) -> List[Action]:
        profile = {
            "mode": task.mode,
            "goal": task.goal,
            "constraints": task.constraints,
            "budget": task.budget_limit,
        }

        # Try orchestrator.brain.strategy.build_strategy for plan items.
        plan_items: List[str] = []
        try:
            if self.llm.available:
                before = self.llm.total_tokens_used
                plan_items = await self.llm.build_strategy(task.target, profile, [])
                task.budget_used += self.llm.total_tokens_used - before
        except Exception as e:  # noqa: BLE001
            log.warning("strategy build failed: %s", str(e)[:120])
            plan_items = []

        # Fallback plan based on mode.
        if not plan_items:
            plan_items = self._default_plan(task)

        actions: List[Action] = []
        for i, item in enumerate(plan_items, start=1):
            sid = f"{task.task_id}-s{i:02d}"
            tool, args = self._parse_plan_item(item)
            actions.append(
                Action(
                    step_id=sid,
                    name=item,
                    tool=tool,
                    args=args,
                    target=task.target,
                )
            )
        return actions

    def _default_plan(self, task: Task) -> List[str]:
        mode = task.mode
        if mode == "recon":
            return [
                "Resolve target scope",
                "nmap -sV version scan",
                "httpx probe web ports",
                "Build target profile",
                "Summarize attack surface",
            ]
        if mode == "exploit":
            return [
                "Identify candidate vulnerabilities",
                "nuclei template scan",
                "Validate one candidate exploit",
                "Record compromise level",
            ]
        if mode == "post":
            return [
                "Enumerate post-exploitation primitives",
                "Collect credentials/artifacts",
                "Map lateral movement paths",
            ]
        if mode == "passive":
            return [
                "Passive OSINT gather",
                "Build evidence graph",
                "Generate hypotheses",
            ]
        return [
            "Recon target",
            "Profile services",
            "Generate findings",
            "Build strategy",
            "Finalize",
        ]

    def _parse_plan_item(self, item: str) -> tuple[Optional[str], List[str]]:
        s = item.strip()
        # Heuristics: items like "nmap -sV version scan" -> tool=nmap args=[-sV]
        known = self.tools.capabilities()
        first = s.split()[0].lower() if s else ""
        if first in known:
            parts = s.split()
            return first, parts[1:]
        return None, []

    async def _await_approval(self, task: Task, action: Action, sem: asyncio.Semaphore) -> bool:
        """Approval + pause gate. Returns True when the step may proceed.

        While blocking (approval wait or manual pause) the semaphore slot is
        released and re-acquired on wake-up, so a gated task does not consume
        one of the N execution slots. A step whose approval times out is
        skipped (returns False) - it is NEVER executed.
        """
        decision = self.tools.broker.check(
            "autonomous-brain",
            action.tool or action.name,
            "execute",
            {"target": task.target},
        )
        if decision["decision"] == "require_approval":
            task._approval_step = action.step_id
            task.state = "awaiting_approval"
            await self.db.update_task_state(task.task_id, "awaiting_approval", step=action.step_id)
            await self.db.audit(
                "coordinator", "step.await_approval", action.step_id,
                detail=str(decision),
            )
            sem.release()
            try:
                approval_wait = asyncio.create_task(task._approval_event.wait())
                abort_wait = asyncio.create_task(task._abort_event.wait())
                done, pending = await asyncio.wait(
                    {approval_wait, abort_wait},
                    timeout=self.settings.approval_timeout_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()
                if task._abort_event.is_set():
                    return False
                if approval_wait in done:
                    task._approval_step = None
                else:
                    log.warning("approval timed out for %s; skipping", action.step_id)
                    task._approval_step = None
                    task.state = "running"
                    await self.db.update_task_state(task.task_id, "running")
                    action.status = "skipped"
                    await self.db.update_step(action.step_id, "skipped", "approval timeout")
                    return False
            finally:
                await sem.acquire()
            task._approval_step = None
            task.state = "running"
            await self.db.update_task_state(task.task_id, "running")

        # Manual pause gate (only blocks if actually paused). The state is
        # re-synced here so a pause issued before the task's first action
        # (while state was still overwritten to "running" at startup) is
        # still reported correctly.
        if not task._pause_event.is_set():
            sem.release()
            task.state = "paused"
            try:
                await self.db.update_task_state(task.task_id, "paused", step=action.step_id)
            except Exception:  # noqa: BLE001
                pass
            try:
                await task._pause_event.wait()
            finally:
                await sem.acquire()
            task.state = "running"
            try:
                await self.db.update_task_state(task.task_id, "running", step=action.step_id)
            except Exception:  # noqa: BLE001
                pass

        if task._abort_event.is_set():
            return False
        return True

    # -------------------------------------------------------- execution
    async def _execute_action(self, task: Task, action: Action) -> None:
        action.status = "running"
        action.started_at = _utcnow_iso()
        task.current_step = action.step_id
        await self.db.update_step(action.step_id, "running")
        await self.db.update_task_state(task.task_id, task.state, step=action.step_id)

        try:
            if action.tool:
                result = await self.tools.execute(
                    tool=action.tool,
                    args=action.args,
                    target=action.target,
                    agent=task.task_id,
                )
                summary = (result.get("stdout") or "")[:240]
                action.result_summary = summary
                if result.get("exit_code", 0) != 0:
                    action.status = "failed"
                    await self._record_failure(task, action, result)
                else:
                    action.status = "done"
                    await self._record_evidence(task, action, result)
            else:
                # Non-tool step: reasoning via LLM; attribute tokens to the task.
                before = self.llm.total_tokens_used
                resp = await self.llm.reasoning_chain(
                    {"step": action.name, "target": task.target},
                    task.goal or "progress",
                )
                used = self.llm.total_tokens_used - before
                if used:
                    task.budget_used += used
                    await self.db.update_task_state(
                        task.task_id, task.state, budget_used=task.budget_used
                    )
                action.result_summary = resp[:240]
                action.status = "done"

            action.finished_at = _utcnow_iso()
            await self.db.update_step(
                action.step_id,
                action.status,
                result_summary=action.result_summary,
                finished_at=action.finished_at,
            )
            await self.db.update_task_state(
                task.task_id, task.state, step=action.step_id
            )
        except Exception as e:  # noqa: BLE001
            log.exception("action %s failed: %s", action.step_id, e)
            action.status = "failed"
            action.result_summary = f"error: {e}"
            action.finished_at = _utcnow_iso()
            await self.db.update_step(
                action.step_id, "failed", result_summary=action.result_summary
            )

    # ----------------------------------------------------------- budget
    def _budget_exhausted(self, task: Task) -> bool:
        """Per-task limit when set, else the global MAX_SPEND_TOKENS cap.
        Only enforced when RAPHAEL_COST_CONTROL is enabled."""
        if not self.settings.raphael_cost_control:
            return False
        limit = (
            task.budget_limit
            if task.budget_limit is not None
            else self.settings.max_spend_tokens
        )
        return task.budget_used >= limit

    async def _record_budget_exhaustion(self, task: Task) -> None:
        if task._budget_note_recorded:
            return
        task._budget_note_recorded = True
        await self.db.insert_finding(
            {
                "task_id": task.task_id,
                "target": task.target,
                "severity": "medium",
                "title": "Token budget exhausted",
                "description": (
                    f"Task {task.task_id} hit its token budget "
                    f"(used={task.budget_used}, limit={task.budget_limit or self.settings.max_spend_tokens}); "
                    "remaining steps were skipped."
                ),
                "confidence": 1.0,
            }
        )
        await self.db.audit("coordinator", "task.budget_exhausted", task.task_id)

    async def _record_evidence(self, task: Task, action: Action, result: Dict[str, Any]) -> None:
        # Add a finding when stdout looks interesting.
        stdout = result.get("stdout", "") or ""
        if stdout:
            await self.evidence.ingest(
                task_id=task.task_id,
                nodes=[
                    {
                        "id": action.step_id,
                        "kind": "tool_output",
                        "attributes": {
                            "tool": action.tool,
                            "exit_code": result.get("exit_code"),
                            "stdout": stdout[:512],
                        },
                        "source": "coordinator",
                        "confidence": 0.8,
                    }
                ],
                edges=[
                    {
                        "src": task.target,
                        "dst": action.step_id,
                        "relation": "yielded_by",
                        "attributes": {"tool": action.tool},
                    }
                ],
            )
            await self.db.insert_finding(
                {
                    "task_id": task.task_id,
                    "target": task.target,
                    "severity": "info",
                    "title": f"{action.tool} output",
                    "description": stdout[:512],
                    "evidence_ref": action.step_id,
                    "confidence": 0.7,
                }
            )
            task.findings_count += 1

    async def _record_failure(self, task: Task, action: Action, result: Dict[str, Any]) -> None:
        await self.db.insert_finding(
            {
                "task_id": task.task_id,
                "target": task.target,
                "severity": "medium",
                "title": f"{action.tool} failed",
                "description": (result.get("stderr") or result.get("stdout") or "")[:512],
                "evidence_ref": action.step_id,
                "confidence": 0.9,
            }
        )
        task.findings_count += 1

    # ----------------------------------------------------------- recovery
    async def recover_pending(self) -> int:
        """On startup, mark any tasks left in 'running' state as 'paused'
        so the operator can resume them explicitly. Returns count recovered."""
        rows = await self.db.list_tasks(state="running")
        for r in rows:
            await self.db.update_task_state(r["task_id"], "paused")
            await self.db.audit("coordinator", "task.recover", r["task_id"])
        return len(rows)

    async def _rehydrate(self, task_id: str) -> Optional[Task]:
        """Rebuild an in-memory Task from its DB row + steps so a task that
        only exists after a restart (state=paused) can be resumed. Steps that
        already reached a terminal status keep it; the rest are re-executed."""
        row = await self.db.get_task(task_id)
        if not row or row["state"] != "paused":
            return None
        try:
            constraints = json.loads(row.get("constraints_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            constraints = {}
        steps = await self.db.list_steps(task_id)
        plan = [
            Action(
                step_id=s["step_id"],
                name=s["name"],
                tool=s.get("tool"),
                args=s.get("args") or [],
                status=s.get("status") or "pending",
                started_at=s.get("started_at"),
                finished_at=s.get("finished_at"),
                result_summary=s.get("result_summary"),
            )
            for s in steps
        ]
        task = Task(
            task_id=row["task_id"],
            target=row["target"],
            mode=row.get("mode") or "full",
            goal=row.get("goal"),
            constraints=constraints,
            budget_limit=row.get("budget_limit"),
            state="paused",
            engagement_id=row.get("engagement_id"),
            created_at=row.get("created_at") or "",
            updated_at=row.get("updated_at") or "",
        )
        task.budget_used = row.get("budget_used") or 0
        task.plan = plan
        task.resumed = True
        return task

    async def shutdown(self) -> None:
        """Called during process shutdown BEFORE the DB is closed: abort all
        live tasks, unblock every gate they may be waiting in, and wait for
        their state to be flushed to SQLite."""
        tasks = self.registry.all()
        for t in tasks:
            t._abort_event.set()
            t._pause_event.set()
            t._approval_event.set()
        bg = [b for b in self.registry.bg_tasks.values() if not b.done()]
        if bg:
            try:
                await asyncio.wait(bg, timeout=10)
            except Exception as e:  # noqa: BLE001
                log.warning("shutdown wait interrupted: %s", str(e)[:120])

    # ----------------------------------------------------------- queries
    async def get_task_view(self, task_id: str) -> Optional[Dict[str, Any]]:
        task = self.registry.get(task_id)
        if task is not None:
            view = task.to_view()
            # Enrich with DB-backed findings count.
            view["findings_count"] = await self.db.count_findings(task_id)
            return view
        # Not in registry - load from DB.
        row = await self.db.get_task(task_id)
        if not row:
            return None
        steps = await self.db.list_steps(task_id)
        findings_count = await self.db.count_findings(task_id)
        try:
            constraints_parsed = json.loads(row.get("constraints_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            constraints_parsed = {}
        return {
            "task_id": row["task_id"],
            "state": row["state"],
            "step": row.get("step"),
            "mode": row.get("mode"),
            "target": row["target"],
            "goal": row.get("goal"),
            "plan": [
                {
                    "step_id": s["step_id"],
                    "name": s["name"],
                    "tool": s.get("tool"),
                    "args": s.get("args") or [],
                    "status": s["status"],
                    "started_at": s.get("started_at"),
                    "finished_at": s.get("finished_at"),
                    "result_summary": s.get("result_summary"),
                }
                for s in steps
            ],
            "findings_count": findings_count,
            "risk": row.get("risk"),
            "budget_used": row.get("budget_used", 0),
            "budget_limit": row.get("budget_limit"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }

    async def list_tasks(
        self, state: Optional[str] = None, target: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        rows = await self.db.list_tasks(state=state, target=target, limit=limit)
        # Single GROUP BY query for all findings counts (no N+1).
        counts = await self.db.count_findings_bulk([r["task_id"] for r in rows])
        out = []
        for r in rows:
            out.append(
                {
                    "task_id": r["task_id"],
                    "state": r["state"],
                    "step": r.get("step"),
                    "mode": r.get("mode"),
                    "target": r["target"],
                    "goal": r.get("goal"),
                    "plan": [],
                    "findings_count": counts.get(r["task_id"], 0),
                    "risk": r.get("risk"),
                    "budget_used": r.get("budget_used", 0),
                    "budget_limit": r.get("budget_limit"),
                    "created_at": r.get("created_at"),
                    "updated_at": r.get("updated_at"),
                }
            )
        return out
