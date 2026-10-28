"""Pydantic v2 request/response models for the Autonomous Brain REST API.

These models live at the FastAPI boundary. Internal coordinator state uses
plain dataclasses / dicts to avoid coupling business logic to pydantic.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TaskMode(str, Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    POST = "post"
    FULL = "full"
    PASSIVE = "passive"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"
    BLOCKED = "blocked"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ControlAction(str, Enum):
    PAUSE = "pause"
    RESUME = "resume"
    ABORT = "abort"
    APPROVE_STEP = "approve_step"


# ---------------------------------------------------------------------------
# Health / introspection
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str
    version: str
    brain_db: str
    uptime_seconds: float
    capabilities_count: int
    active_target: Optional[str] = None
    timestamp: str = Field(default_factory=_utcnow_iso)
    subsystems: Dict[str, Any] = Field(default_factory=dict)
    config: Dict[str, Any] = Field(default_factory=dict)


class CapabilitiesResponse(BaseModel):
    capabilities: List[str]
    engines: List[str]
    tools_known: int


class VersionResponse(BaseModel):
    version: str
    commit: Optional[str] = None


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------


class TaskCreate(BaseModel):
    target: str
    engagement_id: Optional[str] = None
    goal: Optional[str] = "Compromise target within scope"
    mode: TaskMode = TaskMode.RECON
    constraints: Optional[Dict[str, Any]] = None
    budget: Optional[int] = None  # token budget override


class TaskCreateResponse(BaseModel):
    task_id: str
    status: str
    accepted_at: str = Field(default_factory=_utcnow_iso)
    target: str


class StepView(BaseModel):
    step_id: str
    name: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    tool: Optional[str] = None
    args: Optional[List[str]] = None
    result_summary: Optional[str] = None


class TaskView(BaseModel):
    task_id: str
    state: str
    step: Optional[str] = None
    mode: str
    target: str
    goal: Optional[str] = None
    plan: List[StepView] = Field(default_factory=list)
    findings_count: int = 0
    risk: Optional[str] = None
    budget_used: int = 0
    budget_limit: Optional[int] = None
    created_at: str
    updated_at: str


class TaskControlRequest(BaseModel):
    action: ControlAction
    step_id: Optional[str] = None


class TaskControlResponse(BaseModel):
    task_id: str
    action: str
    accepted: bool
    message: str


class TaskListResponse(BaseModel):
    tasks: List[TaskView]
    count: int


# ---------------------------------------------------------------------------
# Tooling broker
# ---------------------------------------------------------------------------


class ToolExecuteRequest(BaseModel):
    tool: str
    args: List[str] = Field(default_factory=list)
    target: Optional[str] = None
    timeout: Optional[float] = Field(default=None, ge=1.0, le=3600.0)
    metadata: Optional[Dict[str, Any]] = None


class ToolExecuteResponse(BaseModel):
    tool: str
    exit_code: int
    stdout: str
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
    fallback_used: bool = False
    broker_decision: Optional[Dict[str, Any]] = None


class CapabilityCheckRequest(BaseModel):
    agent: str
    tool: str
    action: str
    scope: Optional[Dict[str, Any]] = None


class CapabilityCheckResponse(BaseModel):
    decision: str  # "allow" | "deny" | "require_approval"
    reason: Optional[str] = None
    dimensions: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Evidence / world
# ---------------------------------------------------------------------------


class EvidenceNodeIngest(BaseModel):
    id: str
    kind: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source: Optional[str] = None
    confidence: float = 1.0


class EvidenceEdgeIngest(BaseModel):
    src: str
    dst: str
    relation: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class EvidenceIngestRequest(BaseModel):
    nodes: List[EvidenceNodeIngest] = Field(default_factory=list)
    edges: List[EvidenceEdgeIngest] = Field(default_factory=list)
    merge: bool = True


class EvidenceIngestResponse(BaseModel):
    nodes_added: int
    edges_added: int
    nodes_total: int
    edges_total: int


class EntityCreate(BaseModel):
    type: str
    name: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class EntityResponse(BaseModel):
    id: str
    type: str
    name: str
    attributes: Dict[str, Any]


class RelationshipCreate(BaseModel):
    src_type: str
    src_name: str
    dst_type: str
    dst_name: str
    relation: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class RelationshipResponse(BaseModel):
    success: bool
    detail: Optional[str] = None


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class FindingView(BaseModel):
    id: Optional[int] = None
    task_id: Optional[str] = None
    target: str
    severity: str
    title: str
    description: str
    evidence_ref: Optional[str] = None
    confidence: float = 1.0
    created_at: str = Field(default_factory=_utcnow_iso)


class FindingsListResponse(BaseModel):
    findings: List[FindingView]
    count: int


# ---------------------------------------------------------------------------
# Contradictions
# ---------------------------------------------------------------------------


class ContradictionCheckRequest(BaseModel):
    observations: List[Dict[str, Any]]
    candidates: List[Dict[str, Any]] = Field(default_factory=list)


class ContradictionView(BaseModel):
    id: str
    status: str
    subjects: List[str] = Field(default_factory=list)
    detail: Optional[str] = None
    created_at: str = Field(default_factory=_utcnow_iso)


class ContradictionListResponse(BaseModel):
    contradictions: List[ContradictionView]
    count: int


# ---------------------------------------------------------------------------
# Hypothesis / strategy
# ---------------------------------------------------------------------------


class HypothesisCreate(BaseModel):
    statement: str
    confidence: float = 0.5
    parent_id: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)


class HypothesisView(BaseModel):
    id: str
    statement: str
    confidence: float
    status: str = "open"
    evidence_refs: List[str] = Field(default_factory=list)
    created_at: str


class HypothesisVerifyRequest(BaseModel):
    method: str = "default"
    extra: Optional[Dict[str, Any]] = None


class StrategyBuildRequest(BaseModel):
    target: str
    profile: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class StrategyBuildResponse(BaseModel):
    strategy: List[str]


# ---------------------------------------------------------------------------
# Trust / reflection / notes / checkpoints
# ---------------------------------------------------------------------------


class TrustView(BaseModel):
    subject: str
    score: float
    samples: int
    last_updated: str


class ReflectionRunRequest(BaseModel):
    task_id: Optional[str] = None
    scope: str = "recent"


class ReflectionRunResponse(BaseModel):
    reflections: List[Dict[str, Any]]
    updated_hypotheses: int


class NoteIn(BaseModel):
    key: str
    value: Union[str, Dict[str, Any]]
    tags: List[str] = Field(default_factory=list)


class NoteOut(BaseModel):
    key: str
    value: Union[str, Dict[str, Any]]
    tags: List[str] = Field(default_factory=list)
    updated_at: str


class CheckpointIn(BaseModel):
    label: str
    task_id: Optional[str] = None
    note: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None


class CheckpointOut(BaseModel):
    id: int
    label: str
    task_id: Optional[str] = None
    note: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    created_at: str


class WebhookNotify(BaseModel):
    event: str
    subject: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


class WebhookResponse(BaseModel):
    accepted: bool
    message: str


class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None
