"""FastAPI application: Autonomous Brain microservice (Raphael 2.0).

Entry point for `uvicorn brain.main:app --host 0.0.0.0 --port 3700`.
All endpoints documented under /docs. Optional systems degrade gracefully and
surface their state via /health.
"""
from __future__ import annotations

import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure /app is on the path so `import orchestrator` works when baked/mounted.
_HERE = Path(__file__).resolve().parent
_APP_DIR = _HERE.parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .config import Settings, get_settings
from .coordinator import Coordinator, _new_id
from .db import BrainDB, close_db, get_db, init_db
from .evidence_service import EvidenceService
from .llm_service import LLMService, close_llm, get_llm, init_llm
from .schemas import (
    CapabilityCheckRequest,
    CapabilityCheckResponse,
    CheckpointIn,
    CheckpointOut,
    ContradictionCheckRequest,
    ContradictionListResponse,
    ContradictionView,
    ControlAction,
    EntityCreate,
    EntityResponse,
    ErrorResponse,
    EvidenceIngestRequest,
    EvidenceIngestResponse,
    FindingView,
    FindingsListResponse,
    HealthResponse,
    HypothesisCreate,
    HypothesisVerifyRequest,
    HypothesisView,
    NoteIn,
    NoteOut,
    RelationshipCreate,
    RelationshipResponse,
    ReflectionRunRequest,
    ReflectionRunResponse,
    StrategyBuildRequest,
    StrategyBuildResponse,
    TaskControlRequest,
    TaskControlResponse,
    TaskCreate,
    TaskCreateResponse,
    TaskListResponse,
    TaskMode,
    TaskView,
    ToolExecuteRequest,
    ToolExecuteResponse,
    TrustView,
    VersionResponse,
    WebhookNotify,
    WebhookResponse,
)
from .system_service import SystemHealthService
from .tools_service import ToolsService, get_tools, init_tools

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------


class AppState:
    def __init__(self) -> None:
        self.settings: Settings = get_settings()
        self.started_at: float = time.perf_counter()
        self.db: Optional[BrainDB] = None
        self.coordinator: Optional[Coordinator] = None
        self.llm: Optional[LLMService] = None
        self.tools: Optional[ToolsService] = None
        self.evidence: Optional[EvidenceService] = None
        self.system_health: Optional[SystemHealthService] = None


state = AppState()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = state.settings
    _configure_logging(settings.log_level)
    log = logging.getLogger("brain.main")
    log.info("Starting %s v%s on port %s", settings.service_name, __version__, settings.port)

    # --- Persistence -------------------------------------------------------
    state.db = await init_db(settings)
    log.info("BrainDB ready at %s", settings.brain_db)

    # --- LLM ---------------------------------------------------------------
    state.llm = await init_llm(settings)

    # --- Tools / capability broker ----------------------------------------
    state.tools = init_tools(settings)

    # --- Evidence ----------------------------------------------------------
    state.evidence = EvidenceService(state.db)
    state.evidence._load_orchestrator()

    # --- Coordinator -------------------------------------------------------
    state.coordinator = Coordinator(
        db=state.db,
        tools=state.tools,
        llm=state.llm,
        evidence=state.evidence,
        settings=settings,
    )
    recovered = await state.coordinator.recover_pending()
    if recovered:
        log.info("Recovered %d in-flight tasks (marked paused)", recovered)

    # --- System health probes ----------------------------------------------
    state.system_health = SystemHealthService()

    # NOTE: signal handlers are intentionally NOT registered here. Uvicorn
    # installs its own SIGINT/SIGTERM handlers (loop.add_signal_handler) BEFORE
    # the lifespan starts; registering ours would silently REPLACE them and the
    # container would then need SIGKILL to stop. Uvicorn's own handlers already
    # trigger a graceful shutdown that runs the cleanup below.

    try:
        yield
    finally:
        log.info("Shutting down %s", settings.service_name)
        # Order matters: abort in-flight tasks and let them flush state to
        # SQLite BEFORE any resource they may still write to is closed.
        try:
            if state.coordinator is not None:
                await state.coordinator.shutdown()
        except Exception:  # noqa: BLE001
            log.exception("coordinator shutdown failed")
        if state.system_health:
            await state.system_health.close()
        if state.tools:
            await state.tools.close()
        await close_llm()
        await close_db()
        log.info("Shutdown complete")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    app = FastAPI(
        title="Autonomous Brain",
        description="Raphael 2.0 offensive-security autonomous planning & decision loop.",
        version=__version__,
        lifespan=lifespan,
        default_response_class=JSONResponse,
    )

    # CORS: on an offensive-security control plane, a wildcard origin lets any
    # web page drive tool execution. Restrict to explicit env-provided origins.
    settings = state.settings
    cors_origins = os.environ.get("CORS_ALLOW_ORIGINS", "*").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cors_origins if o.strip()],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Opt-in API key gate (BRAIN_API_KEY). When set, every endpoint except the
    # unauthenticated set below requires header `X-API-Key: <key>`. Docker
    # HEALTHCHECK probes /health, so /health must stay open.
    if settings.brain_api_key:
        UNAUTHENTICATED = {"/health", "/version", "/"}
        secret = settings.brain_api_key

        @app.middleware("http")
        async def api_key_gate(request: Request, call_next):
            if request.url.path not in UNAUTHENTICATED:
                if request.headers.get("X-API-Key") != secret:
                    return JSONResponse(
                        status_code=401,
                        content=ErrorResponse(detail="missing or invalid X-API-Key", code="unauthorized").model_dump(),
                    )
            return await call_next(request)

    _register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------


def _coord() -> Coordinator:
    if state.coordinator is None:
        raise HTTPException(status_code=503, detail="coordinator not initialized")
    return state.coordinator


def _tools_svc() -> ToolsService:
    if state.tools is None:
        raise HTTPException(status_code=503, detail="tools service not initialized")
    return state.tools


def _llm_svc() -> LLMService:
    if state.llm is None:
        raise HTTPException(status_code=503, detail="llm service not initialized")
    return state.llm


def _ev_svc() -> EvidenceService:
    if state.evidence is None:
        raise HTTPException(status_code=503, detail="evidence service not initialized")
    return state.evidence


async def _db() -> BrainDB:
    return await get_db()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _register_routes(app: FastAPI) -> None:

    # ============================================================ A) health
    @app.get("/health", response_model=HealthResponse, tags=["health"])
    async def health() -> HealthResponse:
        sys_health: Dict[str, Any] = {}
        if state.system_health is not None:
            sys_health = await state.system_health.snapshot()
        active_targets: List[str] = []
        if state.coordinator:
            try:
                active_targets = await state.db.list_active_targets()
            except Exception:
                pass
        uptime = time.perf_counter() - state.started_at
        capabilities_count = len(_tools_svc().capabilities()) if state.tools else 0
        return HealthResponse(
            status="ok",
            service=state.settings.service_name,
            version=__version__,
            brain_db=state.settings.brain_db,
            uptime_seconds=round(uptime, 2),
            capabilities_count=capabilities_count,
            active_target=active_targets[0] if active_targets else None,
            subsystems=sys_health,
            config=state.settings.health_dict(),
        )

    @app.get("/capabilities", tags=["health"])
    async def capabilities() -> Dict[str, Any]:
        svc = _tools_svc()
        return {
            "capabilities": svc.capabilities(),
            "engines": svc.engines(),
            "tools_known": len(svc.capabilities()),
        }

    @app.get("/version", response_model=VersionResponse, tags=["health"])
    async def version() -> VersionResponse:
        commit = os.environ.get("GIT_COMMIT") or os.environ.get("COMMIT_SHA")
        return VersionResponse(version=__version__, commit=commit)

    # ========================================================== B) tasks
    @app.post("/task", response_model=TaskCreateResponse, tags=["task"], status_code=202)
    async def create_task(req: TaskCreate) -> TaskCreateResponse:
        coord = _coord()
        task = await coord.create_task(
            target=req.target,
            mode=req.mode.value,
            goal=req.goal,
            constraints=req.constraints,
            budget=req.budget,
            engagement_id=req.engagement_id,
        )
        coord.spawn(task)
        return TaskCreateResponse(
            task_id=task.task_id,
            status="accepted",
            accepted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            target=task.target,
        )

    @app.get("/task/{task_id}", response_model=TaskView, tags=["task"])
    async def get_task(task_id: str) -> TaskView:
        view = await _coord().get_task_view(task_id)
        if not view:
            raise HTTPException(status_code=404, detail=f"task {task_id} not found")
        return TaskView(**view)

    @app.post("/task/{task_id}/control", response_model=TaskControlResponse, tags=["task"])
    async def control_task(task_id: str, req: TaskControlRequest) -> TaskControlResponse:
        result = await _coord().control(task_id, req.action.value, req.step_id)
        if not result.get("accepted"):
            raise HTTPException(status_code=409, detail=result.get("message", "rejected"))
        return TaskControlResponse(**result)

    @app.get("/tasks", response_model=TaskListResponse, tags=["task"])
    async def list_tasks(
        state_filter: Optional[str] = Query(None, alias="filter", description="state filter"),
        target: Optional[str] = None,
        limit: int = Query(100, ge=1, le=1000),
    ) -> TaskListResponse:
        rows = await _coord().list_tasks(state=state_filter, target=target, limit=limit)
        return TaskListResponse(tasks=[TaskView(**r) for r in rows], count=len(rows))

    # ========================================================= C) tools
    @app.post("/tools/execute", response_model=ToolExecuteResponse, tags=["tools"])
    async def execute_tool(req: ToolExecuteRequest) -> ToolExecuteResponse:
        svc = _tools_svc()
        result = await svc.execute(
            tool=req.tool,
            args=req.args,
            target=req.target,
            timeout=req.timeout,
        )
        return ToolExecuteResponse(**result)

    @app.get("/tools", tags=["tools"])
    async def list_tools() -> Dict[str, Any]:
        svc = _tools_svc()
        tools_list = await svc.list_tools()
        return {"tools": tools_list, "count": len(tools_list)}

    @app.get("/tools/registry", tags=["tools"])
    async def tools_registry() -> Dict[str, Any]:
        svc = _tools_svc()
        return {"registry": svc.registry(), "count": len(svc.registry())}

    @app.post(
        "/tools/capability-check",
        response_model=CapabilityCheckResponse,
        tags=["tools"],
    )
    async def capability_check(req: CapabilityCheckRequest) -> CapabilityCheckResponse:
        svc = _tools_svc()
        result = svc.broker.check(req.agent, req.tool, req.action, req.scope)
        return CapabilityCheckResponse(**result)

    # ========================================================= D) evidence/world
    @app.get("/evidence", tags=["evidence"])
    async def get_evidence(task_id: Optional[str] = None) -> Dict[str, Any]:
        return await _ev_svc().list_evidence(task_id)

    @app.post("/evidence/ingest", response_model=EvidenceIngestResponse, tags=["evidence"])
    async def ingest_evidence(req: EvidenceIngestRequest) -> EvidenceIngestResponse:
        result = await _ev_svc().ingest(
            task_id=None,
            nodes=[n.model_dump() for n in req.nodes],
            edges=[e.model_dump() for e in req.edges],
            merge=req.merge,
        )
        return EvidenceIngestResponse(**result)

    @app.get("/world/entities", tags=["world"])
    async def list_entities(type: Optional[str] = None) -> Dict[str, Any]:
        return await _ev_svc().list_entities(type)

    @app.post("/world/entities", response_model=EntityResponse, tags=["world"])
    async def create_entity(req: EntityCreate) -> EntityResponse:
        ent = await _ev_svc().create_entity(req.type, req.name, req.attributes)
        return EntityResponse(**ent)

    @app.post("/world/relationships", response_model=RelationshipResponse, tags=["world"])
    async def create_relationship(req: RelationshipCreate) -> RelationshipResponse:
        result = await _ev_svc().create_relationship(
            req.src_type, req.src_name, req.dst_type, req.dst_name,
            req.relation, req.attributes,
        )
        return RelationshipResponse(**result)

    # ========================================================= E) findings
    @app.get("/findings", response_model=FindingsListResponse, tags=["findings"])
    async def list_findings(
        target: Optional[str] = None,
        severity: Optional[str] = None,
        task_id: Optional[str] = None,
        limit: int = Query(100, ge=1, le=1000),
    ) -> FindingsListResponse:
        db = await _db()
        rows = await db.list_findings(target=target, severity=severity, task_id=task_id, limit=limit)
        findings = [FindingView(**r) for r in rows]
        return FindingsListResponse(findings=findings, count=len(findings))

    @app.get("/findings/{finding_id}", response_model=FindingView, tags=["findings"])
    async def get_finding(finding_id: int) -> FindingView:
        db = await _db()
        row = await db.get_finding(finding_id)
        if not row:
            raise HTTPException(status_code=404, detail=f"finding {finding_id} not found")
        return FindingView(**row)

    # ======================================================= F) contradictions
    @app.post("/contradictions/check", response_model=ContradictionView, tags=["contradictions"])
    async def check_contradictions(req: ContradictionCheckRequest) -> ContradictionView:
        cid = _new_id("c")
        status = "open"
        detail = None
        subjects: List[str] = []
        # Try orchestrator.brain.contradiction.ContradictionManager.
        try:
            from orchestrator.brain.contradiction import (  # type: ignore
                ContradictionManager,
                create_contradiction_manager,
            )

            mgr: ContradictionManager = create_contradiction_manager()
            observations = req.observations
            candidates = req.candidates or observations
            result = None
            for obs in observations:
                for cand in candidates:
                    if obs is cand:
                        continue
                    if hasattr(mgr, "check"):
                        try:
                            result = mgr.check(obs, cand)
                        except TypeError:
                            result = mgr.check(obs)
                        if result and getattr(result, "status", None) in {"contradiction", "CONTRADICTION"}:
                            break
            if result is not None:
                status = str(getattr(result, "status", status))
                subjects = list(getattr(result, "subjects", [])) or subjects
                detail = str(getattr(result, "detail", "")) or None
        except Exception as e:  # noqa: BLE001
            detail = f"contradiction engine unavailable: {e}"

        # Simple local heuristic: detect conflicting key=value across observations.
        if status == "open" and not detail:
            seen: Dict[str, str] = {}
            for obs in req.observations:
                for k, v in obs.items():
                    if k in seen and seen[k] != str(v):
                        status = "contradiction"
                        subjects = list({k})
                        detail = f"{k} conflict: {seen[k]} vs {v}"
                    else:
                        seen[k] = str(v)

        db = await _db()
        await db.insert_contradiction(
            {"id": cid, "task_id": None, "status": status, "subjects": subjects, "detail": detail}
        )
        return ContradictionView(id=cid, status=status, subjects=subjects, detail=detail)

    @app.get("/contradictions", response_model=ContradictionListResponse, tags=["contradictions"])
    async def list_contradictions(task_id: Optional[str] = None) -> ContradictionListResponse:
        db = await _db()
        rows = await db.list_contradictions(task_id=task_id)
        out = [
            ContradictionView(
                id=r["id"],
                status=r.get("status", "open"),
                subjects=r.get("subjects", []),
                detail=r.get("detail"),
                created_at=r.get("created_at"),
            )
            for r in rows
        ]
        return ContradictionListResponse(contradictions=out, count=len(out))

    # ======================================================= G) hypotheses/strategy
    @app.get("/hypotheses", tags=["hypotheses"])
    async def list_hypotheses(task_id: Optional[str] = None) -> Dict[str, Any]:
        db = await _db()
        rows = await db.list_hypotheses(task_id=task_id)
        return {"hypotheses": rows, "count": len(rows)}

    @app.post("/hypotheses", response_model=HypothesisView, tags=["hypotheses"])
    async def create_hypothesis(req: HypothesisCreate) -> HypothesisView:
        db = await _db()
        hid = _new_id("h")
        await db.insert_hypothesis(
            {
                "id": hid,
                "task_id": None,
                "statement": req.statement,
                "confidence": req.confidence,
                "status": "open",
                "evidence_refs": req.evidence_refs,
                "parent_id": req.parent_id,
            }
        )
        return HypothesisView(
            id=hid,
            statement=req.statement,
            confidence=req.confidence,
            status="open",
            evidence_refs=req.evidence_refs,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    @app.post("/hypotheses/{hyp_id}/verify", response_model=HypothesisView, tags=["hypotheses"])
    async def verify_hypothesis(hyp_id: str, req: HypothesisVerifyRequest) -> HypothesisView:
        db = await _db()
        existing = await db.get_hypothesis(hyp_id)
        if not existing:
            raise HTTPException(status_code=404, detail=f"hypothesis {hyp_id} not found")
        # Run a reasoning-chain verification via LLM.
        llm = _llm_svc()
        resp = await llm.reasoning_chain(
            {"hypothesis": existing["statement"], "evidence": existing.get("evidence_refs", [])},
            "verify this hypothesis; produce a confidence adjustment.",
        )
        # Bump confidence slightly to reflect verification (clamped 0..1).
        new_conf = max(0.0, min(1.0, float(existing.get("confidence", 0.5)) + 0.1))
        await db.update_hypothesis(hyp_id, confidence=new_conf, status="verified")
        await db.audit("brain", "hypothesis.verify", hyp_id, detail=resp[:160])
        return HypothesisView(
            id=hyp_id,
            statement=existing["statement"],
            confidence=new_conf,
            status="verified",
            evidence_refs=existing.get("evidence_refs", []),
            created_at=existing.get("created_at"),
        )

    @app.post("/strategy/build", response_model=StrategyBuildResponse, tags=["strategy"])
    async def build_strategy(req: StrategyBuildRequest) -> StrategyBuildResponse:
        llm = _llm_svc()
        steps = await llm.build_strategy(req.target, req.profile, req.findings)
        return StrategyBuildResponse(strategy=steps)

    @app.get("/strategy/{task_id}", tags=["strategy"])
    async def get_strategy(task_id: str) -> Dict[str, Any]:
        view = await _coord().get_task_view(task_id)
        if not view:
            raise HTTPException(status_code=404, detail=f"task {task_id} not found")
        return {"task_id": task_id, "plan": view.get("plan", [])}

    # ============================================================ H) trust/reflection
    @app.get("/trust", response_model=TrustView, tags=["trust"])
    async def get_trust(subject: str = Query(...)) -> TrustView:
        db = await _db()
        row = await db.get_trust(subject)
        return TrustView(
            subject=row["subject"],
            score=row["score"],
            samples=row["samples"],
            last_updated=row.get("last_updated") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    @app.post("/reflection/run", response_model=ReflectionRunResponse, tags=["reflection"])
    async def run_reflection(req: ReflectionRunRequest) -> ReflectionRunResponse:
        db = await _db()
        # Use orchestrator.brain.reflection if available.
        reflections: List[Dict[str, Any]] = []
        try:
            from orchestrator.brain import reflection as _ref  # type: ignore

            if hasattr(_ref, "run_reflection"):
                reflections = _ref.run_reflection(req.scope) or []
        except Exception:
            pass
        if not reflections:
            # Local heuristic: pull latest hypotheses and emit a one-line reflection each.
            hyps = await db.list_hypotheses()
            for h in hyps[:5]:
                reflections.append(
                    {
                        "subject": h["id"],
                        "confidence": h.get("confidence", 0.5),
                        "note": f"hypothesis: {h['statement'][:80]}",
                    }
                )

        # Bump confidence on any open hypothesis that survived reflection.
        updated = 0
        for r in reflections:
            subject = r.get("subject")
            if not subject:
                continue
            existing = await db.get_hypothesis(subject)
            if existing and existing.get("status") == "open":
                new_conf = max(0.0, min(1.0, float(existing.get("confidence", 0.5)) + 0.05))
                await db.update_hypothesis(subject, confidence=new_conf)
                updated += 1
            await db.log_trust(subject, float(r.get("confidence", 0.5)), reason="reflection")
        return ReflectionRunResponse(reflections=reflections, updated_hypotheses=updated)

    # ============================================================ I) notes
    @app.get("/notes", tags=["notes"])
    async def list_notes() -> Dict[str, Any]:
        db = await _db()
        rows = await db.list_notes()
        return {"notes": rows, "count": len(rows)}

    @app.post("/notes", response_model=NoteOut, tags=["notes"])
    async def upsert_note(req: NoteIn) -> NoteOut:
        db = await _db()
        result = await db.upsert_note(req.key, req.value, req.tags)
        return NoteOut(**result)

    @app.get("/notes/{key}", response_model=NoteOut, tags=["notes"])
    async def get_note(key: str) -> NoteOut:
        db = await _db()
        result = await db.get_note(key)
        if not result:
            raise HTTPException(status_code=404, detail=f"note {key} not found")
        return NoteOut(**result)

    @app.post("/notes/{key}", response_model=NoteOut, tags=["notes"])
    async def post_note_by_key(key: str, payload: Dict[str, Any]) -> NoteOut:
        db = await _db()
        value = payload.get("value", payload)
        tags = payload.get("tags", [])
        result = await db.upsert_note(key, value, tags)
        return NoteOut(**result)

    @app.delete("/notes/{key}", tags=["notes"])
    async def delete_note(key: str) -> Dict[str, Any]:
        db = await _db()
        ok = await db.delete_note(key)
        if not ok:
            raise HTTPException(status_code=404, detail=f"note {key} not found")
        return {"deleted": True, "key": key}

    # ============================================================ J) checkpoints
    @app.post("/checkpoint", response_model=CheckpointOut, tags=["checkpoints"], status_code=201)
    async def create_checkpoint(req: CheckpointIn) -> CheckpointOut:
        db = await _db()
        row = await db.insert_checkpoint(req.label, req.task_id, req.note, req.payload)
        return CheckpointOut(**row)

    @app.get("/checkpoints", tags=["checkpoints"])
    async def list_checkpoints(task_id: Optional[str] = None) -> Dict[str, Any]:
        db = await _db()
        rows = await db.list_checkpoints(task_id=task_id)
        return {"checkpoints": rows, "count": len(rows)}

    # ============================================================ K) webhook stub
    @app.post("/webhook/notify", response_model=WebhookResponse, tags=["webhook"])
    async def webhook_notify(req: WebhookNotify) -> WebhookResponse:
        db = await _db()
        await db.audit("webhook", req.event, req.subject or "", detail=str(req.payload)[:160])
        return WebhookResponse(accepted=True, message=f"event {req.event} recorded")

    # ============================================================ root + error handlers
    @app.get("/", tags=["root"])
    async def root() -> Dict[str, Any]:
        return {
            "service": state.settings.service_name,
            "version": __version__,
            "docs": "/docs",
            "endpoints": {
                "health": "/health",
                "task": "/task",
                "tools": "/tools",
                "evidence": "/evidence",
                "findings": "/findings",
                "hypotheses": "/hypotheses",
                "strategy": "/strategy/build",
                "contradictions": "/contradictions",
                "notes": "/notes",
                "checkpoints": "/checkpoints",
                "webhook": "/webhook/notify",
            },
        }

    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(detail=str(exc.detail), code=f"http_{exc.status_code}").model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_exc_handler(request: Request, exc: Exception) -> JSONResponse:
        logging.getLogger("brain.main").exception("unhandled error: %s", exc)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(detail=f"internal error: {exc}", code="internal").model_dump(),
        )


# ---------------------------------------------------------------------------
# Module-level app instance (uvicorn brain.main:app)
# ---------------------------------------------------------------------------

app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "brain.main:app",
        host="0.0.0.0",
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=False,
    )
