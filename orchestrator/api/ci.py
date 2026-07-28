import asyncio, logging, os, time, uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from orchestrator.auth import require_scope
from orchestrator.audit_trail import record_event
from orchestrator.engagement_queue import get_queue
from orchestrator.engagement_queue import EngagementQueue
from orchestrator.modes.autonomous import handle as autonomous_handle
from orchestrator.scope import default_scope
from orchestrator.webhook import deliver as deliver_webhook

logger = logging.getLogger("ci_api")

router = APIRouter(prefix="/v1/ci", tags=["ci"])

PHASES = ["recon", "scan", "exploit", "postex", "lateral", "credential", "exfil", "phish"]


class EngageRequest(BaseModel):
    target: str
    phases: Optional[list[str]] = None
    persona: Optional[str] = None
    no_proxy: bool = False
    webhook_url: Optional[str] = None
    priority: Optional[int] = Field(default=0, ge=0, le=10)


class EngageResponse(BaseModel):
    id: str
    target: str
    status: str
    estimate_seconds: Optional[int] = None


class ScanRequest(BaseModel):
    target: str
    persona: Optional[str] = None
    no_proxy: bool = False
    ports: Optional[str] = None


class ReportFormat(str):
    JSON = "json"
    SARIF = "sarif"
    JUNIT = "junit"


@router.post("/engage", response_model=EngageResponse)
async def start_engage(
    req: EngageRequest,
    auth=Depends(require_scope("engagements:rw")),
):
    if not default_scope.check(req.target):
        raise HTTPException(
            status_code=403,
            detail=f"Target {req.target} is not in allowed scope. "
                   f"Allowed: domains={default_scope.domains}, "
                   f"ip_ranges={default_scope.ip_ranges}",
        )

    phases = req.phases or PHASES[:]
    for p in phases:
        if p not in PHASES:
            raise HTTPException(status_code=400, detail=f"Unknown phase: {p}")

    persona = req.persona or (default_scope.persona if default_scope.persona else "")

    queue = get_queue()
    eng_id = queue.enqueue(req.target, phases, persona=persona, webhook_url=req.webhook_url or "")

    record_event(action="engage_start", target=req.target, phase="ci_api", verdict="queued", metadata={
        "eng_id": eng_id, "persona": persona, "phases": phases, "webhook": bool(req.webhook_url),
    })

    return EngageResponse(
        id=eng_id,
        target=req.target,
        status="queued",
        estimate_seconds=len(phases) * 120,
    )


@router.get("/engage/{eng_id}")
async def engage_status(
    eng_id: str,
    auth=Depends(require_scope("engagements:r")),
):
    queue = get_queue()
    eng = queue.get(eng_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    eng_dict = {
        "id": eng.id,
        "target": eng.target,
        "status": eng.status,
        "current_phase": eng.current_phase,
        "phases_completed": eng.phases_completed,
        "findings_count": eng.findings_count,
        "error": eng.error,
        "created_at": eng.created_at,
        "updated_at": eng.updated_at,
    }
    return eng_dict


@router.get("/report/{eng_id}")
async def get_report(
    eng_id: str,
    format: str = Query("json", pattern="^(json|sarif|junit)$"),
    auth=Depends(require_scope("findings:r")),
):
    queue = get_queue()
    eng = queue.get(eng_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if eng.status not in ("complete", "failed"):
        raise HTTPException(status_code=400, detail=f"Engagement still in status: {eng.status}")

    result = eng.result or {}
    phases = result.get("phases", {})
    all_findings = result.get("total_findings", 0)
    analytics = result.get("analytics", {})

    if format == "json":
        return {
            "id": eng_id,
            "target": eng.target,
            "status": eng.status,
            "phases": phases,
            "total_findings": all_findings,
            "analytics": analytics,
            "generated_at": datetime.utcnow().isoformat(),
        }
    elif format == "sarif":
        return _to_sarif(eng_id, eng, phases)
    elif format == "junit":
        return _to_junit(eng_id, eng, phases)
    return result


@router.post("/scan")
async def quick_scan(
    req: ScanRequest,
    auth=Depends(require_scope("engagements:rw")),
):
    if not default_scope.check(req.target):
        raise HTTPException(
            status_code=403,
            detail=f"Target {req.target} is not in allowed scope",
        )

    persona = req.persona or (default_scope.persona if default_scope.persona else "")

    phases = ["recon", "scan"]
    result = await autonomous_handle(
        req.target,
        phases=phases,
        no_proxy=req.no_proxy,
        persona=persona,
    )

    record_event(action="quick_scan", target=req.target, phase="ci_api",
                 verdict="completed",
                 metadata={"persona": persona, "no_proxy": req.no_proxy,
                           "findings": result.get("total_findings", 0)})
    return result


class AgentEngageRequest(BaseModel):
    target: str
    objective: Optional[str] = "compromise"
    persona: Optional[str] = None
    phases: Optional[list[str]] = None


@router.post("/agent-engage")
async def agent_engage(
    req: AgentEngageRequest,
    auth=Depends(require_scope("engagements:rw")),
):
    if not default_scope.check(req.target):
        raise HTTPException(
            status_code=403,
            detail=f"Target {req.target} is not in allowed scope",
        )

    persona = req.persona or (default_scope.persona if default_scope.persona else "")

    from orchestrator.agents.engage import run_agent_engage
    result = await run_agent_engage(
        target=req.target,
        objective=req.objective,
        persona=persona,
        phases=req.phases,
    )

    record_event(action="agent_engage", target=req.target, phase="ci_api",
                 verdict="completed",
                 metadata={"persona": persona, "phases": req.phases, "elapsed": result.get("elapsed_seconds"),
                           "findings": result.get("total_findings", 0)})
    return result


@router.get("/health")
async def health():
    queue = get_queue()
    return {
        "status": "ok",
        "service": "raphael-ci",
        "version": "2.0.0",
        "engagements": queue.stats(),
        "timestamp": time.time(),
    }


def _to_sarif(eng_id: str, eng: "Engagement", phases: dict) -> dict:
    results = []
    for phase_name, phase_data in phases.items():
        for f in phase_data.get("findings", []):
            results.append({
                "ruleId": f.get("type", phase_name),
                "level": "error" if f.get("severity", "").lower() in ("critical", "high") else "warning",
                "message": {"text": f.get("description", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": eng.target},
                        "region": {"snippet": {"text": f.get("evidence", "")[:200]}},
                    }
                }],
            })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Raphael", "version": "2.0.0"}},
            "results": results,
        }],
    }


def _to_junit(eng_id: str, eng: "Engagement", phases: dict) -> dict:
    test_cases = []
    failures = 0
    for phase_name, phase_data in phases.items():
        passed = phase_data.get("success", False)
        findings = phase_data.get("findings", [])
        test_cases.append({
            "name": phase_name,
            "classname": f"raphael.{eng_id}",
            "time": phase_data.get("latency", 0),
            "failure": None if passed else {
                "message": phase_data.get("error", "Phase failed"),
                "type": "PhaseError",
            },
        })
        if not passed:
            failures += 1

    return {
        "testsuite": {
            "name": f"raphael.engagement.{eng_id}",
            "tests": len(test_cases),
            "failures": failures,
            "errors": 0,
            "timestamp": datetime.utcnow().isoformat(),
            "testcase": test_cases,
        }
    }
