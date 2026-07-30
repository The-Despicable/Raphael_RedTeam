"""FastAPI router for case collection pipeline endpoints."""

import json, logging
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional

from case_store import CaseStore, classify_type, generate_params_sig, extract_url_path, extract_query_params

logger = logging.getLogger("case_api")
router = APIRouter(prefix="/cases", tags=["cases"])

DATA_DIR = Path("/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

def _get_store() -> CaseStore:
    return CaseStore(str(DATA_DIR / "cases.db"))


class CaseInput(BaseModel):
    method: str = "GET"
    url: str
    url_path: Optional[str] = None
    query_params: Optional[str] = None
    body_params: Optional[str] = None
    path_params: Optional[str] = None
    cookie_params: Optional[str] = None
    headers: Optional[str] = None
    body: str = ""
    content_type: str = ""
    content_length: int = 0
    response_status: int = 0
    response_headers: Optional[str] = None
    response_size: int = 0
    response_snippet: str = ""
    type: Optional[str] = None
    source: str = "unknown"
    params_key_sig: Optional[str] = None


@router.post("/ingest")
async def ingest_case(case: CaseInput):
    """Ingest a single case into the queue. Auto-classifies and generates dedup signature."""
    url_path = case.url_path or extract_url_path(case.url)
    case_type = case.type or classify_type(case.method, url_path, case.content_type, case.body)
    sig = case.params_key_sig or generate_params_sig(case.url, case.query_params, case.body_params)

    store = _get_store()
    case_dict = case.model_dump()
    case_dict["url_path"] = url_path
    case_dict["type"] = case_type
    case_dict["params_key_sig"] = sig
    if not case_dict.get("query_params") and case.method == "GET":
        case_dict["query_params"] = extract_query_params(case.url)

    row_id = store.insert(case_dict)
    store.close()
    return {"id": row_id, "type": case_type, "dedup": bool(row_id)}


@router.post("/ingest-batch")
async def ingest_batch(cases: list[CaseInput]):
    """Ingest multiple cases at once."""
    store = _get_store()
    count = 0
    for case in cases:
        url_path = case.url_path or extract_url_path(case.url)
        case_type = case.type or classify_type(case.method, url_path, case.content_type, case.body)
        sig = case.params_key_sig or generate_params_sig(case.url, case.query_params, case.body_params)
        case_dict = case.model_dump()
        case_dict["url_path"] = url_path
        case_dict["type"] = case_type
        case_dict["params_key_sig"] = sig
        if not case_dict.get("query_params") and case.method == "GET":
            case_dict["query_params"] = extract_query_params(case.url)
        if store.insert(case_dict):
            count += 1
    store.close()
    return {"ingested": count}


@router.get("/fetch")
async def fetch_cases(
    type: str = Query(...),
    limit: int = Query(5, ge=1, le=50),
    agent: str = Query(...),
    stage: Optional[str] = Query(None),
):
    """Fetch cases for an agent. Stage-aware dispatch."""
    store = _get_store()
    rows = store.fetch(type, limit, agent, stage=stage)
    store.close()
    return {"cases": rows, "count": len(rows)}


@router.post("/done")
async def mark_done(
    ids: list[int] = Query(...),
    stage: Optional[str] = Query(None),
):
    store = _get_store()
    store.mark_done(ids, stage=stage)
    store.close()
    return {"status": "ok"}


@router.post("/error")
async def mark_error(ids: list[int] = Query(...)):
    store = _get_store()
    store.mark_error(ids)
    store.close()
    return {"status": "ok"}


@router.post("/set-stage")
async def set_stage(ids: list[int] = Query(...), stage: str = Query(...)):
    store = _get_store()
    store.set_stage(ids, stage)
    store.close()
    return {"status": "ok"}


@router.post("/reset-stale")
async def reset_stale(minutes: int = Query(10)):
    store = _get_store()
    count = store.reset_stale(minutes)
    store.close()
    return {"reset": count}


@router.post("/retry-errors")
async def retry_errors(max_retries: int = Query(2)):
    store = _get_store()
    count = store.retry_errors(max_retries)
    store.close()
    return {"retried": count}


@router.get("/stats")
async def get_stats():
    store = _get_store()
    s = store.stats()
    store.close()
    return s


@router.get("/stats-by-stage")
async def get_stats_by_stage():
    store = _get_store()
    rows = store.stats_by_stage()
    store.close()
    return {"stages": rows}
