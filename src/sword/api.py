import asyncio, json, sys, os, logging
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

sys.path.insert(0, "/app")

from sword.pipeline import run_sword
from sword.report import SwordReport

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SWORD-API] %(levelname)s %(message)s")
log = logging.getLogger("sword-api")

app = FastAPI(title="Sword API", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class SwordRequest(BaseModel):
    target: str
    phases: Optional[list] = None
    config: Optional[dict] = None

class SwordStatus(BaseModel):
    task_id: str
    target: str
    status: str

_tasks = {}

@app.get("/")
async def root():
    return {"service": "Sword Offensive Pipeline", "version": "2.0", "phases": ["recon", "scan", "exploit", "postex", "exfil", "phish"]}

@app.post("/sword/run")
async def sword_run(req: SwordRequest):
    api_keys = {}
    for k in ["SHODAN_API_KEY", "CENSYS_API_KEY", "SPIDERFOOT_API_KEY"]:
        v = os.environ.get(k)
        if v:
            api_keys[k.lower().replace("_api_key", "")] = v
    try:
        result = await run_sword(req.target, api_keys, req.config or {}, req.phases)
        report = SwordReport(result)
        paths = report.save()
        result["_report_files"] = paths
        return result
    except Exception as e:
        log.error("sword run failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
@app.get("/sword/health")
async def health():
    tools = {}
    for name in ["nmap", "nuclei", "subfinder", "whatweb"]:
        p = os.popen(f"which {name} 2>/dev/null")
        tools[name] = bool(p.read().strip())
        p.close()
    return {"status": "ok", "service": "sword", "version": "2.0", "tools": tools}

@app.post("/sword/report")
async def generate_report(data: dict):
    report = SwordReport(data)
    md = report.generate_markdown()
    html = report.generate_html()
    return {"markdown": md, "html": html}


# ── Cloak broker mediation ──────────────────────────────────────
CLOAK_SERVICE_URL = os.getenv("CLOAK_SERVICE_URL", os.getenv("CLOAK_URL", "http://127.0.0.1:3401"))
CLOAK_FALLBACK_URLS = [CLOAK_SERVICE_URL, "http://127.0.0.1:3401"]


async def _cloak_base() -> str:
    # Prefer the configured/internal URL; fall back to host-published URL.
    for base in CLOAK_FALLBACK_URLS:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{base.rstrip('/')}/health")
            if r.status_code == 200:
                return base.rstrip("/")
        except Exception:
            continue
    return CLOAK_SERVICE_URL.rstrip("/")


class CloakMediateRequest(BaseModel):
    url: Optional[str] = None
    target: Optional[str] = None
    viewport: Optional[dict] = None
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    wait: int = 3


async def _mediate_cloak(payload: CloakMediateRequest) -> dict:
    base = await _cloak_base()
    url = payload.url or payload.target or "about:blank"
    body = {
        "url": url,
        "viewport": payload.viewport,
        "user_agent": payload.user_agent,
        "proxy": payload.proxy,
        "wait": payload.wait,
    }
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(f"{base}/launch", json=body)
        if r.status_code >= 400:
            # try alternate alias
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(f"{base}/cloak", json=body)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text[:2000]}
        return {
            "status": "ok" if r.status_code < 400 else "error",
            "mediator": "sword",
            "upstream": base,
            "upstream_status": r.status_code,
            "cloak_service": data,
        }
    except Exception as e:
        log.error("cloak mediation failed: %s", e)
        raise HTTPException(status_code=502, detail=f"cloak mediation failed: {e}")


@app.get("/broker/status")
async def broker_status():
    base = await _cloak_base()
    cloak_health = None
    upstream_status = 0
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{base}/health")
        upstream_status = r.status_code
        if r.status_code == 200:
            cloak_health = r.json()
    except Exception as e:
        cloak_health = {"error": str(e)}
    return {
        "status": "mediating" if upstream_status == 200 else "degraded",
        "mediator": "sword",
        "upstream_cloak": base,
        "upstream_status": upstream_status,
        "cloak_service": cloak_health,
        "mediation": "sword -> cloak-service broker wrapper",
    }


@app.post("/broker")
async def broker_root(payload: CloakMediateRequest = CloakMediateRequest()):
    return await _mediate_cloak(payload)


@app.post("/broker/cloak")
async def broker_cloak(payload: CloakMediateRequest = CloakMediateRequest()):
    return await _mediate_cloak(payload)


@app.post("/broker/mediate")
async def broker_mediate(payload: CloakMediateRequest = CloakMediateRequest()):
    return await _mediate_cloak(payload)


@app.post("/cloak")
async def cloak_root(payload: CloakMediateRequest = CloakMediateRequest()):
    return await _mediate_cloak(payload)


@app.post("/cloak/launch")
async def cloak_launch(payload: CloakMediateRequest = CloakMediateRequest()):
    return await _mediate_cloak(payload)


# backward-compat alias under /sword prefix is handled by router-less mounts above
