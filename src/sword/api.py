import asyncio, json, sys, os, logging
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

@app.get("/sword/health")
async def health():
    tools = {}
    for name in ["nmap", "nuclei", "subfinder", "whatweb"]:
        p = os.popen(f"which {name} 2>/dev/null")
        tools[name] = bool(p.read().strip())
        p.close()
    return {"status": "ok", "tools": tools}

@app.post("/sword/report")
async def generate_report(data: dict):
    report = SwordReport(data)
    md = report.generate_markdown()
    html = report.generate_html()
    return {"markdown": md, "html": html}
