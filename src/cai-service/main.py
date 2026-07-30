import sys
sys.path.insert(0, "/raphael")

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cai-service")

app = FastAPI(title="CAI Service", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReconRequest(BaseModel):
    target: str
    engine: str = "karma_v2"
    mode: str = "host"
    modules: str = "dnsresolve,whois,subdomains"


class ScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    rate: int = 100
    sudo: bool = False
    nuclei_templates: Optional[list] = None
    nuclei_severity: Optional[str] = None
    nuclei_rate_limit: int = 50
    whatweb_aggression: int = 1


class ExploitRequest(BaseModel):
    target: str
    url: Optional[str] = None
    ports: Optional[list] = None
    sql_level: int = 3
    sql_risk: int = 2


class DefendRequest(BaseModel):
    code: str
    filename: str = "unknown"


class ForensicRequest(BaseModel):
    target_ip: str
    domain: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None
    network: Optional[str] = None


class OracleRequest(BaseModel):
    vector: Optional[str] = None
    subtype: Optional[str] = None
    count: int = 5
    encode: Optional[str] = None


class ChatRequest(BaseModel):
    model: str = "auto"
    messages: list
    max_tokens: int = 4096
    temperature: float = 0.85
    system: Optional[str] = None


class AuditRequest(BaseModel):
    target: str
    ports: str = "1-1000"


@app.post("/agent/recon")
async def agent_recon(req: ReconRequest):
    try:
        if req.engine == "spiderfoot":
            from orchestrator.spiderfoot_wrapper import SpiderFootWrapper
            sf = SpiderFootWrapper()
            result = sf.scan(req.target, req.modules)
        else:
            from orchestrator.karma_wrapper import KarmaV2Wrapper
            kv = KarmaV2Wrapper()
            result = kv.scan(req.target, req.mode)
        log.info("recon %s %s -> %s", req.engine, req.target, result.get("status", "ok"))
        return result
    except Exception as e:
        log.error("recon error: %s", e)
        return {"error": str(e)}


@app.post("/agent/scan")
async def agent_scan(req: ScanRequest):
    try:
        from orchestrator.scanners.nmap_scanner import NmapScanner
        from orchestrator.scanners.nuclei_scanner import NucleiScanner
        from orchestrator.scanners.whatweb_scanner import WhatwebScanner

        nmap = NmapScanner()
        nuclei = NucleiScanner()
        whatweb = WhatwebScanner()

        nmap_result = nmap.scan_ports(req.target, req.ports, req.rate, req.sudo)
        nuclei_result = nuclei.scan(req.target, req.nuclei_templates, req.nuclei_severity, req.nuclei_rate_limit)
        whatweb_result = whatweb.scan(req.target, req.whatweb_aggression)

        result = {
            "target": req.target,
            "nmap": nmap_result,
            "nuclei": nuclei_result,
            "whatweb": whatweb_result,
        }
        log.info("scan %s -> %d ports", req.target, len(nmap_result.get("ports", [])))
        return result
    except Exception as e:
        log.error("scan error: %s", e)
        return {"error": str(e)}


@app.post("/agent/exploit")
async def agent_exploit(req: ExploitRequest):
    try:
        from orchestrator.exploit.pipeline import ExploitPipeline
        ep = ExploitPipeline()
        result = await ep.run(req.target, req.url, req.ports, req.sql_level, req.sql_risk)
        log.info("exploit %s -> %d vulns", req.target, result.get("summary", {}).get("vulnerabilities_found", 0))
        return result
    except Exception as e:
        log.error("exploit error: %s", e)
        return {"error": str(e)}


@app.post("/agent/defend")
async def agent_defend(req: DefendRequest):
    try:
        from orchestrator.sast.pipeline import SastPipeline
        sp = SastPipeline()
        result = await sp.scan(req.code, req.filename)
        log.info("defend %s -> %d findings", req.filename, result.get("findings_count", 0))
        return result
    except Exception as e:
        log.error("defend error: %s", e)
        return {"error": str(e)}


@app.post("/agent/forensic")
async def agent_forensic(req: ForensicRequest):
    try:
        from orchestrator.postex.pipeline import PostExploitPipeline
        pp = PostExploitPipeline()
        result = await pp.run(req.target_ip, req.domain, req.username, req.password, req.hash, req.network)
        log.info("forensic %s -> ok", req.target_ip)
        return result
    except Exception as e:
        log.error("forensic error: %s", e)
        return {"error": str(e)}


@app.post("/agent/oracle")
async def agent_oracle(req: OracleRequest):
    try:
        from orchestrator.exploit.payloads_db import PayloadsDB
        db = PayloadsDB()
        if req.vector:
            result = db.query(req.vector, req.subtype, req.count, req.encode)
        else:
            result = db.vectors()
        log.info("oracle vector=%s -> %d items", req.vector, len(result) if isinstance(result, list) else 1)
        return {"data": result}
    except Exception as e:
        log.error("oracle error: %s", e)
        return {"error": str(e)}


@app.post("/agent/chat")
async def agent_chat(req: ChatRequest):
    try:
        from orchestrator.providers import call_model
        result = await call_model(req.model, req.messages, req.max_tokens, req.temperature, req.system)
        log.info("chat model=%s -> %d chars", req.model, len(result))
        return {"response": result}
    except Exception as e:
        log.error("chat error: %s", e)
        return {"error": str(e)}


@app.post("/agent/audit")
async def agent_audit(req: AuditRequest):
    try:
        from orchestrator.scanners.nmap_scanner import NmapScanner
        from orchestrator.scanners.nuclei_scanner import NucleiScanner
        from orchestrator.scanners.whatweb_scanner import WhatwebScanner
        from orchestrator.exploit.pipeline import ExploitPipeline
        from orchestrator.postex.pipeline import PostExploitPipeline

        nmap = NmapScanner()
        nuclei = NucleiScanner()
        whatweb = WhatwebScanner()

        nmap_result = nmap.scan_ports(req.target, req.ports)
        nuclei_result = nuclei.scan(req.target)
        whatweb_result = whatweb.scan(req.target)

        port_numbers = [p["port"] for p in nmap_result.get("ports", [])]

        ep = ExploitPipeline()
        exploit_result = await ep.run(req.target, ports=port_numbers)

        pp = PostExploitPipeline()
        forensic_result = await pp.run(req.target)

        result = {
            "target": req.target,
            "scan": {
                "nmap": nmap_result,
                "nuclei": nuclei_result,
                "whatweb": whatweb_result,
            },
            "exploit": exploit_result,
            "forensic": forensic_result,
        }
        log.info("audit %s complete", req.target)
        return result
    except Exception as e:
        log.error("audit error: %s", e)
        return {"error": str(e)}
