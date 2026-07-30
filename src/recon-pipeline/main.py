import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

from datetime import datetime
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .case_api import router as case_router

sys.path.insert(0, "/home/yaser/raphael-2.0/raphael")

from orchestrator.scanners.nmap_scanner import NmapScanner
from orchestrator.scanners.nuclei_scanner import NucleiScanner
from orchestrator.scanners.whatweb_scanner import WhatwebScanner
from orchestrator.karma_wrapper import KarmaV2Wrapper
from orchestrator.spiderfoot_wrapper import SpiderFootWrapper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-pipeline")

app = FastAPI(title="Recon Pipeline", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(case_router)

tasks: dict = {}


class ReconRequest(BaseModel):
    target: str
    subdomains: bool = True
    ports: str = "80,443,8080,8443"
    severity: str = "medium"
    aggression: int = 3


class DeepReconRequest(BaseModel):
    target: str
    modules: str = "sfp_dnsresolve,sfp_whois"


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "tools": {
            "subfinder": check_tool("subfinder"),
            "nmap": check_tool("nmap"),
            "nuclei": NucleiScanner().available,
            "whatweb": WhatwebScanner().available,
            "karma": KarmaV2Wrapper()._available,
            "spiderfoot": SpiderFootWrapper()._available,
        },
    }


async def run_subfinder(target: str) -> list:
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", target, "-silent",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        subdomains = [s.strip() for s in stdout.decode().splitlines() if s.strip()]
        return subdomains
    except asyncio.TimeoutError:
        logger.warning(f"subfinder timed out for {target}")
        return []
    except Exception as e:
        logger.error(f"subfinder error: {e}")
        return []


def write_targets_file(targets: list) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
    for t in targets:
        tmp.write(t + "\n")
    tmp.close()
    return tmp.name


def run_nmap(target: str, ports: str) -> dict:
    scanner = NmapScanner()
    return scanner.scan_ports(target, ports=ports, rate=100)


def run_nuclei(target: str, severity: str) -> dict:
    scanner = NucleiScanner()
    return scanner.scan(target, severity=severity, rate_limit=50)


def run_whatweb(target: str, aggression: int) -> dict:
    scanner = WhatwebScanner()
    return scanner.scan(target, aggression=aggression)


def run_karma(target: str) -> dict:
    wrapper = KarmaV2Wrapper()
    return wrapper.scan(target, mode="host")


def run_spiderfoot(target: str, modules: str) -> dict:
    wrapper = SpiderFootWrapper()
    return wrapper.scan(target, modules=modules)


async def run_recon_chain(request: ReconRequest) -> dict:
    target = request.target
    ports = request.ports
    severity = request.severity
    aggression = request.aggression

    subdomains = []
    if request.subdomains:
        logger.info(f"Running subfinder on {target}")
        subdomains = await run_subfinder(target)

    all_targets = [target] + subdomains
    targets_file = write_targets_file(all_targets)

    logger.info(f"Running nmap on {target} ports {ports}")
    nmap_result = await asyncio.to_thread(run_nmap, target, ports)
    open_ports = nmap_result.get("ports", [])

    http_targets = []
    for t in all_targets:
        for p in open_ports:
            port = p.get("port", 80) if isinstance(p, dict) else p
            if port in (80, 8080, 8000, 8888):
                http_targets.append(f"http://{t}:{port}")
            elif port in (443, 8443, 4443):
                http_targets.append(f"https://{t}:{port}")
            else:
                http_targets.append(f"https://{t}:{port}")
    if not http_targets:
        http_targets = [f"https://{target}"]

    logger.info(f"Running nuclei on {target} (severity: {severity})")
    nuclei_result = await asyncio.to_thread(run_nuclei, target, severity)

    logger.info(f"Running whatweb on {target}")
    whatweb_result = await asyncio.to_thread(run_whatweb, target, aggression)

    summary = {
        "subdomains_found": len(subdomains),
        "open_ports_count": len(open_ports),
        "vulnerabilities_found": nuclei_result.get("findings_count", 0),
        "technologies_detected": whatweb_result.get("tech_count", 0),
    }

    return {
        "target": target,
        "subdomains": subdomains,
        "open_ports": open_ports,
        "vulnerabilities": nuclei_result.get("findings", []),
        "tech_stack": whatweb_result.get("technologies", {}),
        "summary": summary,
    }


async def run_deep_recon(request: DeepReconRequest) -> dict:
    target = request.target
    modules = request.modules

    spiderfoot_task = asyncio.to_thread(run_spiderfoot, target, modules)
    karma_task = asyncio.to_thread(run_karma, target)

    osint_result, shodan_result = await asyncio.gather(spiderfoot_task, karma_task)

    return {
        "target": target,
        "osint": osint_result,
        "shodan": shodan_result,
        "combined": {
            "spiderfoot_status": osint_result.get("status"),
            "karma_status": shodan_result.get("status"),
        },
    }


@app.post("/recon/run")
async def recon_run(request: ReconRequest):
    task_id = str(uuid.uuid4())
    tasks[task_id] = {"status": "running", "progress": "starting", "result": None}

    async def worker():
        try:
            tasks[task_id]["progress"] = "recon chain in progress"
            result = await run_recon_chain(request)
            tasks[task_id] = {"status": "completed", "progress": "done", "result": result}
        except Exception as e:
            logger.exception("recon chain failed")
            tasks[task_id] = {"status": "failed", "progress": "error", "error": str(e)}

    asyncio.create_task(worker())
    return {"task_id": task_id, "status": "started"}


@app.post("/recon/deep")
async def recon_deep(request: DeepReconRequest):
    task_id = str(uuid.uuid4())
    tasks[task_id] = {"status": "running", "progress": "starting", "result": None}

    async def worker():
        try:
            tasks[task_id]["progress"] = "deep recon in progress"
            result = await run_deep_recon(request)
            tasks[task_id] = {"status": "completed", "progress": "done", "result": result}
        except Exception as e:
            logger.exception("deep recon failed")
            tasks[task_id] = {"status": "failed", "progress": "error", "error": str(e)}

    asyncio.create_task(worker())
    return {"task_id": task_id, "status": "started"}


@app.get("/recon/status/{task_id}")
async def recon_status(task_id: str):
    task = tasks.get(task_id)
    if task is None:
        return {"error": "task not found"}
    return task


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3503)
