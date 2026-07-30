"""Simplified tool bridge endpoints - maps /api/tools/{nmap,recon} to Kali container."""

import asyncio
import httpx
import json
import logging
import re
import time
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel, Field
from enum import Enum

logger = logging.getLogger("raphael.tools_bridge")

router = APIRouter(prefix="/api/tools", tags=["tools"])

KALI_CONTAINER_URL = "http://localhost:3800/run"

class ToolRunRequest(BaseModel):
    tool: str
    args: list[str] = []
    timeout: int = 120
    env: dict[str, str] = {}

class ToolRunResponse(BaseModel):
    tool: str
    returncode: int
    stdout: str
    stderr: str

class NmapScanType(str, Enum):
    quick = "quick"
    full = "full"
    vuln = "vuln"
    os_detection = "os_detection"
    udp = "udp"

class NmapRequest(BaseModel):
    target: str
    scan_type: NmapScanType = NmapScanType.quick
    ports: Optional[str] = None
    extra_args: list[str] = []
    timeout: int = 300

class NmapResponse(BaseModel):
    target: str
    scan_type: str
    returncode: int
    raw_stdout: str
    raw_stderr: str = ""
    open_ports: list[dict]
    os_guess: Optional[str] = None

class ReconRequest(BaseModel):
    target: str
    subdomain_scan: bool = True
    port_scan: bool = True
    technology_detect: bool = True
    screenshot: bool = False
    depth: str = "normal"
    timeout: int = 600

class ReconResponse(BaseModel):
    target: str
    domains: list[str] = []
    open_ports: list[dict] = []
    technologies: list[dict] = []
    screenshots: list[str] = []
    raw_logs: list[str] = []
    returncode: int

async def _run_in_kali(
    tool: str,
    args: list[str],
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> ToolRunResponse:
    params = {"tool": tool, "args": " ".join(args), "timeout": timeout}
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout + 10)) as client:
        try:
            resp = await client.post(KALI_CONTAINER_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
            return ToolRunResponse(**data)
        except httpx.TimeoutException:
            raise HTTPException(504, f"Tool '{tool}' timed out after {timeout}s")
        except httpx.HTTPStatusError as e:
            raise HTTPException(502, f"Kali container error: {e.response.text}")
        except Exception as e:
            raise HTTPException(500, f"Internal bridge error: {e}")

def _parse_nmap_stdout(stdout: str) -> tuple[list[dict], Optional[str]]:
    ports = []
    os_guess = None
    in_port_section = False
    for line in stdout.splitlines():
        if line.startswith("PORT"):
            in_port_section = True
            continue
        if in_port_section:
            if not line.strip() or "Nmap done" in line:
                in_port_section = False
                continue
            parts = line.split()
            if len(parts) >= 3 and "/" in parts[0]:
                try:
                    port_proto = parts[0].split("/")
                    port_num = int(port_proto[0])
                    proto = port_proto[1]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    ports.append({
                        "port": port_num,
                        "protocol": proto,
                        "service": service,
                        "state": state,
                    })
                except (ValueError, IndexError):
                    continue
        if "OS details:" in line or "Aggressive OS guesses:" in line:
            os_guess = line.strip()
    return ports, os_guess

SCAN_ARGS = {
    NmapScanType.quick: ["-T4", "-F"],
    NmapScanType.full: ["-T4", "-p-"],
    NmapScanType.vuln: ["-T4", "-sV", "--script=vuln"],
    NmapScanType.os_detection: ["-T4", "-O", "-sV"],
    NmapScanType.udp: ["-T4", "-sU", "--top-ports=100"],
}

@router.post("/nmap", response_model=NmapResponse)
async def run_nmap(req: NmapRequest):
    if req.ports:
        args = ["-Pn"]  # always skip ping when explicit ports given
        args.extend(["-p", req.ports])
    else:
        args = SCAN_ARGS[req.scan_type][:]
    args.extend(req.extra_args)
    args.append(req.target)

    result = await _run_in_kali("nmap", args, timeout=req.timeout)
    open_ports, os_guess = _parse_nmap_stdout(result.stdout)

    return NmapResponse(
        target=req.target,
        scan_type=req.scan_type.value,
        returncode=result.returncode,
        raw_stdout=result.stdout,
        raw_stderr=result.stderr,
        open_ports=open_ports,
        os_guess=os_guess,
    )

@router.post("/recon", response_model=ReconResponse)
async def run_recon(req: ReconRequest):
    raw_logs = []
    domains: list[str] = []
    open_ports: list[dict] = []
    technologies: list[dict] = []
    screenshots: list[str] = []

    import asyncio
    start = time.time()

    tasks = []

    if req.subdomain_scan:
        async def sub_enum():
            nonlocal domains
            try:
                result = await _run_in_kali("subfinder", ["-d", req.target, "-silent"], timeout=120)
                raw_logs.append(f"[subfinder] exit={result.returncode}")
                domains = [d.strip() for d in result.stdout.splitlines() if d.strip()]
            except HTTPException as e:
                raw_logs.append(f"[subfinder] ERROR: {e.detail}")
        tasks.append(sub_enum())

    if req.port_scan:
        depth_args = {"light": ["-T4", "-F"], "normal": ["-T4", "-p-", "--top-ports=1000"], "deep": ["-T4", "-p-"]}
        async def port_scan():
            nonlocal open_ports
            try:
                args = depth_args.get(req.depth, depth_args["normal"]) + [req.target]
                result = await _run_in_kali("nmap", args, timeout=300)
                raw_logs.append(f"[nmap] exit={result.returncode}")
                open_ports, _ = _parse_nmap_stdout(result.stdout)
            except HTTPException as e:
                raw_logs.append(f"[nmap] ERROR: {e.detail}")
        tasks.append(port_scan())

    if req.technology_detect:
        async def tech_detect():
            nonlocal technologies
            try:
                result = await _run_in_kali("whatweb", [req.target, "--log-json=/dev/stdout"], timeout=120)
                raw_logs.append(f"[whatweb] exit={result.returncode}")
                for line in result.stdout.splitlines():
                    m = re.search(r"\{.*\}", line)
                    if m:
                        try:
                            techs = json.loads(m.group())
                            technologies.append(techs)
                        except json.JSONDecodeError:
                            pass
                if not technologies:
                    technologies.append({"source": "whatweb", "raw": result.stdout[:500]})
            except HTTPException as e:
                raw_logs.append(f"[whatweb] ERROR: {e.detail}")
        tasks.append(tech_detect())

    if req.screenshot:
        async def ss():
            nonlocal screenshots
            try:
                result = await _run_in_kali("aquatone", ["-out", "/tmp/aquatone", req.target], timeout=120)
                raw_logs.append(f"[aquatone] exit={result.returncode}")
                import glob, base64
                for f in glob.glob("/tmp/aquatone/*.png")[:5]:
                    with open(f, "rb") as img:
                        screenshots.append(base64.b64encode(img.read()).decode())
            except HTTPException as e:
                raw_logs.append(f"[aquatone] ERROR: {e.detail}")
        tasks.append(ss())

    await asyncio.gather(*tasks, return_exceptions=True)

    return ReconResponse(
        target=req.target,
        domains=domains,
        open_ports=open_ports,
        technologies=technologies,
        screenshots=screenshots,
        raw_logs=raw_logs,
        returncode=0,
    )
