#!/usr/bin/env python3
"""
Kali Tools Service — Brokered Tool Execution Endpoint

Wraps common Kali tools (sqlmap, nmap, nikto, etc.) and exposes them
via a REST API for brokered invocation through the CapabilityBroker.

Security: All invocations must be authorized by CapabilityBroker before
reaching this service. This service performs NO authorization itself.
"""

import subprocess
import shlex
import os
import shutil
import logging
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, Header
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kali-tools")

app = FastAPI(title="Kali Tools Service", version="1.0.0")

TOOLS_CACHE: dict[str, str] = {}

@app.on_event("startup")
async def cache_tools():
    """Populate TOOLS_CACHE with available executables."""
    paths = os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    for d in paths.split(":"):
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    fp = os.path.join(d, f)
                    if os.path.isfile(fp) and os.access(fp, os.X_OK):
                        TOOLS_CACHE[f] = fp
            except (PermissionError, OSError):
                continue
    
    # Explicitly check for known tools
    for tool in ["nuclei", "httpx", "sqlmap", "nmap", "nikto", "gobuster", "ffuf"]:
        TOOLS_CACHE[tool] = shutil.which(tool) or ""
    
    logger.info(f"Cached {len(TOOLS_CACHE)} tools")


class ToolRunRequest(BaseModel):
    tool: str = Field(..., description="Tool name (must be in allowed list)")
    args: str = Field(default="", description="Command line arguments")
    timeout: int = Field(default=300, ge=1, le=3600, description="Timeout in seconds")


class ToolRunResponse(BaseModel):
    tool: str
    returncode: int
    stdout: str
    stderr: str
    authorized: bool = True


ALLOWED_TOOLS = {
    "sqlmap", "nmap", "nikto", "nuclei", "httpx", "gobuster", "ffuf",
    "dirb", "whatweb", "wpscan", "joomscan", "droopescan", "cmsmap",
    "ssh", "ncrack", "hydra", "medusa", "msfconsole", "msfvenom",
    "searchsploit", "exploitdb", "curl", "wget", "netcat", "ncat", "socat",
    "python3", "bash", "sh", "zsh", "git", "jq", "whois", "dig", "host",
}

@app.post("/run", response_model=ToolRunResponse)
def run_tool(request: ToolRunRequest, authorization: Optional[str] = Header(None)):
    """
    Execute a brokered tool command.
    
    Authorization header should contain the ActionReceipt ID from CapabilityBroker.
    This service does NOT perform authorization - it trusts the broker.
    """
    tool = request.tool
    args = request.args
    timeout = request.timeout
    
    if tool not in ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail=f"Tool '{tool}' not in allowed list")
    
    if tool not in TOOLS_CACHE or not TOOLS_CACHE[tool]:
        raise HTTPException(status_code=404, detail=f"Tool '{tool}' not available")
    
    # Build command
    cmd = shlex.split(f"{tool} {args}") if args else [tool]
    
    logger.info(f"Executing: {' '.join(cmd)} (auth: {authorization})")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/workspace"
        )
        return ToolRunResponse(
            tool=tool,
            returncode=result.returncode,
            stdout=result.stdout[-10000:] if result.stdout else "",
            stderr=result.stderr[-5000:] if result.stderr else "",
            authorized=True
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Tool '{tool}' not found")
    except subprocess.TimeoutExpired:
        return ToolRunResponse(
            tool=tool,
            returncode=-1,
            stdout="",
            stderr="timed out",
            authorized=True
        )
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tools")
def list_tools():
    return {"tools": sorted(k for k, v in TOOLS_CACHE.items() if v and k in ALLOWED_TOOLS), "total": len(TOOLS_CACHE)}


@app.get("/health")
def health():
    return {"status": "ok", "tools": len(TOOLS_CACHE)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3800)