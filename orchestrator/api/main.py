"""Raphael Orchestrator API — FastAPI application."""

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from orchestrator.api.agent import router as agent_router
from orchestrator.api.tools import router as tools_router
from orchestrator.api.tools_bridge import router as tools_bridge_router
from orchestrator.api.session import router as session_router
from orchestrator.api.session_manager import get_session_manager
from orchestrator.api.types import HealthResponse, Persona
from orchestrator.auth import load_keys as load_api_keys
from orchestrator.audit_trail import record_event
from orchestrator.chains.tool_registry import registry

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("orchestrator_api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Raphael Orchestrator API...")
    load_api_keys()
    
    # Verify tool binaries
    tool_bins = ["nmap", "sqlmap", "bloodhound-python", "msfconsole", "crackmapexec", "chisel"]
    available = []
    for bin_name in tool_bins:
        import shutil
        if shutil.which(bin_name):
            available.append(bin_name)
        else:
            logger.warning(f"Tool not found in PATH: {bin_name}")
    
    logger.info(f"Available tools: {available}")
    
    record_event(
        action="api_startup",
        target="local",
        phase="lifecycle",
        verdict="success",
        metadata={"tools_available": available}
    )
    
    yield
    
    # Shutdown
    logger.info("Shutting down Raphael Orchestrator API...")
    record_event(
        action="api_shutdown",
        target="local",
        phase="lifecycle",
        verdict="success",
        metadata={}
    )


app = FastAPI(
    title="Raphael 2.0 Orchestrator API",
    version="2.0.0",
    description="Offensive security orchestration API with Z3R0/Ghost/Stealth/FORGE personas",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# Routers
app.include_router(agent_router)
app.include_router(tools_router)
app.include_router(tools_bridge_router)
app.include_router(session_router)


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    session_manager = get_session_manager()
    stats = session_manager.get_stats()
    
    return HealthResponse(
        status="ok",
        version="2.0.0",
        orchestrator_ready=True,
        tools_available=[t["name"] for t in registry.list_tools()],
        active_sessions=stats["total_sessions"],
    )


@app.get("/api/personas")
async def list_personas():
    """List available personas with their capabilities."""
    from orchestrator.api.types import PERSONA_PROMPTS, TOOL_PERMISSIONS
    
    return {
        "personas": [
            {
                "id": p.value,
                "name": p.value.upper(),
                "description": PERSONA_PROMPTS[p].split("\n")[1] if p in PERSONA_PROMPTS else "",
                "default_mode": "autonomous",
                "permissions_summary": {
                    tool: "full" if "all" in perms.get("allowed", []) 
                          else "restricted" if perms.get("ask") 
                          else "denied"
                    for tool, perms in TOOL_PERMISSIONS.get(p, {}).items()
                },
            }
            for p in Persona
        ],
        "default": Persona.Z3R0.value,
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("ORCHESTRATOR_API_PORT", "3800"))
    uvicorn.run(app, host="0.0.0.0", port=port)