"""REST endpoints for pentest tools execution."""

import asyncio
import logging
import shlex
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from orchestrator.api.types import (
    ToolExecuteRequest,
    ToolExecuteResponse,
    ToolListResponse,
    ToolInfo,
    Persona,
    check_tool_permission,
)
from orchestrator.auth import require_scope
from orchestrator.chains.tool_registry import (
    execute_nmap,
    execute_sqlmap,
    execute_bloodhound,
    execute_metasploit,
    execute_crackmapexec,
    execute_chisel,
    ToolRegistry,
)
from orchestrator.audit_trail import record_event

logger = logging.getLogger("tools_api")

router = APIRouter(prefix="/api/tools", tags=["tools"])

# Tool metadata for listing
TOOL_METADATA = [
    ToolInfo(
        name="nmap",
        description="Network port scanning and service enumeration",
        category="recon",
        parameters={
            "target": {"type": "string", "description": "Target IP, domain, or CIDR"},
            "ports": {"type": "string", "description": "Port range (e.g., '1-65535', '80,443,8080')", "default": "1-1000"},
            "scan_type": {"type": "string", "description": "Scan type: syn, connect, udp, ack", "default": "syn"},
            "stealth": {"type": "boolean", "description": "Use stealth timing (T2)", "default": False},
            "aggressive": {"type": "boolean", "description": "Aggressive scan (-A)", "default": False},
            "service_version": {"type": "boolean", "description": "Service version detection (-sV)", "default": True},
            "os_detection": {"type": "boolean", "description": "OS detection (-O)", "default": False},
            "scripts": {"type": "string", "description": "NSE scripts to run", "default": "default"},
        },
        requires_approval=True,
    ),
    ToolInfo(
        name="sqlmap",
        description="Automated SQL injection detection and exploitation",
        category="exploit",
        parameters={
            "url": {"type": "string", "description": "Target URL with vulnerable parameter"},
            "data": {"type": "string", "description": "POST data for testing"},
            "dbms": {"type": "string", "description": "Force DBMS (mysql, postgres, mssql, oracle, sqlite)"},
            "level": {"type": "integer", "description": "Test level (1-5)", "default": 3},
            "risk": {"type": "integer", "description": "Risk level (1-3)", "default": 2},
            "batch": {"type": "boolean", "description": "Non-interactive mode", "default": True},
            "threads": {"type": "integer", "description": "Number of threads", "default": 5},
            "timeout": {"type": "integer", "description": "Request timeout in seconds", "default": 30},
        },
        requires_approval=True,
    ),
    ToolInfo(
        name="bloodhound",
        description="Active Directory attack path analysis via BloodHound",
        category="postex",
        parameters={
            "domain": {"type": "string", "description": "AD domain (e.g., corp.local)"},
            "dc": {"type": "string", "description": "Domain controller IP/hostname"},
            "username": {"type": "string", "description": "Username for authentication"},
            "password": {"type": "string", "description": "Password for authentication"},
            "collection_method": {"type": "string", "description": "Collection method: all, group, localadmin, session, trust, dc", "default": "all"},
            "output_dir": {"type": "string", "description": "Output directory for JSON files"},
            "stealth": {"type": "boolean", "description": "Use stealth collection", "default": False},
        },
        requires_approval=True,
    ),
    ToolInfo(
        name="metasploit",
        description="Metasploit Framework module execution",
        category="exploit",
        parameters={
            "module": {"type": "string", "description": "Module path (e.g., exploit/windows/smb/ms17_010_eternalblue)"},
            "rhost": {"type": "string", "description": "Target host"},
            "rport": {"type": "integer", "description": "Target port"},
            "payload": {"type": "string", "description": "Payload to use (e.g., windows/x64/meterpreter/reverse_tcp)"},
            "lhost": {"type": "string", "description": "Local host for reverse connection"},
            "lport": {"type": "integer", "description": "Local port for reverse connection", "default": 4444},
            "options": {"type": "object", "description": "Additional module options as key-value pairs"},
        },
        requires_approval=True,
    ),
    ToolInfo(
        name="crackmapexec",
        description="Network enumeration and credential testing across protocols",
        category="postex",
        parameters={
            "target": {"type": "string", "description": "Target IP, CIDR, or file with targets"},
            "protocol": {"type": "string", "description": "Protocol: smb, ssh, winrm, ldap, mssql, rdp", "default": "smb"},
            "username": {"type": "string", "description": "Username or user file"},
            "password": {"type": "string", "description": "Password, hash, or pass file"},
            "hash": {"type": "string", "description": "NTLM hash for pass-the-hash"},
            "command": {"type": "string", "description": "Command to execute on target"},
            "module": {"type": "string", "description": "CME module to run"},
            "options": {"type": "object", "description": "Module options as key-value pairs"},
        },
        requires_approval=True,
    ),
    ToolInfo(
        name="chisel",
        description="Fast TCP/UDP tunneling over HTTP/SOCKS5",
        category="c2",
        parameters={
            "mode": {"type": "string", "description": "Mode: server or client", "default": "client"},
            "target": {"type": "string", "description": "Target server (host:port) for client mode"},
            "port": {"type": "integer", "description": "Local port to bind (server mode)", "default": 8080},
            "socks5": {"type": "boolean", "description": "Enable SOCKS5 proxy", "default": True},
            "reverse": {"type": "boolean", "description": "Reverse tunnel (R:remote:local)", "default": False},
            "auth": {"type": "string", "description": "Authentication string (user:pass)"},
            "fingerprint": {"type": "string", "description": "TLS fingerprint for server verification"},
        },
        requires_approval=True,
    ),
]


@router.get("", response_model=ToolListResponse)
async def list_tools(
    category: Optional[str] = Query(None, description="Filter by category"),
    persona: Persona = Query(Persona.Z3R0, description="Persona for permission filtering"),
    auth=Depends(require_scope("tools:read")),
):
    """List available tools with persona-based permission info."""
    tools = TOOL_METADATA
    
    if category:
        tools = [t for t in tools if t.category == category]
    
    # Add permission info per persona
    result_tools = []
    for tool in tools:
        allowed, needs_approval = check_tool_permission(persona, tool.name, "default")
        tool_dict = tool.model_dump()
        tool_dict["allowed_for_persona"] = allowed
        tool_dict["requires_approval"] = needs_approval or tool.requires_approval
        result_tools.append(ToolInfo(**tool_dict))
    
    return ToolListResponse(tools=result_tools, total=len(result_tools))


@router.post("/{tool_name}", response_model=ToolExecuteResponse)
async def execute_tool(
    tool_name: str,
    req: ToolExecuteRequest,
    auth=Depends(require_scope("tools:execute")),
):
    """Execute a pentest tool with given parameters."""
    execution_id = str(uuid.uuid4())
    
    # Validate tool exists
    tool_meta = next((t for t in TOOL_METADATA if t.name == tool_name), None)
    if not tool_meta:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")
    
    # Check persona permission
    persona = req.persona or Persona.Z3R0
    allowed, needs_approval = check_tool_permission(persona, tool_name, req.mode or "default")
    
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Tool '{tool_name}' not allowed for persona '{persona.value}' in mode '{req.mode or 'default'}'"
        )
    
    if needs_approval and not req.approved:
        raise HTTPException(
            status_code=403,
            detail=f"Tool '{tool_name}' requires operator approval for persona '{persona.value}'"
        )
    
    # Scope check for target
    target = req.params.get("target") or req.params.get("url") or req.params.get("rhost") or req.params.get("domain")
    if target:
        from orchestrator.scope import default_scope
        if not default_scope.check(target):
            raise HTTPException(
                status_code=403,
                detail=f"Target {target} is not in allowed scope"
            )
    
    record_event(
        action="tool_execute",
        target=target or "unknown",
        phase="api",
        verdict="started",
        metadata={
            "execution_id": execution_id,
            "tool": tool_name,
            "persona": persona.value,
            "mode": req.mode or "default",
            "approved": req.approved,
        }
    )
    
    try:
        # Execute the tool
        # Merge top-level target into params for executor
        exec_params = dict(req.params)
        if req.target:
            exec_params["target"] = req.target
        result = await _execute_tool_by_name(tool_name, exec_params, execution_id)
        
        record_event(
            action="tool_execute",
            target=target or "unknown",
            phase="api",
            verdict="completed" if result.get("success") else "failed",
            metadata={
                "execution_id": execution_id,
                "tool": tool_name,
                "exit_code": result.get("exit_code"),
                "duration": result.get("duration"),
            }
        )
        
        return ToolExecuteResponse(
            execution_id=execution_id,
            tool=tool_name,
            success=result.get("success", False),
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
            exit_code=result.get("exit_code", -1),
            duration=result.get("duration", 0),
            artifacts=result.get("artifacts", []),
        )
        
    except Exception as e:
        logger.exception(f"Tool execution failed: {e}")
        record_event(
            action="tool_execute",
            target=target or "unknown",
            phase="api",
            verdict="error",
            metadata={"execution_id": execution_id, "tool": tool_name, "error": str(e)}
        )
        return ToolExecuteResponse(
            execution_id=execution_id,
            tool=tool_name,
            success=False,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=0,
            artifacts=[],
        )


async def _execute_tool_by_name(tool_name: str, params: dict, execution_id: str) -> dict:
    """Route to appropriate tool executor."""
    executors = {
        "nmap": execute_nmap,
        "sqlmap": execute_sqlmap,
        "bloodhound": execute_bloodhound,
        "metasploit": execute_metasploit,
        "crackmapexec": execute_crackmapexec,
        "chisel": execute_chisel,
    }
    
    executor = executors.get(tool_name)
    if not executor:
        return {"success": False, "stderr": f"No executor for tool: {tool_name}", "exit_code": -1, "duration": 0}
    
    return await executor(params, execution_id)


# Convenience endpoints for common tool invocations
@router.post("/nmap/scan")
async def nmap_quick_scan(
    target: str,
    ports: str = "1-1000",
    stealth: bool = False,
    auth=Depends(require_scope("tools:execute")),
):
    """Quick nmap scan endpoint."""
    req = ToolExecuteRequest(
        target=target,
        params={"target": target, "ports": ports, "stealth": stealth},
        persona=Persona.Z3R0,
    )
    return await execute_tool("nmap", req, auth)


@router.post("/sqlmap/scan")
async def sqlmap_quick_scan(
    url: str,
    data: Optional[str] = None,
    auth=Depends(require_scope("tools:execute")),
):
    """Quick SQLMap scan endpoint."""
    req = ToolExecuteRequest(
        target=url,
        params={"url": url, "data": data, "batch": True},
        persona=Persona.GHOST,  # SQLMap requires Ghost persona
    )
    return await execute_tool("sqlmap", req, auth)


@router.post("/crackmapexec/enum")
async def cme_enum(
    target: str,
    protocol: str = "smb",
    username: str = "",
    password: str = "",
    auth=Depends(require_scope("tools:execute")),
):
    """Quick CrackMapExec enumeration."""
    req = ToolExecuteRequest(
        target=target,
        params={"target": target, "protocol": protocol, "username": username, "password": password},
        persona=Persona.GHOST,
    )
    return await execute_tool("crackmapexec", req, auth)