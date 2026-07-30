"""Agent execution endpoint with SSE streaming."""

import asyncio
import json
import logging
import uuid
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from orchestrator.api.types import (
    AgentRequest,
    AgentResponse,
    AgentEvent,
    EventType,
    Persona,
    ToolDefinition,
    get_persona_prompt,
    check_tool_permission,
)
from orchestrator.auth import require_scope
from orchestrator.agents.engage import build_orchestrator, run_agent_engage
from orchestrator.audit_trail import record_event

logger = logging.getLogger("agent_api")

router = APIRouter(prefix="/api/agent", tags=["agent"])


class AgentExecuteRequest(BaseModel):
    """Request for agent execution with SSE streaming."""
    messages: list[dict] = Field(..., description="Conversation messages")
    tools: list[ToolDefinition] = Field(default_factory=list, description="Available tool definitions")
    target: Optional[str] = Field(None, description="Target IP/domain/CIDR")
    mode: str = Field(default="autonomous", description="Execution mode")
    session_id: Optional[str] = Field(None, description="Session ID for continuity")
    persona: Optional[Persona] = Field(default=Persona.Z3R0, description="Operational persona")
    config: dict = Field(default_factory=dict, description="Additional configuration")


@router.post("/execute")
async def execute_agent(
    request: Request,
    req: AgentExecuteRequest,
    auth=Depends(require_scope("agent:execute")),
):
    """
    Execute agent with Server-Sent Events streaming.
    
    Returns SSE stream with events:
    - text: Assistant text content
    - tool_call: Tool invocation request
    - tool_result: Tool execution result
    - error: Error information
    - done: Completion signal
    """
    session_id = req.session_id or str(uuid.uuid4())
    target = req.target or req.config.get("target")
    persona = req.persona or Persona.Z3R0
    
    # Scope check
    if target:
        from orchestrator.scope import default_scope
        if not default_scope.check(target):
            raise HTTPException(
                status_code=403,
                detail=f"Target {target} is not in allowed scope"
            )
    
    # Build system prompt with persona
    system_prompt = get_persona_prompt(persona)
    
    # Filter tools based on persona permissions
    allowed_tools = []
    for tool in req.tools:
        allowed, needs_approval = check_tool_permission(persona, tool.name, "default")
        if allowed:
            tool.requires_approval = needs_approval
            allowed_tools.append(tool)
    
    record_event(
        action="agent_execute",
        target=target or "unknown",
        phase="api",
        verdict="started",
        metadata={
            "session_id": session_id,
            "persona": persona.value,
            "mode": req.mode,
            "tools_count": len(allowed_tools),
            "messages_count": len(req.messages),
        }
    )
    
    async def event_generator() -> AsyncGenerator[str, None]:
        """Generate SSE events from agent execution."""
        try:
            # Use the existing agent engagement system
            # Convert messages to objective
            objective = ""
            for msg in req.messages:
                if msg.get("role") == "user":
                    objective = msg.get("content", "")
                    break
            
            # Check for prefix-based persona escalation
            if objective:
                if objective.startswith("Ghost "):
                    persona = Persona.GHOST
                    objective = objective[6:]
                elif objective.startswith("Stealth "):
                    persona = Persona.STEALTH
                    objective = objective[8:]
                elif objective.startswith("Full "):
                    persona = Persona.GHOST
                    objective = objective[5:]
            
            if not objective:
                objective = "Analyze and assess target"
            
            # Run engagement
            result = await run_agent_engage(
                target=target or "unknown",
                objective=objective,
                persona=persona.value,
                phases=req.config.get("phases"),
            )
            
            # Stream results as SSE events
            # Send text response
            text_content = _format_result_for_streaming(result)
            yield f"data: {json.dumps({'type': 'text', 'content': text_content})}\n\n"
            
            # Send completion
            yield f"data: {json.dumps({'type': 'done', 'session_id': session_id})}\n\n"
            
            record_event(
                action="agent_execute",
                target=target or "unknown",
                phase="api",
                verdict="completed",
                metadata={
                    "session_id": session_id,
                    "persona": persona.value,
                    "findings": result.get("total_findings", 0),
                    "elapsed": result.get("elapsed_seconds", 0),
                }
            )
            
        except Exception as e:
            logger.exception(f"Agent execution failed: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'session_id': session_id, 'error': str(e)})}\n\n"
            
            record_event(
                action="agent_execute",
                target=target or "unknown",
                phase="api",
                verdict="error",
                metadata={"session_id": session_id, "error": str(e)}
            )
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/execute-sync", response_model=AgentResponse)
async def execute_agent_sync(
    req: AgentExecuteRequest,
    auth=Depends(require_scope("agent:execute")),
):
    """Execute agent synchronously (non-streaming)."""
    session_id = req.session_id or str(uuid.uuid4())
    target = req.target or req.config.get("target")
    persona = req.persona or Persona.Z3R0
    
    if target:
        from orchestrator.scope import default_scope
        if not default_scope.check(target):
            raise HTTPException(
                status_code=403,
                detail=f"Target {target} is not in allowed scope"
            )
    
    # Check for prefix-based persona escalation
    original_objective = ""
    for msg in req.messages:
        if msg.get("role") == "user":
            original_objective = msg.get("content", "")
            break
    
    objective = original_objective
    if original_objective:
        if original_objective.startswith("Ghost "):
            persona = Persona.GHOST
            objective = original_objective[6:]
        elif original_objective.startswith("Stealth "):
            persona = Persona.STEALTH
            objective = original_objective[8:]
        elif original_objective.startswith("Full "):
            persona = Persona.GHOST
            objective = original_objective[5:]
    
    if not objective:
        objective = "Analyze and assess target"
    
    # Filter tools based on persona
    allowed_tools = []
    for tool in req.tools:
        allowed, needs_approval = check_tool_permission(persona, tool.name, "default")
        if allowed:
            tool.requires_approval = needs_approval
            allowed_tools.append(tool)
    
    result = await run_agent_engage(
        target=target or "unknown",
        objective=objective,
        persona=persona.value,
        phases=req.config.get("phases"),
    )
    
    return AgentResponse(
        session_id=session_id,
        target=target,
        persona=persona,
        result=result,
        tools_available=[t.name for t in allowed_tools],
    )


def _format_result_for_streaming(result: dict) -> str:
    """Format agent result for streaming output."""
    lines = []
    lines.append(f"Target: {result.get('target', 'unknown')}")
    lines.append(f"Persona: {result.get('persona', 'unknown')}")
    lines.append(f"Objective: {result.get('objective', 'unknown')}")
    lines.append(f"Elapsed: {result.get('elapsed_seconds', 0):.2f}s")
    lines.append(f"Findings: {result.get('total_findings', 0)}")
    lines.append(f"Tasks Completed: {result.get('tasks_completed', 0)}")
    lines.append("")
    
    findings = result.get("findings", [])
    if findings:
        lines.append("=== FINDINGS ===")
        for i, f in enumerate(findings[:20], 1):
            lines.append(f"{i}. [{f.get('severity', 'info').upper()}] {f.get('type', 'finding')}")
            lines.append(f"   {f.get('description', 'No description')}")
            if f.get('evidence'):
                lines.append(f"   Evidence: {f['evidence'][:200]}")
            lines.append("")
    
    goal_tree = result.get("goal_tree", {})
    if goal_tree:
        lines.append("=== EXECUTION TREE ===")
        lines.append(_format_goal_tree(goal_tree))
    
    return "\n".join(lines)


def _format_goal_tree(tree: dict, indent: int = 0) -> str:
    """Format goal tree for display."""
    lines = []
    prefix = "  " * indent
    node_type = tree.get("type", "unknown")
    target = tree.get("target", "")
    desc = tree.get("description", "")
    status = tree.get("status", "pending")
    lines.append(f"{prefix}▸ {node_type} [{status}] {target} - {desc}")
    
    for child in tree.get("children", []):
        lines.append(_format_goal_tree(child, indent + 1))
    
    return "\n".join(lines)


@router.get("/personas")
async def list_personas(auth=Depends(require_scope("agent:read"))):
    """List available personas with descriptions."""
    return {
        "personas": [
            {
                "id": "z3r0",
                "name": "Z3R0",
                "description": "Clinical analysis — recon-first, surgical precision, zero noise",
                "default": True,
                "tools": "recon-only (nmap single, nuclei, passive enum)",
            },
            {
                "id": "ghost",
                "name": "Ghost",
                "description": "Full-spectrum assault — all phases, all tools, no constraints",
                "default": False,
                "tools": "all tools allowed (nmap mass, sqlmap, msf, bloodhound, etc.)",
            },
            {
                "id": "stealth",
                "name": "Stealth",
                "description": "Low-and-slow surgical — passive recon, operator approval for actions",
                "default": False,
                "tools": "ask-permission for non-recon tools",
            },
            {
                "id": "student",
                "name": "Student",
                "description": "Autonomous pentest learning agent — continuous research, stack profiling, chain synthesis",
                "default": False,
                "tools": "all tools + research scheduler + stack matcher + chain synthesizer",
            },
        ],
        "default": "z3r0",
    }


@router.post("/persona/{persona_id}/permission")
async def check_permission(
    persona_id: Persona,
    tool: str,
    mode: str = "default",
    auth=Depends(require_scope("agent:read")),
):
    """Check if a tool is allowed for a persona."""
    allowed, needs_approval = check_tool_permission(persona_id, tool, mode)
    return {
        "persona": persona_id.value,
        "tool": tool,
        "mode": mode,
        "allowed": allowed,
        "requires_approval": needs_approval,
    }