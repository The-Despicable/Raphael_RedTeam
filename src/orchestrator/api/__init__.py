"""Raphael Orchestrator API package."""

from orchestrator.api.agent import router as agent_router
from orchestrator.api.tools import router as tools_router
from orchestrator.api.session import router as session_router, get_session_manager
from orchestrator.api.types import (
    Persona,
    Mode,
    ToolDefinition,
    Message,
    AgentRequest,
    AgentResponse,
    SessionCreate,
    SessionResponse,
    SessionUpdate,
    ToolExecuteRequest,
    ToolExecuteResponse,
    HealthResponse,
    get_persona_prompt,
    check_tool_permission,
)

__all__ = [
    # Routers
    "agent_router",
    "tools_router",
    "session_router",
    # Session manager
    "get_session_manager",
    # Types
    "Persona",
    "Mode",
    "ToolDefinition",
    "Message",
    "AgentRequest",
    "AgentResponse",
    "SessionCreate",
    "SessionResponse",
    "SessionUpdate",
    "ToolExecuteRequest",
    "ToolExecuteResponse",
    "HealthResponse",
    # Helpers
    "get_persona_prompt",
    "check_tool_permission",
]