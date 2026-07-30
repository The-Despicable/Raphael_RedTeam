"""Session management endpoints."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from orchestrator.api.types import SessionCreate, SessionResponse, SessionUpdate, Persona, Mode
from orchestrator.api.session_manager import get_session_manager
from orchestrator.auth import require_scope

logger = logging.getLogger("session_api")

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


class SessionListResponse(BaseModel):
    sessions: list[SessionResponse]
    total: int
    limit: int
    offset: int


class SessionStatsResponse(BaseModel):
    total_sessions: int
    total_messages: int
    by_persona: dict[str, int]
    by_mode: dict[str, int]
    db_path: str


@router.post("", response_model=SessionResponse)
async def create_session(
    req: SessionCreate,
    auth=Depends(require_scope("sessions:rw")),
):
    """Create a new session."""
    manager = get_session_manager()
    session = manager.create(req)
    logger.info(f"Created session {session.id} for target={req.target}, persona={req.persona}")
    return session


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    target: Optional[str] = Query(None),
    persona: Optional[Persona] = Query(None),
    auth=Depends(require_scope("sessions:r")),
):
    """List sessions with optional filters."""
    manager = get_session_manager()
    sessions = manager.list(limit=limit, offset=offset, target=target, persona=persona)
    
    # Get total count
    with manager.get_db_connection() as conn:
        query = "SELECT COUNT(*) FROM sessions WHERE 1=1"
        params = []
        if target:
            query += " AND target = ?"
            params.append(target)
        if persona:
            query += " AND persona = ?"
            params.append(persona.value)
        total = conn.execute(query, params).fetchone()[0]
    
    return SessionListResponse(
        sessions=sessions,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=SessionStatsResponse)
async def get_session_stats(auth=Depends(require_scope("sessions:r"))):
    """Get session statistics."""
    manager = get_session_manager()
    stats = manager.get_stats()
    return SessionStatsResponse(**stats)


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    auth=Depends(require_scope("sessions:r")),
):
    """Get session by ID."""
    manager = get_session_manager()
    session = manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.patch("/{session_id}", response_model=SessionResponse)
async def update_session(
    session_id: str,
    update: SessionUpdate,
    auth=Depends(require_scope("sessions:rw")),
):
    """Update session fields."""
    manager = get_session_manager()
    session = manager.update(session_id, update)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.delete("/{session_id}")
async def delete_session(
    session_id: str,
    auth=Depends(require_scope("sessions:rw")),
):
    """Delete a session."""
    manager = get_session_manager()
    if not manager.delete(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "deleted", "session_id": session_id}


@router.get("/{session_id}/messages")
async def get_session_messages(
    session_id: str,
    limit: int = Query(100, ge=1, le=500),
    auth=Depends(require_scope("sessions:r")),
):
    """Get messages for a session."""
    manager = get_session_manager()
    session = manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    messages = manager.get_messages(session_id, limit=limit)
    return {"session_id": session_id, "messages": messages, "count": len(messages)}


@router.post("/{session_id}/messages")
async def add_session_message(
    session_id: str,
    role: str,
    content: str,
    tool_calls: Optional[list] = None,
    tool_call_id: Optional[str] = None,
    name: Optional[str] = None,
    auth=Depends(require_scope("sessions:rw")),
):
    """Add a message to session history."""
    manager = get_session_manager()
    session = manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    success = manager.add_message(
        session_id=session_id,
        role=role,
        content=content,
        tool_calls=tool_calls,
        tool_call_id=tool_call_id,
        name=name,
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add message")
    
    return {"status": "added", "session_id": session_id}