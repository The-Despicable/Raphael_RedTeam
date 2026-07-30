"""Session management with SQLite persistence."""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from orchestrator.api.types import SessionCreate, SessionResponse, SessionUpdate, Persona, Mode

logger = logging.getLogger("session_manager")


class SessionManager:
    """SQLite-based session management."""
    
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = str(Path.home() / ".raphael" / "sessions.db")
        
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    persona TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tool_calls TEXT,
                    tool_call_id TEXT,
                    name TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_session 
                ON messages(session_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_updated 
                ON sessions(updated_at DESC)
            """)
            conn.commit()
    
    def create(self, req: SessionCreate) -> SessionResponse:
        """Create a new session."""
        session_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO sessions (id, target, persona, mode, metadata, created_at, updated_at, message_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    session_id,
                    req.target,
                    req.persona.value,
                    req.mode.value,
                    json.dumps(req.metadata),
                    now,
                    now,
                ),
            )
            conn.commit()
        
        return SessionResponse(
            id=session_id,
            target=req.target,
            persona=req.persona,
            mode=req.mode,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            metadata=req.metadata,
            message_count=0,
        )
    
    def get(self, session_id: str) -> Optional[SessionResponse]:
        """Get session by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        
        if not row:
            return None
        
        return SessionResponse(
            id=row["id"],
            target=row["target"],
            persona=Persona(row["persona"]),
            mode=Mode(row["mode"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=json.loads(row["metadata"]),
            message_count=row["message_count"],
        )
    
    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        target: Optional[str] = None,
        persona: Optional[Persona] = None,
    ) -> list[SessionResponse]:
        """List sessions with optional filters."""
        query = "SELECT * FROM sessions WHERE 1=1"
        params = []
        
        if target:
            query += " AND target = ?"
            params.append(target)
        if persona:
            query += " AND persona = ?"
            params.append(persona.value)
        
        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
        
        return [
            SessionResponse(
                id=row["id"],
                target=row["target"],
                persona=Persona(row["persona"]),
                mode=Mode(row["mode"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                metadata=json.loads(row["metadata"]),
                message_count=row["message_count"],
            )
            for row in rows
        ]
    
    def update(self, session_id: str, update: SessionUpdate) -> Optional[SessionResponse]:
        """Update session fields."""
        session = self.get(session_id)
        if not session:
            return None
        
        fields = []
        params = []
        
        if update.target is not None:
            fields.append("target = ?")
            params.append(update.target)
        if update.persona is not None:
            fields.append("persona = ?")
            params.append(update.persona.value)
        if update.mode is not None:
            fields.append("mode = ?")
            params.append(update.mode.value)
        if update.metadata is not None:
            fields.append("metadata = ?")
            params.append(json.dumps(update.metadata))
        
        if not fields:
            return session
        
        fields.append("updated_at = ?")
        params.append(datetime.utcnow().isoformat())
        params.append(session_id)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                f"UPDATE sessions SET {', '.join(fields)} WHERE id = ?",
                params,
            )
            conn.commit()
        
        return self.get(session_id)
    
    def delete(self, session_id: str) -> bool:
        """Delete a session and its messages."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        tool_calls: Optional[list] = None,
        tool_call_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> bool:
        """Add a message to session history."""
        session = self.get(session_id)
        if not session:
            return False
        
        now = datetime.utcnow().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO messages (session_id, role, content, tool_calls, tool_call_id, name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    role,
                    content,
                    json.dumps(tool_calls) if tool_calls else None,
                    tool_call_id,
                    name,
                    now,
                ),
            )
            conn.execute(
                "UPDATE sessions SET message_count = message_count + 1, updated_at = ? WHERE id = ?",
                (now, session_id),
            )
            conn.commit()
        
        return True
    
    def get_messages(self, session_id: str, limit: int = 100) -> list[dict]:
        """Get messages for a session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM messages 
                WHERE session_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        
        return [
            {
                "role": row["role"],
                "content": row["content"],
                "tool_calls": json.loads(row["tool_calls"]) if row["tool_calls"] else None,
                "tool_call_id": row["tool_call_id"],
                "name": row["name"],
            }
            for row in reversed(rows)
        ]
    
    def get_db_connection(self):
        """Get a database connection for external queries."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_stats(self) -> dict:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            by_persona = dict(
                conn.execute(
                    "SELECT persona, COUNT(*) FROM sessions GROUP BY persona"
                ).fetchall()
            )
            by_mode = dict(
                conn.execute(
                    "SELECT mode, COUNT(*) FROM sessions GROUP BY mode"
                ).fetchall()
            )
            total_messages = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        
        return {
            "total_sessions": total,
            "total_messages": total_messages,
            "by_persona": by_persona,
            "by_mode": by_mode,
            "db_path": self.db_path,
        }


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get or create global session manager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def set_session_manager(manager: SessionManager):
    """Set global session manager (for testing)."""
    global _session_manager
    _session_manager = manager