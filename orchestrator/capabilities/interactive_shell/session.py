"""session.py — ShellSession state object and authorization receipts.

Defines the brokered session state machine and the receipt types returned
by CapabilityBroker for shell session and command authorization.
"""

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from .capability import ShellCapabilityType, ShellConnectionInfo


class ShellSessionStatus(str, Enum):
    """Lifecycle states for a shell session."""
    PROPOSED = "proposed"           # Planner proposed, awaiting Broker authorization
    AUTHORIZED = "authorized"       # Broker authorized, session created
    CONNECTING = "connecting"       # Capability.connect() in progress
    ACTIVE = "active"               # Connected, accepting commands
    IDLE = "idle"                   # Active but no recent commands
    TERMINATING = "terminating"     # Broker or capability closing session
    TERMINATED = "terminated"       # Clean shutdown complete
    ERROR = "error"                 # Connection failed or error state


class CommandFilterDecision(str, Enum):
    """Result of command filtering pipeline."""
    ALLOW = "allow"                 # Tier 1: static allowlist match
    ESCALATE = "escalate"           # Tier 2: LLM classifier says ESCALATE
    DENY = "deny"                   # Tier 1 deny or Tier 2 DENY


@dataclass
class ShellSessionProposal:
    """
    Proposal for a new shell session, submitted by Planner.

    This is the input to CapabilityBroker.authorize_shell_session().
    """
    capability_type: ShellCapabilityType
    target: str                     # Target IP/hostname
    port: int = 22                  # Target port (SSH default)
    username: str = ""              # Username (for SSH)
    auth_method: str = "password"   # "password", "key", "none"
    password: str = ""              # Password if auth_method=password
    private_key_path: str = ""      # Private key path if auth_method=key
    lhost: str = ""                 # Local host for reverse shell callback
    lport: int = 0                  # Local port for reverse shell (0 = auto-assign)
    max_duration_seconds: int = 3600  # Max session lifetime
    max_idle_seconds: int = 300     # Max idle before auto-terminate
    heartbeat_interval_seconds: int = 30  # Heartbeat interval
    allowed_commands_pattern: str = (
        r"^(ls|cat|id|pwd|whoami|uname|ps|netstat|ss|find|grep|head|tail|"
        r"less|more|file|stat|which|python3|python|bash|sh|zsh|exit|clear|"
        r"history|env|echo|cd|mkdir|touch|cp|mv|rm|chmod|chown)$"
    )
    pty_cols: int = 120
    pty_rows: int = 40
    working_directory: str = ""
    environment: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)  # exploit_chain_id, vulnerability_id, etc.

    def to_connection_info(self) -> ShellConnectionInfo:
        """Convert to ShellConnectionInfo for capability creation."""
        return ShellConnectionInfo(
            capability_type=self.capability_type,
            target=self.target,
            port=self.port,
            username=self.username,
            password=self.password,
            private_key_path=self.private_key_path,
            auth_method=self.auth_method,
            lhost=self.lhost,
            lport=self.lport,
            timeout=30.0,
            pty_cols=self.pty_cols,
            pty_rows=self.pty_rows,
            env=self.environment,
            metadata=self.metadata,
        )


@dataclass
class SessionReceipt:
    """
    Authorization receipt for a shell session.

    Returned by CapabilityBroker.authorize_shell_session().
    """
    session_id: str
    authorized: bool
    status: ShellSessionStatus
    expires_at: float                    # Unix timestamp
    restrictions: dict                   # {allowed_commands_pattern, max_idle, heartbeat_interval}
    listener_info: Optional[dict] = None  # {lhost, lport, protocol} for reverse shells
    reason: str = ""
    policy_version: str = "1.0"
    authorized_by: str = "capability_broker"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["capability_type"] = self.capability_type.value if hasattr(self, 'capability_type') else ""
        return d


@dataclass
class CommandReceipt:
    """
    Authorization receipt for a shell command.

    Returned by CapabilityBroker.authorize_shell_command().
    """
    command_id: str
    session_id: str
    command: str
    authorized: bool
    decision: CommandFilterDecision
    reason: str = ""
    falsification_task_id: Optional[str] = None  # If decision=ESCALATE
    session_status: ShellSessionStatus = ShellSessionStatus.ACTIVE
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["decision"] = self.decision.value
        d["session_status"] = self.session_status.value
        return d


@dataclass
class TerminationReceipt:
    """Receipt for session termination."""
    session_id: str
    terminated: bool
    reason: str
    terminated_by: str  # "broker", "planner", "capability", "timeout", "policy"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ShellSession:
    """
    Brokered shell session state object.

    This is the single source of truth for session state. All components
    (Broker, Planner, Capability) reference this object.

    Lifecycle:
        PROPOSED -> AUTHORIZED -> CONNECTING -> ACTIVE -> IDLE -> TERMINATING -> TERMINATED
                           --> ERROR (any state on failure)
    """
    session_id: str
    capability_type: ShellCapabilityType
    target: str
    username: str = ""
    auth_method: str = ""
    lhost: str = ""
    lport: int = 0
    allowed_commands_pattern: str = ""
    max_duration_seconds: int = 3600
    max_idle_seconds: int = 300
    heartbeat_interval_seconds: int = 30
    pty_cols: int = 120
    pty_rows: int = 40
    working_directory: str = ""
    environment: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    # Runtime state (managed by Broker/Capability)
    status: ShellSessionStatus = ShellSessionStatus.PROPOSED
    created_at: float = field(default_factory=time.time)
    authorized_at: float = 0.0
    connected_at: float = 0.0
    expires_at: float = 0.0
    last_activity_at: float = 0.0
    last_heartbeat_at: float = 0.0
    command_count: int = 0
    denied_command_count: int = 0
    last_denied_at: float = 0.0
    current_working_directory: str = ""
    capability_ref: Any = None  # Reference to capability instance

    def __post_init__(self):
        if self.expires_at == 0:
            self.expires_at = self.created_at + self.max_duration_seconds

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def is_idle_expired(self) -> bool:
        if self.last_activity_at == 0:
            return False
        return (time.time() - self.last_activity_at) >= self.max_idle_seconds

    @property
    def idle_seconds(self) -> float:
        if self.last_activity_at == 0:
            return 0.0
        return time.time() - self.last_activity_at

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    @property
    def can_accept_commands(self) -> bool:
        return self.status == ShellSessionStatus.ACTIVE and not self.is_expired

    def record_command(self, denied: bool = False):
        """Record command execution for idle/expiry tracking."""
        self.last_activity_at = time.time()
        self.command_count += 1
        if denied:
            self.denied_command_count += 1
            self.last_denied_at = time.time()

    def check_denial_threshold(self, threshold: int = 3, window_seconds: int = 60) -> bool:
        """Check if denial threshold exceeded (auto-terminate trigger)."""
        if self.denied_command_count >= threshold:
            if self.last_denied_at and (time.time() - self.last_denied_at) <= window_seconds:
                return True
        return False

    def transition(self, new_status: ShellSessionStatus) -> bool:
        """Validate and perform state transition."""
        valid_transitions = {
            ShellSessionStatus.PROPOSED: {ShellSessionStatus.AUTHORIZED, ShellSessionStatus.ERROR},
            ShellSessionStatus.AUTHORIZED: {ShellSessionStatus.CONNECTING, ShellSessionStatus.ERROR, ShellSessionStatus.TERMINATED},
            ShellSessionStatus.CONNECTING: {ShellSessionStatus.ACTIVE, ShellSessionStatus.ERROR, ShellSessionStatus.TERMINATED},
            ShellSessionStatus.ACTIVE: {ShellSessionStatus.IDLE, ShellSessionStatus.TERMINATING, ShellSessionStatus.ERROR},
            ShellSessionStatus.IDLE: {ShellSessionStatus.ACTIVE, ShellSessionStatus.TERMINATING, ShellSessionStatus.ERROR},
            ShellSessionStatus.TERMINATING: {ShellSessionStatus.TERMINATED, ShellSessionStatus.ERROR},
            ShellSessionStatus.TERMINATED: set(),
            ShellSessionStatus.ERROR: {ShellSessionStatus.TERMINATED},
        }

        if new_status in valid_transitions.get(self.status, set()):
            old_status = self.status
            self.status = new_status
            if new_status == ShellSessionStatus.AUTHORIZED:
                self.authorized_at = time.time()
                self.expires_at = self.authorized_at + self.max_duration_seconds
            elif new_status == ShellSessionStatus.ACTIVE:
                self.connected_at = time.time()
                self.last_activity_at = time.time()
            elif new_status == ShellSessionStatus.TERMINATING:
                pass
            return True
        return False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["capability_type"] = self.capability_type.value
        d["status"] = self.status.value
        d["created_at_iso"] = datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat()
        d["authorized_at_iso"] = datetime.fromtimestamp(self.authorized_at, tz=timezone.utc).isoformat() if self.authorized_at else None
        d["connected_at_iso"] = datetime.fromtimestamp(self.connected_at, tz=timezone.utc).isoformat() if self.connected_at else None
        d["expires_at_iso"] = datetime.fromtimestamp(self.expires_at, tz=timezone.utc).isoformat() if self.expires_at else None
        return d

    @classmethod
    def from_proposal(cls, proposal: ShellSessionProposal, session_id: str = None) -> "ShellSession":
        """Create a ShellSession from a proposal (status=PROPOSED)."""
        return cls(
            session_id=session_id or f"shell_{uuid.uuid4().hex[:12]}",
            capability_type=proposal.capability_type,
            target=proposal.target,
            username=proposal.username,
            auth_method=proposal.auth_method,
            lhost=proposal.lhost,
            lport=proposal.lport,
            allowed_commands_pattern=proposal.allowed_commands_pattern,
            max_duration_seconds=proposal.max_duration_seconds,
            max_idle_seconds=proposal.max_idle_seconds,
            heartbeat_interval_seconds=proposal.heartbeat_interval_seconds,
            pty_cols=proposal.pty_cols,
            pty_rows=proposal.pty_rows,
            working_directory=proposal.working_directory,
            environment=proposal.environment,
            metadata=proposal.metadata,
            status=ShellSessionStatus.PROPOSED,
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_json(cls, json_str: str) -> "ShellSession":
        data = json.loads(json_str)
        data["capability_type"] = ShellCapabilityType(data["capability_type"])
        data["status"] = ShellSessionStatus(data["status"])
        return cls(**data)


# ── Persistence ───────────────────────────────────────────────────

class ShellSessionStore:
    """
    SQLite-backed persistence for shell sessions.

    Enables crash recovery: on restart, sessions in ACTIVE/IDLE can be
    reaped or resumed. TERMINATED sessions are kept for audit.
    """

    def __init__(self, db_path: str = "data/shell_sessions.db"):
        import os
        import sqlite3
        import tempfile
        import logging

        _log = logging.getLogger("shell_session_store")
        self.db_path = db_path
        # Try to ensure directory exists and is writable
        try:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            # Test write access
            test_path = os.path.join(os.path.dirname(db_path) or ".", ".write_test")
            with open(test_path, "w") as f:
                f.write("test")
            os.unlink(test_path)
        except (OSError, PermissionError):
            # Fall back to temp directory
            tmp_dir = tempfile.mkdtemp(prefix="shell_sessions_")
            self.db_path = os.path.join(tmp_dir, "shell_sessions.db")
            _log.warning("Using fallback db path: %s", self.db_path)

        self._init_db()

    def _init_db(self):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS shell_sessions (
                    session_id TEXT PRIMARY KEY,
                    capability_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    username TEXT DEFAULT '',
                    auth_method TEXT DEFAULT '',
                    lhost TEXT DEFAULT '',
                    lport INTEGER DEFAULT 0,
                    allowed_commands_pattern TEXT NOT NULL,
                    max_duration_seconds INTEGER DEFAULT 3600,
                    max_idle_seconds INTEGER DEFAULT 300,
                    heartbeat_interval_seconds INTEGER DEFAULT 30,
                    pty_cols INTEGER DEFAULT 120,
                    pty_rows INTEGER DEFAULT 40,
                    working_directory TEXT DEFAULT '',
                    environment TEXT DEFAULT '{}',
                    metadata TEXT DEFAULT '{}',
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    authorized_at REAL DEFAULT 0,
                    connected_at REAL DEFAULT 0,
                    expires_at REAL NOT NULL,
                    last_activity_at REAL DEFAULT 0,
                    last_heartbeat_at REAL DEFAULT 0,
                    command_count INTEGER DEFAULT 0,
                    denied_command_count INTEGER DEFAULT 0,
                    last_denied_at REAL DEFAULT 0,
                    current_working_directory TEXT DEFAULT '',
                    updated_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_shell_sessions_status
                ON shell_sessions(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_shell_sessions_expires
                ON shell_sessions(expires_at)
            """)
            conn.commit()

    def save(self, session: ShellSession):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO shell_sessions (
                    session_id, capability_type, target, username, auth_method,
                    lhost, lport, allowed_commands_pattern, max_duration_seconds,
                    max_idle_seconds, heartbeat_interval_seconds, pty_cols, pty_rows,
                    working_directory, environment, metadata, status,
                    created_at, authorized_at, connected_at, expires_at,
                    last_activity_at, last_heartbeat_at, command_count,
                    denied_command_count, last_denied_at, current_working_directory,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id,
                session.capability_type.value,
                session.target,
                session.username,
                session.auth_method,
                session.lhost,
                session.lport,
                session.allowed_commands_pattern,
                session.max_duration_seconds,
                session.max_idle_seconds,
                session.heartbeat_interval_seconds,
                session.pty_cols,
                session.pty_rows,
                session.working_directory,
                json.dumps(session.environment),
                json.dumps(session.metadata),
                session.status.value,
                session.created_at,
                session.authorized_at,
                session.connected_at,
                session.expires_at,
                session.last_activity_at,
                session.last_heartbeat_at,
                session.command_count,
                session.denied_command_count,
                session.last_denied_at,
                session.current_working_directory,
                time.time(),
            ))
            conn.commit()

    def get(self, session_id: str) -> Optional[ShellSession]:
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM shell_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_session(row)

    def get_active_sessions(self) -> list[ShellSession]:
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM shell_sessions WHERE status IN (?, ?, ?, ?)",
                (
                    ShellSessionStatus.AUTHORIZED.value,
                    ShellSessionStatus.CONNECTING.value,
                    ShellSessionStatus.ACTIVE.value,
                    ShellSessionStatus.IDLE.value,
                )
            ).fetchall()
            return [self._row_to_session(r) for r in rows]

    def get_expired_sessions(self) -> list[ShellSession]:
        import sqlite3
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM shell_sessions WHERE expires_at < ? AND status NOT IN (?, ?)",
                (now, ShellSessionStatus.TERMINATED.value, ShellSessionStatus.ERROR.value)
            ).fetchall()
            return [self._row_to_session(r) for r in rows]

    def delete(self, session_id: str):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM shell_sessions WHERE session_id = ?", (session_id,))
            conn.commit()

    def _row_to_session(self, row) -> ShellSession:
        session = ShellSession(
            session_id=row["session_id"],
            capability_type=ShellCapabilityType(row["capability_type"]),
            target=row["target"],
            username=row["username"],
            auth_method=row["auth_method"],
            lhost=row["lhost"],
            lport=row["lport"],
            allowed_commands_pattern=row["allowed_commands_pattern"],
            max_duration_seconds=row["max_duration_seconds"],
            max_idle_seconds=row["max_idle_seconds"],
            heartbeat_interval_seconds=row["heartbeat_interval_seconds"],
            pty_cols=row["pty_cols"],
            pty_rows=row["pty_rows"],
            working_directory=row["working_directory"],
            environment=json.loads(row["environment"]),
            metadata=json.loads(row["metadata"]),
            status=ShellSessionStatus(row["status"]),
            created_at=row["created_at"],
            authorized_at=row["authorized_at"],
            connected_at=row["connected_at"],
            expires_at=row["expires_at"],
            last_activity_at=row["last_activity_at"],
            last_heartbeat_at=row["last_heartbeat_at"],
            command_count=row["command_count"],
            denied_command_count=row["denied_command_count"],
            last_denied_at=row["last_denied_at"],
            current_working_directory=row["current_working_directory"],
        )
        return session