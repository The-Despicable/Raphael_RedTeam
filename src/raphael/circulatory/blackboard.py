"""Blackboard — SQLite persistent shared state for Raphael."""
import sqlite3
import json
import time
import asyncio
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("raphael.blackboard")

class Blackboard:
    """Append-mostly SQLite state store. All organs read/write here."""

    DB_PATH = Path(__file__).parent.parent / "data" / "raphael_blackboard.db"

    def __init__(self, db_path: str | None = None):
        self._path = Path(db_path) if db_path else self.DB_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    def connect(self):
        """Open connection and create tables if needed."""
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL;")
        self._conn.execute("PRAGMA synchronous = NORMAL;")
        self._create_tables()

    def _create_tables(self):
        c = self._conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS target_model (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT 'network',
                constraints TEXT DEFAULT '[]',
                affordances TEXT DEFAULT '[]',
                unknowns TEXT DEFAULT '[]',
                timestamp REAL NOT NULL,
                component TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS capability_model (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                capability_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'gap',
                acquisition_cost REAL DEFAULT 0.0,
                expires_at REAL,
                timestamp REAL NOT NULL,
                component TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS execution_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                cycle INTEGER NOT NULL,
                technique TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0,
                failure_class TEXT,
                output_summary TEXT,
                latency_ms REAL,
                timestamp REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                score REAL NOT NULL,
                component TEXT DEFAULT '',
                timestamp REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload TEXT DEFAULT '{}',
                publisher TEXT DEFAULT '',
                timestamp REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS engagement_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL UNIQUE,
                current_cycle INTEGER DEFAULT 0,
                target TEXT DEFAULT '',
                status TEXT DEFAULT 'running',
                profile_json TEXT DEFAULT '{}',
                is_stuck INTEGER DEFAULT 0,
                updated_at REAL NOT NULL
            );
        """)
        self._conn.commit()

    async def write_target_model(self, engagement_id: str, domain: str,
                                  constraints: list, affordances: list,
                                  unknowns: list, component: str = "unknown"):
        async with self._lock:
            self._conn.execute(
                """INSERT INTO target_model (engagement_id, domain, constraints, affordances,
                   unknowns, timestamp, component) VALUES (?,?,?,?,?,?,?)""",
                (engagement_id, domain, json.dumps(constraints), json.dumps(affordances),
                 json.dumps(unknowns), time.time(), component)
            )
            self._conn.commit()

    async def read_latest_target(self, engagement_id: str) -> dict:
        """Read the latest target model state."""
        async with self._lock:
            c = self._conn.execute(
                "SELECT * FROM target_model WHERE engagement_id=? ORDER BY id DESC LIMIT 1",
                (engagement_id,)
            )
            row = c.fetchone()
            if not row:
                return {"constraints": [], "affordances": [], "unknowns": []}
            return {
                "constraints": json.loads(row["constraints"]),
                "affordances": json.loads(row["affordances"]),
                "unknowns": json.loads(row["unknowns"]),
                "domain": row["domain"],
            }

    async def write_execution_log(self, engagement_id: str, cycle: int,
                                  technique: str, success: bool,
                                  failure_class: str | None = None,
                                  output_summary: str = "",
                                  latency_ms: float = 0.0):
        async with self._lock:
            self._conn.execute(
                """INSERT INTO execution_log (engagement_id, cycle, technique, success,
                   failure_class, output_summary, latency_ms, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (engagement_id, cycle, technique, 1 if success else 0,
                 failure_class, output_summary[:500], latency_ms, time.time())
            )
            self._conn.commit()

    async def write_risk_score(self, engagement_id: str, score: float,
                                component: str = "thermoregulator"):
        async with self._lock:
            self._conn.execute(
                "INSERT INTO risk_scores (engagement_id, score, component, timestamp) VALUES (?,?,?,?)",
                (engagement_id, score, component, time.time())
            )
            self._conn.commit()

    async def write_event(self, event_type: str, payload: dict,
                           publisher: str = ""):
        async with self._lock:
            self._conn.execute(
                "INSERT INTO events (event_type, payload, publisher, timestamp) VALUES (?,?,?,?)",
                (event_type, json.dumps(payload), publisher, time.time())
            )
            self._conn.commit()

    async def get_engagement_state(self, engagement_id: str) -> dict | None:
        async with self._lock:
            c = self._conn.execute(
                "SELECT * FROM engagement_state WHERE engagement_id=?",
                (engagement_id,)
            )
            row = c.fetchone()
            if not row:
                return None
            return dict(row)

    async def save_engagement_state(self, engagement_id: str, target: str,
                                     current_cycle: int, status: str = "running",
                                     profile_json: str = "{}", is_stuck: bool = False):
        async with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO engagement_state
                   (engagement_id, current_cycle, target, status, profile_json, is_stuck, updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (engagement_id, current_cycle, target, status,
                 profile_json, 1 if is_stuck else 0, time.time())
            )
            self._conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
