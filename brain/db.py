"""Async-friendly SQLite persistence for the Autonomous Brain.

Uses aiosqlite for non-blocking access on the FastAPI event loop. Tables:
tasks, steps, findings, evidence (json), hypotheses, contradictions,
trust_logs, notes, checkpoints.

On startup the schema is created idempotently and any in-progress tasks are
re-loaded into the coordinator registry.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import aiosqlite

from .config import Settings, get_settings

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    engagement_id TEXT,
    target TEXT NOT NULL,
    goal TEXT,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    step TEXT,
    constraints_json TEXT,
    budget_limit INTEGER,
    budget_used INTEGER DEFAULT 0,
    risk TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS steps (
    step_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    name TEXT NOT NULL,
    tool TEXT,
    status TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    result_summary TEXT,
    args_json TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);
CREATE INDEX IF NOT EXISTS idx_steps_task ON steps(task_id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    target TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_ref TEXT,
    confidence REAL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    kind TEXT NOT NULL,
    node_id TEXT NOT NULL,
    attributes_json TEXT,
    source TEXT,
    confidence REAL DEFAULT 1.0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence(task_id);
CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence(kind);

CREATE TABLE IF NOT EXISTS evidence_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    relation TEXT NOT NULL,
    attributes_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON evidence_edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON evidence_edges(dst);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    statement TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    status TEXT DEFAULT 'open',
    evidence_refs_json TEXT,
    parent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contradictions (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    status TEXT NOT NULL,
    subjects_json TEXT,
    detail TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    score REAL NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trust_subject ON trust_logs(subject);

CREATE TABLE IF NOT EXISTS notes (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    tags_json TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    task_id TEXT,
    note TEXT,
    payload_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON checkpoints(task_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT NOT NULL,
    subject TEXT,
    detail TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_log(subject);
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id(prefix: str = "t") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class BrainDB:
    """Async wrapper around aiosqlite. Singleton per process is fine because
    aiosqlite serializes writes through a single thread.

    Avoid fragile singletons in production code by passing a BrainDB instance
    explicitly to services that need it. The module-level `get_db()` is only a
    convenience for the FastAPI dependency system.
    """

    def __init__(self, path: str):
        self.path = path
        self._conn: Optional[aiosqlite.Connection] = None
        self._init_lock_count = 0

    async def init(self) -> None:
        """Open connection and apply schema idempotently.

        PRAGMAs: WAL for concurrent-read resilience while the event loop
        writes; foreign_keys=ON so the declared FKs on steps/findings are
        actually enforced (SQLite defaults them OFF); busy_timeout so brief
        cross-process access (e.g. sqlite3 CLI during debugging) does not
        fail instantly.
        """
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA foreign_keys=ON",
            "PRAGMA busy_timeout=5000",
        ):
            await self._conn.execute(pragma)
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _exec(self, sql: str, params: Tuple = ()) -> sqlite3.Cursor:
        assert self._conn is not None, "BrainDB.init() not called"
        cur = await self._conn.execute(sql, params)
        await self._conn.commit()
        return cur

    async def _fetchall(self, sql: str, params: Tuple = ()) -> List[aiosqlite.Row]:
        assert self._conn is not None
        async with self._conn.execute(sql, params) as cur:
            return await cur.fetchall()

    async def _fetchone(self, sql: str, params: Tuple = ()) -> Optional[aiosqlite.Row]:
        async with self._conn.execute(sql, params) as cur:
            return await cur.fetchone()

    # ------------------------------------------------------------------ tasks
    async def insert_task(self, task: Dict[str, Any]) -> None:
        now = _utcnow_iso()
        await self._exec(
            """INSERT INTO tasks
               (task_id, engagement_id, target, goal, mode, state, step,
                constraints_json, budget_limit, budget_used, risk,
                created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                task["task_id"],
                task.get("engagement_id"),
                task["target"],
                task.get("goal"),
                task.get("mode", "recon"),
                task.get("state", "pending"),
                task.get("step"),
                json.dumps(task.get("constraints") or {}),
                task.get("budget_limit"),
                task.get("budget_used", 0),
                task.get("risk"),
                now,
                now,
            ),
        )

    async def update_task_state(
        self,
        task_id: str,
        state: str,
        step: Optional[str] = None,
        budget_used: Optional[int] = None,
        risk: Optional[str] = None,
    ) -> None:
        fields = ["state = ?", "updated_at = ?"]
        params: List[Any] = [state, _utcnow_iso()]
        if step is not None:
            fields.append("step = ?")
            params.append(step)
        if budget_used is not None:
            fields.append("budget_used = ?")
            params.append(budget_used)
        if risk is not None:
            fields.append("risk = ?")
            params.append(risk)
        params.append(task_id)
        await self._exec(f"UPDATE tasks SET {', '.join(fields)} WHERE task_id = ?", tuple(params))

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        row = await self._fetchone("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
        return dict(row) if row else None

    async def list_tasks(
        self,
        state: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM tasks WHERE 1=1"
        params: List[Any] = []
        if state:
            sql += " AND state = ?"
            params.append(state)
        if target:
            sql += " AND target = ?"
            params.append(target)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = await self._fetchall(sql, tuple(params))
        return [dict(r) for r in rows]

    async def list_active_targets(self) -> List[str]:
        rows = await self._fetchall(
            "SELECT DISTINCT target FROM tasks WHERE state IN ('running','paused','awaiting_approval')"
        )
        return [r["target"] for r in rows]

    # ------------------------------------------------------------------ steps
    async def insert_step(self, step: Dict[str, Any]) -> None:
        await self._exec(
            """INSERT OR REPLACE INTO steps
               (step_id, task_id, name, tool, status, started_at,
                finished_at, result_summary, args_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                step["step_id"],
                step["task_id"],
                step["name"],
                step.get("tool"),
                step.get("status", "pending"),
                step.get("started_at"),
                step.get("finished_at"),
                step.get("result_summary"),
                json.dumps(step.get("args") or []),
            ),
        )

    async def update_step(
        self,
        step_id: str,
        status: str,
        result_summary: Optional[str] = None,
        finished_at: Optional[str] = None,
    ) -> None:
        await self._exec(
            """UPDATE steps SET status = ?, result_summary = ?, finished_at = ?
               WHERE step_id = ?""",
            (status, result_summary, finished_at or _utcnow_iso(), step_id),
        )

    async def list_steps(self, task_id: str) -> List[Dict[str, Any]]:
        rows = await self._fetchall(
            "SELECT * FROM steps WHERE task_id = ? ORDER BY rowid", (task_id,)
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["args"] = json.loads(d.get("args_json") or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                d["args"] = []
            out.append(d)
        return out

    # --------------------------------------------------------------- findings
    async def insert_finding(self, finding: Dict[str, Any]) -> int:
        cur = await self._exec(
            """INSERT INTO findings
               (task_id, target, severity, title, description,
                evidence_ref, confidence, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                finding.get("task_id"),
                finding["target"],
                finding.get("severity", "info"),
                finding["title"],
                finding.get("description", ""),
                finding.get("evidence_ref"),
                finding.get("confidence", 1.0),
                _utcnow_iso(),
            ),
        )
        return cur.lastrowid or 0

    async def list_findings(
        self,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        task_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if target:
            sql += " AND target = ?"
            params.append(target)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if task_id:
            sql += " AND task_id = ?"
            params.append(task_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = await self._fetchall(sql, tuple(params))
        return [dict(r) for r in rows]

    async def get_finding(self, finding_id: int) -> Optional[Dict[str, Any]]:
        row = await self._fetchone("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return dict(row) if row else None

    async def count_findings(self, task_id: Optional[str] = None) -> int:
        if task_id:
            row = await self._fetchone(
                "SELECT COUNT(*) AS c FROM findings WHERE task_id = ?", (task_id,)
            )
        else:
            row = await self._fetchone("SELECT COUNT(*) AS c FROM findings")
        return row["c"] if row else 0

    async def count_findings_bulk(self, task_ids: List[str]) -> Dict[str, int]:
        """Single GROUP BY instead of one COUNT per task (fixes N+1 in /tasks)."""
        if not task_ids:
            return {}
        placeholders = ",".join("?" for _ in task_ids)
        rows = await self._fetchall(
            f"SELECT task_id, COUNT(*) AS c FROM findings "
            f"WHERE task_id IN ({placeholders}) GROUP BY task_id",
            tuple(task_ids),
        )
        return {r["task_id"]: r["c"] for r in rows}

    # --------------------------------------------------------------- evidence
    async def insert_evidence_node(self, node: Dict[str, Any]) -> None:
        await self._exec(
            """INSERT INTO evidence (task_id, kind, node_id, attributes_json,
                                      source, confidence, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                node.get("task_id"),
                node.get("kind", "unknown"),
                node["node_id"],
                json.dumps(node.get("attributes") or {}),
                node.get("source"),
                node.get("confidence", 1.0),
                _utcnow_iso(),
            ),
        )

    async def insert_evidence_edge(self, edge: Dict[str, Any]) -> None:
        await self._exec(
            """INSERT INTO evidence_edges
               (task_id, src, dst, relation, attributes_json, created_at)
               VALUES (?,?,?,?,?,?)""",
            (
                edge.get("task_id"),
                edge["src"],
                edge["dst"],
                edge["relation"],
                json.dumps(edge.get("attributes") or {}),
                _utcnow_iso(),
            ),
        )

    async def evidence_node_exists(self, node_id: str, task_id: Optional[str]) -> bool:
        """Used by ingest dedup (merge=True)."""
        if task_id is None:
            row = await self._fetchone(
                "SELECT 1 FROM evidence WHERE node_id = ? AND task_id IS NULL LIMIT 1",
                (node_id,),
            )
        else:
            row = await self._fetchone(
                "SELECT 1 FROM evidence WHERE node_id = ? AND task_id = ? LIMIT 1",
                (node_id, task_id),
            )
        return row is not None

    async def count_evidence(self, task_id: Optional[str] = None) -> Dict[str, int]:
        """Cheap COUNT queries (ingest totals) instead of full table scans."""
        if task_id:
            node_row = await self._fetchone(
                "SELECT COUNT(*) AS c FROM evidence WHERE task_id = ? OR task_id IS NULL",
                (task_id,),
            )
            edge_row = await self._fetchone(
                "SELECT COUNT(*) AS c FROM evidence_edges WHERE task_id = ? OR task_id IS NULL",
                (task_id,),
            )
        else:
            node_row = await self._fetchone("SELECT COUNT(*) AS c FROM evidence")
            edge_row = await self._fetchone("SELECT COUNT(*) AS c FROM evidence_edges")
        return {"nodes": node_row["c"] if node_row else 0, "edges": edge_row["c"] if edge_row else 0}

    async def list_evidence(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        if task_id:
            node_rows = await self._fetchall(
                "SELECT * FROM evidence WHERE task_id = ? OR task_id IS NULL ORDER BY id",
                (task_id,),
            )
            edge_rows = await self._fetchall(
                "SELECT * FROM evidence_edges WHERE task_id = ? OR task_id IS NULL ORDER BY id",
                (task_id,),
            )
        else:
            node_rows = await self._fetchall("SELECT * FROM evidence ORDER BY id")
            edge_rows = await self._fetchall("SELECT * FROM evidence_edges ORDER BY id")

        nodes = []
        for r in node_rows:
            d = dict(r)
            d["attributes"] = json.loads(d.get("attributes_json") or "{}")
            nodes.append(d)
        edges = []
        for r in edge_rows:
            d = dict(r)
            d["attributes"] = json.loads(d.get("attributes_json") or "{}")
            edges.append(d)
        return {"nodes": nodes, "edges": edges}

    # ----------------------------------------------------------- hypotheses
    async def insert_hypothesis(self, hyp: Dict[str, Any]) -> None:
        now = _utcnow_iso()
        await self._exec(
            """INSERT OR REPLACE INTO hypotheses
               (id, task_id, statement, confidence, status,
                evidence_refs_json, parent_id, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                hyp["id"],
                hyp.get("task_id"),
                hyp["statement"],
                hyp.get("confidence", 0.5),
                hyp.get("status", "open"),
                json.dumps(hyp.get("evidence_refs") or []),
                hyp.get("parent_id"),
                now,
                now,
            ),
        )

    async def update_hypothesis(
        self, hyp_id: str, confidence: Optional[float] = None, status: Optional[str] = None
    ) -> None:
        fields = ["updated_at = ?"]
        params: List[Any] = [_utcnow_iso()]
        if confidence is not None:
            fields.append("confidence = ?")
            params.append(confidence)
        if status is not None:
            fields.append("status = ?")
            params.append(status)
        params.append(hyp_id)
        await self._exec(
            f"UPDATE hypotheses SET {', '.join(fields)} WHERE id = ?", tuple(params)
        )

    async def list_hypotheses(self, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if task_id:
            rows = await self._fetchall(
                "SELECT * FROM hypotheses WHERE task_id = ? OR task_id IS NULL ORDER BY created_at DESC",
                (task_id,),
            )
        else:
            rows = await self._fetchall(
                "SELECT * FROM hypotheses ORDER BY created_at DESC"
            )
        out = []
        for r in rows:
            d = dict(r)
            d["evidence_refs"] = json.loads(d.get("evidence_refs_json") or "[]")
            out.append(d)
        return out

    async def get_hypothesis(self, hyp_id: str) -> Optional[Dict[str, Any]]:
        row = await self._fetchone("SELECT * FROM hypotheses WHERE id = ?", (hyp_id,))
        if not row:
            return None
        d = dict(row)
        d["evidence_refs"] = json.loads(d.get("evidence_refs_json") or "[]")
        return d

    # -------------------------------------------------------- contradictions
    async def insert_contradiction(self, c: Dict[str, Any]) -> None:
        await self._exec(
            """INSERT INTO contradictions
               (id, task_id, status, subjects_json, detail, created_at)
               VALUES (?,?,?,?,?,?)""",
            (
                c["id"],
                c.get("task_id"),
                c.get("status", "open"),
                json.dumps(c.get("subjects") or []),
                c.get("detail"),
                _utcnow_iso(),
            ),
        )

    async def list_contradictions(self, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if task_id:
            rows = await self._fetchall(
                "SELECT * FROM contradictions WHERE task_id = ? OR task_id IS NULL ORDER BY created_at DESC",
                (task_id,),
            )
        else:
            rows = await self._fetchall(
                "SELECT * FROM contradictions ORDER BY created_at DESC"
            )
        out = []
        for r in rows:
            d = dict(r)
            d["subjects"] = json.loads(d.get("subjects_json") or "[]")
            out.append(d)
        return out

    # ----------------------------------------------------------- trust logs
    async def log_trust(self, subject: str, score: float, reason: str = "") -> None:
        await self._exec(
            "INSERT INTO trust_logs (subject, score, reason, created_at) VALUES (?,?,?,?)",
            (subject, score, reason, _utcnow_iso()),
        )

    async def get_trust(self, subject: str) -> Dict[str, Any]:
        row = await self._fetchone(
            "SELECT AVG(score) AS avg, COUNT(*) AS c, MAX(created_at) AS last FROM trust_logs WHERE subject = ?",
            (subject,),
        )
        if not row or not row["c"]:
            return {"subject": subject, "score": 0.5, "samples": 0, "last_updated": None}
        return {
            "subject": subject,
            "score": row["avg"],
            "samples": row["c"],
            "last_updated": row["last"],
        }

    # -------------------------------------------------------------- notes
    async def upsert_note(self, key: str, value: Any, tags: List[str]) -> Dict[str, Any]:
        value_str = json.dumps(value) if not isinstance(value, str) else value
        await self._exec(
            "INSERT INTO notes (key, value, tags_json, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
            "tags_json=excluded.tags_json, updated_at=excluded.updated_at",
            (key, value_str, json.dumps(tags), _utcnow_iso()),
        )
        return {"key": key, "value": value, "tags": tags, "updated_at": _utcnow_iso()}

    async def get_note(self, key: str) -> Optional[Dict[str, Any]]:
        row = await self._fetchone("SELECT * FROM notes WHERE key = ?", (key,))
        if not row:
            return None
        d = dict(row)
        try:
            d["value"] = json.loads(d["value"])
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        d["tags"] = json.loads(d.get("tags_json") or "[]")
        return d

    async def list_notes(self) -> List[Dict[str, Any]]:
        rows = await self._fetchall("SELECT * FROM notes ORDER BY updated_at DESC")
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["value"] = json.loads(d["value"])
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
            d["tags"] = json.loads(d.get("tags_json") or "[]")
            out.append(d)
        return out

    async def delete_note(self, key: str) -> bool:
        cur = await self._exec("DELETE FROM notes WHERE key = ?", (key,))
        return cur.rowcount > 0

    # ----------------------------------------------------------- checkpoints
    async def insert_checkpoint(
        self, label: str, task_id: Optional[str], note: Optional[str], payload: Optional[Dict]
    ) -> Dict[str, Any]:
        cur = await self._exec(
            """INSERT INTO checkpoints (label, task_id, note, payload_json, created_at)
               VALUES (?,?,?,?,?)""",
            (label, task_id, note, json.dumps(payload) if payload else None, _utcnow_iso()),
        )
        return {
            "id": cur.lastrowid,
            "label": label,
            "task_id": task_id,
            "note": note,
            "payload": payload,
            "created_at": _utcnow_iso(),
        }

    async def list_checkpoints(self, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if task_id:
            rows = await self._fetchall(
                "SELECT * FROM checkpoints WHERE task_id = ? ORDER BY id DESC", (task_id,)
            )
        else:
            rows = await self._fetchall("SELECT * FROM checkpoints ORDER BY id DESC")
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d.get("payload_json") or "null")
            out.append(d)
        return out

    # --------------------------------------------------------------- audit
    async def audit(self, actor: str, action: str, subject: str = "", detail: str = "") -> None:
        await self._exec(
            "INSERT INTO audit_log (actor, action, subject, detail, created_at) VALUES (?,?,?,?,?)",
            (actor, action, subject, detail, _utcnow_iso()),
        )


# ---------------------------------------------------------------------------
# Module-level singleton (FastAPI-friendly).
# ---------------------------------------------------------------------------

_db: Optional[BrainDB] = None


async def init_db(settings: Optional[Settings] = None) -> BrainDB:
    global _db
    settings = settings or get_settings()
    _db = BrainDB(settings.brain_db)
    await _db.init()
    return _db


async def get_db() -> BrainDB:
    """FastAPI dependency. Asserts init_db() was called during lifespan."""
    if _db is None:
        await init_db()
    assert _db is not None
    return _db


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None


@asynccontextmanager
async def db_session() -> AsyncIterator[BrainDB]:
    """Context manager for tests / background work outside FastAPI deps."""
    db = await get_db()
    try:
        yield db
    finally:
        pass
