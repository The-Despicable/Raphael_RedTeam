"""
GrowthDB Integration Pipeline — FIXED VERSION (adaptation of user's design).

Root cause (from post-mortem): The existing GrowthDB is in-memory (dict + list),
so findings are never persisted across sessions. The Harvester extracts techniques
into harvester.db but they never reach GrowthDB's in-memory store.

Fix: Add a SQLite-backed persistence layer with schema contracts, atomic merge,
reconciliation logging, and a staging table pattern. This wraps the existing
in-memory GrowthDB with durable storage.

Schema contract v2 — every technique must satisfy required_fields or fail loudly.
"""

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("student.integration")

# ─────────────────────────────────────────────────────────────
# SCHEMA CONTRACT — Version 2
# Every field the pipeline must produce. Missing = fail loudly.
# ─────────────────────────────────────────────────────────────

REQUIRED_FIELDS = {
    "technique_id": str,
    "name": str,
    "class": str,           # e.g. "SQL Injection", "SSRF", "RCE"
    "subclass": str,         # e.g. "UNION-based", "IMDS", "kernel exploit"
    "confidence": float,     # 0.0–1.0
    "cvss_min": float,       # 0.0–10.0
    "target_profiles": list,  # e.g. ["nginx+python+aws"]
    "detection": list,        # payload strings or curl commands
    "chainable_with": list,   # technique_id strings this can chain to
    "source": str,            # "cve_scan", "writeup_ingestion", "scihub", etc.
    "learned": str,           # ISO 8601 timestamp
    "key_references": list,   # URLs or CVE IDs
}

OPTIONAL_FIELDS = {
    "tags": list,
    "failure_reasons": list,
    "derived_from": str,
    "novel_chain": list,
}

# ─────────────────────────────────────────────────────────────
# SCHEMA SQL
# ─────────────────────────────────────────────────────────────

STAGING_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS technique_staging (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    class           TEXT NOT NULL,
    subclass        TEXT DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0.5,
    cvss_min        REAL NOT NULL DEFAULT 5.0,
    target_profiles TEXT NOT NULL DEFAULT '[]',
    detection       TEXT NOT NULL DEFAULT '[]',
    chainable_with  TEXT NOT NULL DEFAULT '[]',
    source          TEXT NOT NULL DEFAULT 'scan',
    learned         TEXT NOT NULL DEFAULT '',
    key_references  TEXT NOT NULL DEFAULT '[]',
    tags            TEXT DEFAULT '[]',
    failure_reasons TEXT DEFAULT '[]',
    derived_from    TEXT DEFAULT '',
    novel_chain     TEXT DEFAULT '[]',
    _ingested_at    TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

MAIN_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS growthdb_main (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    class           TEXT NOT NULL,
    subclass        TEXT DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0.5,
    cvss_min        REAL NOT NULL DEFAULT 5.0,
    target_profiles TEXT NOT NULL DEFAULT '[]',
    detection       TEXT NOT NULL DEFAULT '[]',
    chainable_with  TEXT NOT NULL DEFAULT '[]',
    source          TEXT NOT NULL DEFAULT 'scan',
    learned         TEXT NOT NULL DEFAULT '',
    key_references  TEXT NOT NULL DEFAULT '[]',
    tags            TEXT DEFAULT '[]',
    failure_reasons TEXT DEFAULT '[]',
    derived_from    TEXT DEFAULT '',
    novel_chain     TEXT DEFAULT '[]',
    _first_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    _last_updated   TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

RECONCILIATION_LOG_SQL = """
CREATE TABLE IF NOT EXISTS integration_log (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_time        TEXT NOT NULL DEFAULT (datetime('now')),
    source_records  INTEGER NOT NULL DEFAULT 0,
    staging_inserts INTEGER NOT NULL DEFAULT 0,
    merged_upserts  INTEGER NOT NULL DEFAULT 0,
    errors          TEXT DEFAULT '[]',
    duration_sec    REAL DEFAULT 0.0
)
"""

# ─────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────

STUDENT_DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "student_kb.sqlite"
)


class StudentKB:
    """
    Persistent knowledge base for THE STUDENT.
    
    Wraps the existing in-memory GrowthDB with a SQLite-backed pipeline:
      Harvester → validate → staging → MERGE → main → reconcile
    
    Every technique passes schema validation or gets logged as a failure.
    """

    def __init__(self, db_path: str = STUDENT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self):
        """Create or verify all tables match expected schema."""
        self.conn.execute(STAGING_TABLE_SQL)
        self.conn.execute(MAIN_TABLE_SQL)
        self.conn.execute(RECONCILIATION_LOG_SQL)
        self.conn.commit()

        # Schema validation: check that main table has all required columns
        cursor = self.conn.execute("PRAGMA table_info(growthdb_main)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        required_cols = set(REQUIRED_FIELDS.keys()) | {"_first_seen", "_last_updated"}

        missing = required_cols - existing_cols
        if missing:
            raise RuntimeError(
                f"SCHEMA MISMATCH: growthdb_main missing columns: {missing}\n"
                "Run migration or reinitialize the database."
            )

        logger.info(
            "StudentKB schema validated — %d columns present", len(existing_cols)
        )

    # ── Validation ────────────────────────────────────────────

    def validate_technique(self, technique: dict) -> tuple:
        """
        Validate a technique record against the schema contract.
        Returns (is_valid, list_of_error_messages).
        """
        errors = []

        for field, expected_type in REQUIRED_FIELDS.items():
            if field not in technique:
                errors.append(f"MISSING required field: {field}")
                continue

            value = technique[field]
            if expected_type == list and not isinstance(value, list):
                errors.append(
                    f"FIELD TYPE: {field} should be list, got {type(value).__name__}"
                )
            elif expected_type == float and not isinstance(value, (int, float)):
                errors.append(
                    f"FIELD TYPE: {field} should be float, got {type(value).__name__}"
                )
            elif expected_type == str and not isinstance(value, str):
                errors.append(
                    f"FIELD TYPE: {field} should be str, got {type(value).__name__}"
                )

        tid = technique.get("technique_id", "")
        if not tid or not str(tid).strip():
            errors.append("technique_id is empty or missing")

        conf = technique.get("confidence", -1)
        if not (0.0 <= conf <= 1.0):
            errors.append(f"confidence out of range [0-1]: {conf}")

        ts = technique.get("learned", "")
        if ts:
            try:
                datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                errors.append(f"learned is not valid ISO 8601: {ts}")

        return len(errors) == 0, errors

    # ── Integration ───────────────────────────────────────────

    def integrate(self, techniques: list[dict]) -> dict:
        """
        Atomic integration: Validate → Stage → MERGE → Reconcile.
        
        Returns summary dict with counts and any errors.
        """
        start_time = time.time()
        run_stats = {
            "received": len(techniques),
            "valid": 0,
            "invalid": 0,
            "staged": 0,
            "merged": 0,
            "errors": [],
        }

        # Phase 1: Validate all techniques
        valid_techs = []
        for tech in techniques:
            is_valid, errors = self.validate_technique(tech)
            if is_valid:
                valid_techs.append(tech)
                run_stats["valid"] += 1
            else:
                run_stats["invalid"] += 1
                run_stats["errors"].append({
                    "technique_id": tech.get("technique_id", "UNKNOWN"),
                    "errors": errors,
                })
                logger.warning(
                    "INVALID technique %s: %s",
                    tech.get("technique_id", "UNKNOWN"),
                    errors,
                )

        if run_stats["valid"] == 0 and run_stats["received"] > 0:
            logger.error(
                "INTEGRATION FAILED: 0 valid out of %d. Check schema contract.",
                len(techniques),
            )
            run_stats["errors"].append("ZERO_VALID_TECHNIQUES")
            self._log_run(run_stats, start_time)
            return run_stats

        # Phase 2: Load into staging table
        staged_count = 0
        for tech in valid_techs:
            try:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO technique_staging
                    (technique_id, name, class, subclass, confidence, cvss_min,
                     target_profiles, detection, chainable_with, source, learned,
                     key_references, tags, failure_reasons, derived_from, novel_chain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tech["technique_id"],
                        tech["name"],
                        tech["class"],
                        tech.get("subclass", ""),
                        tech["confidence"],
                        tech["cvss_min"],
                        json.dumps(tech.get("target_profiles", [])),
                        json.dumps(tech.get("detection", [])),
                        json.dumps(tech.get("chainable_with", [])),
                        tech["source"],
                        tech["learned"],
                        json.dumps(tech.get("key_references", [])),
                        json.dumps(tech.get("tags", [])),
                        json.dumps(tech.get("failure_reasons", [])),
                        tech.get("derived_from", ""),
                        json.dumps(tech.get("novel_chain", [])),
                    ),
                )
                staged_count += 1
            except Exception as e:
                run_stats["errors"].append({
                    "technique_id": tech.get("technique_id", "UNKNOWN"),
                    "error": str(e),
                })
                logger.error("STAGING ERROR %s: %s", tech.get("technique_id"), e)

        run_stats["staged"] = staged_count
        self.conn.commit()

        # Phase 3: MERGE staging → main (atomic upsert)
        if staged_count > 0:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO growthdb_main
                    (technique_id, name, class, subclass, confidence, cvss_min,
                     target_profiles, detection, chainable_with, source, learned,
                     key_references, tags, failure_reasons, derived_from, novel_chain,
                     _first_seen, _last_updated)
                    SELECT
                        s.technique_id, s.name, s.class, s.subclass,
                        s.confidence, s.cvss_min,
                        s.target_profiles, s.detection, s.chainable_with,
                        s.source, s.learned,
                        s.key_references, s.tags, s.failure_reasons,
                        s.derived_from, s.novel_chain,
                        COALESCE(m._first_seen, datetime('now')),
                        datetime('now')
                    FROM technique_staging s
                    LEFT JOIN growthdb_main m
                        ON s.technique_id = m.technique_id
                    """
                )
                merged = self.conn.execute("SELECT changes()").fetchone()[0]
                run_stats["merged"] = merged

                self.conn.execute("DELETE FROM technique_staging")
                self.conn.commit()

                logger.info(
                    "INTEGRATION SUCCESS: %d staged → %d merged (%d total in KB)",
                    staged_count,
                    merged,
                    self.conn.execute(
                        "SELECT COUNT(*) FROM growthdb_main"
                    ).fetchone()[0],
                )

            except Exception as e:
                self.conn.rollback()
                run_stats["errors"].append(f"MERGE FAILED: {e}")
                logger.error("MERGE FAILED — rolling back: %s", e)

        # Phase 4: Reconciliation audit
        self._log_run(run_stats, start_time)

        # Diagnostic: if merge produced 0 rows but staging had rows
        if staged_count > 0 and run_stats["merged"] == 0:
            logger.warning(
                "DIAGNOSTIC: %d rows staged but 0 merged — possible key collision",
                staged_count,
            )

        return run_stats

    def _log_run(self, stats: dict, start_time: float):
        """Log integration run to reconciliation table."""
        duration = time.time() - start_time
        self.conn.execute(
            """
            INSERT INTO integration_log
            (source_records, staging_inserts, merged_upserts, errors, duration_sec)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                stats["received"],
                stats["staged"],
                stats["merged"],
                json.dumps(stats["errors"][:20]),
                round(duration, 2),
            ),
        )
        self.conn.commit()

    # ── Queries ───────────────────────────────────────────────

    def get_techniques(
        self, limit: int = 100, class_filter: Optional[str] = None
    ) -> list[dict]:
        """Get techniques from the main KB."""
        query = "SELECT * FROM growthdb_main"
        params = []
        if class_filter:
            query += " WHERE class = ?"
            params.append(class_filter)
        query += " ORDER BY _last_updated DESC LIMIT ?"
        params.append(limit)

        cursor = self.conn.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = []
        for row in cursor.fetchall():
            tech = dict(zip(columns, row))
            for jf in [
                "target_profiles",
                "detection",
                "chainable_with",
                "key_references",
                "tags",
                "failure_reasons",
                "novel_chain",
            ]:
                if tech.get(jf) and isinstance(tech[jf], str):
                    try:
                        tech[jf] = json.loads(tech[jf])
                    except (json.JSONDecodeError, TypeError):
                        tech[jf] = []
            results.append(tech)
        return results

    def get_findings(self, limit: int = 100) -> list[dict]:
        """Backwards-compatible alias for get_techniques."""
        return self.get_techniques(limit=limit)

    def stats(self) -> dict:
        """Return summary statistics."""
        return {
            "total": self.conn.execute(
                "SELECT COUNT(*) FROM growthdb_main"
            ).fetchone()[0],
            "by_class": {
                row[0]: row[1]
                for row in self.conn.execute(
                    "SELECT class, COUNT(*) FROM growthdb_main GROUP BY class"
                ).fetchall()
            },
            "by_source": {
                row[0]: row[1]
                for row in self.conn.execute(
                    "SELECT source, COUNT(*) FROM growthdb_main GROUP BY source"
                ).fetchall()
            },
        }

    def diagnostic_report(self) -> dict:
        """Full pipeline health report."""
        report = {
            "total_in_kb": self.conn.execute(
                "SELECT COUNT(*) FROM growthdb_main"
            ).fetchone()[0],
            "by_source": {},
            "by_class": {},
            "recent_integrations": [],
            "schema_status": "OK",
        }

        cursor = self.conn.execute(
            "SELECT source, COUNT(*) FROM growthdb_main GROUP BY source"
        )
        for row in cursor:
            report["by_source"][row[0]] = row[1]

        cursor = self.conn.execute(
            "SELECT class, COUNT(*) FROM growthdb_main GROUP BY class"
        )
        for row in cursor:
            report["by_class"][row[0]] = row[1]

        cursor = self.conn.execute(
            "SELECT run_time, source_records, staging_inserts, merged_upserts, errors "
            "FROM integration_log ORDER BY run_id DESC LIMIT 10"
        )
        for row in cursor:
            report["recent_integrations"].append({
                "time": row[0],
                "received": row[1],
                "staged": row[2],
                "merged": row[3],
                "has_errors": bool(row[4] and row[4] != "[]"),
            })

        return report

    # ── Helpers ───────────────────────────────────────────────

    def record(self, key: str, value: Any) -> None:
        """Legacy: store any key-value in the metadata store."""
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS kv_store (key TEXT PRIMARY KEY, value TEXT)"
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value) VALUES (?, ?)",
            (key, json.dumps(value)),
        )
        self.conn.commit()

    def retrieve(self, key: str) -> Any:
        """Legacy: retrieve from key-value store."""
        try:
            row = self.conn.execute(
                "SELECT value FROM kv_store WHERE key = ?", (key,)
            ).fetchone()
            if row:
                return json.loads(row[0])
        except Exception:
            pass
        return None

    def store_finding(self, finding: dict) -> None:
        """Legacy: store a single finding (wraps integrate)."""
        self.integrate([finding])

    def close(self):
        self.conn.close()
