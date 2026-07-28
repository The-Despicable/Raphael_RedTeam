"""
GrowthDB — Persistent knowledge store for Raphael.

Wraps the SQLite-backed StudentKB pipeline for durability.
Keeps backward compatibility with the original in-memory API
while persisting all data to disk.

v2 upgrade:
  - All writes go through the StudentKB integration pipeline
    (schema validation → staging → atomic MERGE → reconciliation logging)
  - All reads fall back to in-memory cache for speed
  - No data loss on process restart
"""

import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger("growth_db")


class GrowthDB:
    """
    Persistent GrowthDB that delegates to StudentKB for storage.
    
    Backward-compatible with the original in-memory API:
      record(key, value)    → stored in SQLite kv_store
      retrieve(key)         → read from SQLite kv_store
      store_finding(dict)   → validated and merged into growthdb_main
      get_findings(limit)   → read from growthdb_main (SQLite)
      stats()               → summary from SQLite
    
    New API:
      get_techniques(limit, class_filter)  → same as get_findings with optional filter
      diagnostic_report()                  → pipeline health
    """

    def __init__(self, db_path: Optional[str] = None):
        self._store: dict[str, Any] = {}
        self._findings: list[dict] = []

        # Lazily initialize the persistent KB
        self._kb = None
        self._db_path = db_path

    def _get_kb(self):
        """Lazy-init the persistent StudentKB."""
        if self._kb is None:
            try:
                from orchestrator.student.integration_pipeline import (
                    StudentKB,
                    STUDENT_DB_PATH,
                )
                path = self._db_path or STUDENT_DB_PATH
                self._kb = StudentKB(db_path=path)
                logger.info("GrowthDB: Persistent StudentKB initialized at %s", path)
            except Exception as e:
                logger.warning("GrowthDB: StudentKB not available, using in-memory: %s", e)
        return self._kb

    def record(self, key: str, value: Any) -> None:
        """Store any key-value (delegates to StudentKB kv_store)."""
        self._store[key] = {"value": value, "timestamp": time.time()}
        kb = self._get_kb()
        if kb:
            try:
                kb.record(key, value)
            except Exception as e:
                logger.debug("GrowthDB: failed to persist record: %s", e)

    def retrieve(self, key: str) -> Any:
        """Retrieve from key-value store."""
        entry = self._store.get(key)
        if entry is not None:
            return entry["value"]

        # Fallback: try persistent store
        kb = self._get_kb()
        if kb:
            try:
                value = kb.retrieve(key)
                if value is not None:
                    self._store[key] = {"value": value, "timestamp": time.time()}
                    return value
            except Exception:
                pass
        return None

    def store_finding(self, finding: dict) -> None:
        """
        Store a finding with schema validation through the pipeline.
        
        The finding dict should have at minimum:
          technique_id, name, class, confidence, cvss_min, source, learned
        """
        # Always keep an in-memory copy
        self._findings.append(finding)

        # Also persist through the pipeline
        kb = self._get_kb()
        if kb:
            try:
                result = kb.integrate([finding])
                if result["errors"]:
                    logger.warning(
                        "GrowthDB: integration errors for %s: %s",
                        finding.get("technique_id", "?"),
                        result["errors"][:2],
                    )
            except Exception as e:
                logger.debug("GrowthDB: persistence failed: %s", e)

    def get_findings(self, limit: int = 100) -> list[dict]:
        """
        Get findings/knowledge entries.
        
        First tries persistent StudentKB (richer data with all fields).
        Falls back to in-memory cache.
        """
        kb = self._get_kb()
        if kb:
            try:
                return kb.get_techniques(limit=limit)
            except Exception as e:
                logger.debug("GrowthDB: KB read failed, using in-memory: %s", e)

        # Fallback: in-memory cache
        return self._findings[-limit:]

    def get_techniques(self, limit: int = 100,
                       class_filter: Optional[str] = None) -> list[dict]:
        """
        Get techniques, optionally filtered by class.
        Delegates to StudentKB for richer persistence.
        """
        kb = self._get_kb()
        if kb:
            try:
                return kb.get_techniques(limit=limit, class_filter=class_filter)
            except Exception as e:
                logger.debug("GrowthDB: get_techniques failed: %s", e)

        # Fallback: in-memory filter
        results = self._findings[-limit:]
        if class_filter:
            results = [
                f for f in results
                if f.get("class", "").lower() == class_filter.lower()
            ]
        return results

    def diagnostic_report(self) -> dict:
        """Full pipeline health report."""
        report = {
            "in_memory_entries": len(self._store),
            "in_memory_findings": len(self._findings),
            "persistent_store": "unavailable",
            "total_in_kb": 0,
            "by_source": {},
            "by_class": {},
            "schema_status": "unknown",
        }

        kb = self._get_kb()
        if kb:
            try:
                diag = kb.diagnostic_report()
                report["persistent_store"] = "active"
                report["total_in_kb"] = diag.get("total_in_kb", 0)
                report["by_source"] = diag.get("by_source", {})
                report["by_class"] = diag.get("by_class", {})
                report["schema_status"] = diag.get("schema_status", "OK")
                report["recent_integrations"] = diag.get("recent_integrations", [])
            except Exception as e:
                report["persistent_store"] = f"error: {e}"

        return report

    def stats(self) -> dict:
        """Return summary statistics."""
        kb = self._get_kb()
        if kb:
            try:
                return kb.stats()
            except Exception:
                pass
        return {
            "entries": len(self._store),
            "findings": len(self._findings),
        }

    @property
    def conn(self):
        """
        Backward-compatible access to the underlying SQLite connection.
        Used by student.py for direct SQL queries.
        """
        kb = self._get_kb()
        if kb:
            return kb.conn
        raise AttributeError(
            "GrowthDB: no SQLite connection available "
            "(StudentKB not initialized)"
        )

    def record_technique_result(
        self, technique_name: str, category: str, success: bool,
    ) -> None:
        """Record a technique test result for confidence tracking."""
        try:
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS techniques (
                    technique_name TEXT PRIMARY KEY,
                    category TEXT,
                    success_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    last_used REAL,
                    confidence REAL DEFAULT 0.5
                )"""
            )
            if success:
                self.conn.execute(
                    """INSERT INTO techniques (technique_name, category, success_count, last_used, confidence)
                       VALUES (?, ?, 1, ?, 0.5)
                       ON CONFLICT(technique_name) DO UPDATE SET
                       success_count = success_count + 1, last_used = ?,
                       confidence = MIN(confidence + 0.05, 1.0)""",
                    (technique_name, category, time.time(), time.time()),
                )
            else:
                self.conn.execute(
                    """INSERT INTO techniques (technique_name, category, fail_count, last_used, confidence)
                       VALUES (?, ?, 1, ?, 0.5)
                       ON CONFLICT(technique_name) DO UPDATE SET
                       fail_count = fail_count + 1, last_used = ?,
                       confidence = MAX(confidence - 0.1, 0.1)""",
                    (technique_name, category, time.time(), time.time()),
                )
            self.conn.commit()
        except Exception as e:
            logger.debug("GrowthDB: record_technique_result failed: %s", e)
