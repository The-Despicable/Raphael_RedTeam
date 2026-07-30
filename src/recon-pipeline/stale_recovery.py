"""Stale recovery and in-flight guard for case collection pipeline."""

import json, logging, time
from pathlib import Path
from typing import Optional

from case_store import CaseStore

logger = logging.getLogger("stale_recovery")


def recover_stale_cases(db_path: str, threshold_minutes: int = 10) -> int:
    """Reset cases stuck in 'processing' status back to 'pending'.
    Returns count of recovered cases."""
    store = CaseStore(db_path)
    count = store.reset_stale(threshold_minutes)
    store.close()
    return count


def get_in_flight_summary(db_path: str) -> dict:
    """Get summary of currently in-flight cases grouped by agent and type."""
    store = CaseStore(db_path)
    c = store._cursor()
    rows = c.execute(
        "SELECT assigned_agent, type, stage, COUNT(*) as count FROM cases WHERE status='processing' GROUP BY assigned_agent, type, stage"
    ).fetchall()
    store.close()
    return {f"{r['assigned_agent']}:{r['type']}:{r['stage']}": r["count"] for r in rows}


def check_engagement_health(eng_dir: Path) -> dict:
    """Check overall engagement health — queue state, phases, containers."""
    health = {
        "healthy": True,
        "issues": [],
        "stats": {},
    }

    db_path = str(eng_dir / "cases.db")
    if Path(db_path).exists():
        store = CaseStore(db_path)
        stats = store.stats()
        store.close()
        health["stats"] = stats

        in_flight = stats.get("by_status", {}).get("processing", 0)
        if in_flight > 0:
            health["issues"].append(f"{in_flight} case(s) stuck in processing")

        errored = stats.get("by_status", {}).get("error", 0)
        if errored > 0:
            health["issues"].append(f"{errored} case(s) in error state")

    scope_path = eng_dir / "scope.json"
    if scope_path.exists():
        scope = json.loads(scope_path.read_text())
        if scope.get("status") == "in_progress":
            health["current_phase"] = scope.get("current_phase")

    if health["issues"]:
        health["healthy"] = False

    return health


def auto_recover(eng_dir: Path) -> bool:
    """Auto-recover a stalled engagement.
    Returns True if recovery was needed and applied."""
    db_path = str(eng_dir / "cases.db")
    recovered = 0

    if Path(db_path).exists():
        recovered = recover_stale_cases(db_path, threshold_minutes=0)
        store = CaseStore(db_path)
        store.retry_errors(max_retries=5)
        store.close()

    if recovered > 0:
        logger.info("Auto-recovered %d stale cases for %s", recovered, eng_dir.name)
        return True
    return False
