"""audit_trail.py — structured JSON event log with hash-chain verification.

Every operation is recorded with: timestamp, operator, action, target, phase,
model, verdict, latency. Events are linked via SHA-256 hash chain for
tamper-evident audit. Writes to rotating JSONL files.
"""

import json
import os
import time
import hashlib
import logging
from pathlib import Path

AUDIT_DIR = os.getenv("AUDIT_DIR", str(Path(__file__).resolve().parent / "data" / "audit"))
os.makedirs(AUDIT_DIR, exist_ok=True)

logger = logging.getLogger("audit_trail")

_last_hash = None
_session_id = None


def _session() -> str:
    global _session_id
    if _session_id is None:
        entropy = f"{time.time_ns()}:{os.urandom(8).hex()}"
        _session_id = hashlib.sha256(entropy.encode()).hexdigest()[:12]
    return _session_id


def _log_path() -> str:
    date = time.strftime("%Y-%m-%d")
    return os.path.join(AUDIT_DIR, f"audit_{date}.jsonl")


def _load_last_hash() -> str:
    global _last_hash
    if _last_hash is not None:
        return _last_hash
    path = _log_path()
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path) as f:
            for line in f:
                pass
            try:
                last = json.loads(line.strip())
                _last_hash = last.get("event_hash", "")
            except (json.JSONDecodeError, IndexError):
                _last_hash = ""
    else:
        _last_hash = ""
    return _last_hash


def record_event(
    action: str,
    target: str = "",
    phase: str = "",
    model: str = "",
    verdict: str = "",
    latency: float = 0.0,
    operator: str = "raphael",
    metadata: dict = None,
    error: str = None,
) -> dict:
    prev_hash = _load_last_hash()
    event = {
        "session": _session(),
        "timestamp": time.time(),
        "datetime_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "operator": operator,
        "action": action,
        "target": target,
        "phase": phase,
        "model": model,
        "verdict": verdict,
        "latency_seconds": round(latency, 3),
        "prev_hash": prev_hash,
    }
    if metadata:
        event["metadata"] = metadata
    if error:
        event["error"] = error

    raw = json.dumps(event, sort_keys=True)
    event_hash = hashlib.sha256(raw.encode()).hexdigest()
    event["event_hash"] = event_hash

    path = _log_path()
    with open(path, "a") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")

    global _last_hash
    _last_hash = event_hash
    return event


def verify_chain(path: str = None) -> list:
    if path is None:
        today = time.strftime("%Y-%m-%d")
        path = os.path.join(AUDIT_DIR, f"audit_{today}.jsonl")

    if not os.path.exists(path):
        return [{"error": f"Audit file not found: {path}"}]

    issues = []
    prev_hash = ""
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                issues.append({"line": line_num, "error": f"Invalid JSON: {e}"})
                continue

            if event.get("prev_hash", "") != prev_hash:
                issues.append({
                    "line": line_num,
                    "error": f"Hash chain break: expected prev_hash='{prev_hash}', got '{event.get('prev_hash', '')}'",
                    "event": event.get("action", "?"),
                })

            raw = json.dumps({k: v for k, v in event.items() if k != "event_hash"}, sort_keys=True)
            computed = hashlib.sha256(raw.encode()).hexdigest()
            if event.get("event_hash", "") != computed:
                issues.append({
                    "line": line_num,
                    "error": f"Event hash mismatch (tampered)",
                    "action": event.get("action", "?"),
                })

            prev_hash = event.get("event_hash", "")

    if not issues:
        issues.append({"status": "chain intact", "events": line_num})

    return issues


def get_session_log(session: str = None) -> list:
    if session is None:
        session = _session()
    date = time.strftime("%Y-%m-%d")
    path = os.path.join(AUDIT_DIR, f"audit_{date}.jsonl")
    if not os.path.exists(path):
        return []
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("session") == session:
                events.append(event)
    return events


def audit_stats() -> dict:
    total_events = 0
    chain_breaks = 0
    for fn in os.listdir(AUDIT_DIR):
        if not fn.startswith("audit_") or not fn.endswith(".jsonl"):
            continue
        path = os.path.join(AUDIT_DIR, fn)
        issues = verify_chain(path)
        total_events += sum(1 for _ in open(path) if _.strip())
        chain_breaks += sum(1 for i in issues if "Hash chain break" in i.get("error", ""))
    return {
        "total_events": total_events,
        "audit_files": len([f for f in os.listdir(AUDIT_DIR) if f.startswith("audit_")]),
        "chain_breaks": chain_breaks,
    }
