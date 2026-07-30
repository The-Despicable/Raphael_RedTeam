import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from pathlib import Path

log = logging.getLogger("agent.audit")


@dataclass
class KillSwitch:
    active: bool = False
    trigger_reason: str = ""
    triggered_at: float = 0.0

    def trigger(self, reason: str):
        self.active = True
        self.trigger_reason = reason
        self.triggered_at = time.time()
        log.critical(f"KILL_SWITCH triggered: {reason}")

    def check(self) -> bool:
        return self.active


@dataclass
class AuditLogger:
    log_dir: str = "/tmp/agent_audit"
    _enabled: bool = True

    def __post_init__(self):
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)

    def log(self, event: str, data: dict):
        if not self._enabled:
            return
        entry = {
            "ts": time.time(),
            "event": event,
            "data": data,
        }
        fp = Path(self.log_dir) / f"audit_{int(time.time())}.jsonl"
        with open(fp, "a") as f:
            f.write(json.dumps(entry) + "\n")


@dataclass
class IntegrityMonitor:
    _hashes: dict[str, str] = field(default_factory=dict)

    def record(self, path: str):
        try:
            with open(path, "rb") as f:
                import hashlib
                self._hashes[path] = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass

    def verify(self, path: str) -> bool:
        if path not in self._hashes:
            return True
        try:
            with open(path, "rb") as f:
                import hashlib
                return hashlib.sha256(f.read()).hexdigest() == self._hashes[path]
        except Exception:
            return False


@dataclass
class ForensicCollector:
    collect_dir: str = "/tmp/agent_forensics"

    def __post_init__(self):
        Path(self.collect_dir).mkdir(parents=True, exist_ok=True)

    def collect(self, label: str, data: bytes) -> str:
        fname = f"{label}_{int(time.time())}_{uuid.uuid4().hex[:8]}.bin"
        fpath = Path(self.collect_dir) / fname
        with open(fpath, "wb") as f:
            f.write(data)
        return str(fpath)


kill_switch = KillSwitch()
audit_logger = AuditLogger()
integrity_monitor = IntegrityMonitor()
forensic_collector = ForensicCollector()


def setup_agent_safety(config: dict = None) -> dict:
    config = config or {}
    kill_switch.active = False
    audit_logger._enabled = config.get("audit_enabled", True)
    return {
        "kill_switch": kill_switch,
        "audit_logger": audit_logger,
        "integrity_monitor": integrity_monitor,
        "forensic_collector": forensic_collector,
    }