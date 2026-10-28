"""runtime.pidfiles — PID file management under runtime/pid/."""
from __future__ import annotations

import os
import signal
from pathlib import Path
from typing import Optional

from runtime.env import PID_DIR


def pid_path(name: str) -> Path:
    return PID_DIR / f"{name}.pid"


def write(name: str, pid: int) -> None:
    PID_DIR.mkdir(parents=True, exist_ok=True)
    pid_path(name).write_text(str(pid))


def read(name: str) -> Optional[int]:
    p = pid_path(name)
    if not p.is_file():
        return None
    try:
        return int(p.read_text().strip())
    except ValueError:
        return None


def alive(name: str) -> bool:
    pid = read(name)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def terminate(name: str, timeout: float = 8.0) -> bool:
    """SIGTERM then SIGKILL. Returns True if the process is gone."""
    import time
    pid = read(name)
    if pid is None:
        return True
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
        except OSError:
            pid_path(name).unlink(missing_ok=True)
            return True
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            try:
                os.kill(pid, 0)
            except OSError:
                pid_path(name).unlink(missing_ok=True)
                return True
            time.sleep(0.2)
    pid_path(name).unlink(missing_ok=True)
    return False


def clear(name: str) -> None:
    pid_path(name).unlink(missing_ok=True)
