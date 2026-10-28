"""runtime.logs — per-service log streaming into runtime/logs/<name>.log."""
from __future__ import annotations

import asyncio
from pathlib import Path

from runtime.env import LOG_DIR


def log_path(name: str) -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / f"{name}.log"


async def drain_to_file(name: str, stream: asyncio.StreamReader) -> None:
    """Continuously drain a subprocess pipe into the service log file.

    Prevents pipe-buffer deadlock (a child that fills its stdout pipe while
    nobody reads blocks forever)."""
    path = log_path(name)
    with path.open("ab") as f:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            f.write(chunk)
            f.flush()


def tail(name: str, lines: int = 20) -> str:
    p = log_path(name)
    if not p.is_file():
        return ""
    return "\n".join(p.read_text(errors="replace").splitlines()[-lines:])
