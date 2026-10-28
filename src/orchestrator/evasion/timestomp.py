"""orchestrator.evasion.timestomp — MFT/timestamp manipulation planner.

Planning only. `plan_timestomp` returns a command; `apply_timestomp` executes it
only under the same double opt-in as `antiforensics.execute`.
"""
from __future__ import annotations

import os
import subprocess
from typing import Sequence

from .antiforensics import (CONFIRM_TOKEN, AntiforensicsLocked, AntiforensicsStep)

DEFAULT_REFERENCE = "/bin/bash"


def plan_timestomp(path: str, reference: str | None = None,
                   timestamp: str | None = None) -> AntiforensicsStep:
    """Match `path`'s mtime/atime to a reference file, or set an explicit stamp."""
    if not path:
        raise ValueError("path is required")
    if timestamp:
        command = f'touch -t {timestamp} -- "{path}"'
        reason = f"set explicit timestamp {timestamp} on {path}"
    else:
        ref = reference or DEFAULT_REFERENCE
        command = f'touch -r "{ref}" -- "{path}"'
        reason = f"copy mtime/atime from {ref} onto {path}"
    return AntiforensicsStep(
        id="timestomp.apply",
        command=command,
        reason=reason,
        category="timestomp",
        platform="linux",
        destructive=False,
        requires_root=False,
        idempotent=True,
    )


def plan_timestomp_batch(paths: Sequence[str], reference: str | None = None) -> list[AntiforensicsStep]:
    return [plan_timestomp(p, reference=reference) for p in paths]


def plan_equalize(paths: Sequence[str], reference: str | None = None) -> str:
    """Render a single script that normalizes every path to one reference."""
    script = "#!/usr/bin/env bash\n"
    ref = reference or DEFAULT_REFERENCE
    for p in paths:
        script += f'touch -r "{ref}" -- "{p}"\n'
    return script


def apply_timestomp(step: AntiforensicsStep, *, confirm: str) -> dict:
    if os.environ.get("RAPHAEL_AF_EXECUTE") != "1":
        raise AntiforensicsLocked("RAPHAEL_AF_EXECUTE != 1 — timestomp is planning-only")
    if confirm != CONFIRM_TOKEN:
        raise AntiforensicsLocked(f"confirmation token mismatch; expected {CONFIRM_TOKEN!r}")
    proc = subprocess.run(step.command, shell=True, capture_output=True, text=True, timeout=15)
    return {"id": step.id, "rc": proc.returncode,
            "stdout": proc.stdout[-300:], "stderr": proc.stderr[-300:]}
