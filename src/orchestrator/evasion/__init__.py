"""orchestrator.evasion — OPSEC / anti-forensics planning surface.

Nothing in this package executes destructive commands by default. See
`antiforensics.execute` for the double opt-in gate.
"""
from __future__ import annotations

from .antiforensics import (
    AntiforensicsLocked,
    AntiforensicsStep,
    artifact_clean,
    auditd_wipe,
    browser_cache_clean,
    execute,
    history_scrub,
    journal_vacuum,
    kernel_cache_drop,
    known_hosts_prune,
    log_wipe,
    plan,
    render_script,
    secure_delete,
)
from .phase import AFTER_PHASE, COVERING_TRACKS, PHASE_DESCRIPTION, insert_after
from .timestomp import (
    apply_timestomp,
    plan_equalize,
    plan_timestomp,
    plan_timestomp_batch,
)

__all__ = [
    # types / gate
    "AntiforensicsStep",
    "AntiforensicsLocked",
    # planners
    "plan",
    "render_script",
    "execute",
    "history_scrub",
    "log_wipe",
    "journal_vacuum",
    "auditd_wipe",
    "kernel_cache_drop",
    "browser_cache_clean",
    "artifact_clean",
    "secure_delete",
    "known_hosts_prune",
    # timestomp
    "plan_timestomp",
    "plan_timestomp_batch",
    "plan_equalize",
    "apply_timestomp",
    # phase
    "COVERING_TRACKS",
    "AFTER_PHASE",
    "PHASE_DESCRIPTION",
    "insert_after",
]
