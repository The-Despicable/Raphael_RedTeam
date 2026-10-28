"""Phase registration for anti-forensic cleanup.

`covering_tracks` runs after `postex`. It is planned, never auto-executed:
the phase executor must call `antiforensics.render_script()` and hand the result
to the operator.
"""
from __future__ import annotations

COVERING_TRACKS = "covering_tracks"
AFTER_PHASE = "postex"

PHASE_DESCRIPTION = (
    "Post-exploitation cleanup planning: history, logs, journal, audit, artifacts "
    "and timestomp. Dry-run only unless RAPHAEL_AF_EXECUTE=1."
)


def insert_after(phases: list[str], phase: str = COVERING_TRACKS,
                 after: str = AFTER_PHASE) -> list[str]:
    """Idempotently place `phase` directly after `after`."""
    if phase in phases:
        return phases
    out = list(phases)
    try:
        idx = out.index(after) + 1
    except ValueError:
        idx = len(out)
    out.insert(idx, phase)
    return out
