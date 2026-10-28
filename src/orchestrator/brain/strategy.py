import logging
from typing import Any

logger = logging.getLogger("strategy")

from .evasion.phase import COVERING_TRACKS, AFTER_PHASE

DEFAULT_PHASES = [
    "harvest", "recon", "scan", "exploit", AFTER_PHASE,
    COVERING_TRACKS,
    "lateral", "credential", "exfil", "phish",
]


def build_strategy(target: str, profile: dict, findings: list[Any]) -> list[str]:
    phases = DEFAULT_PHASES.copy()
    tags = profile.get("tags", [])
    if "ad" in tags or "domain" in tags:
        phases.insert(3, "ad_kill_chain")
    return phases
