import logging
from typing import Any

logger = logging.getLogger("adversary_profiles")

PROFILES: dict[str, dict[str, Any]] = {
    "apt29": {"name": "APT29", "ttps": ["T1059", "T1003", "T1087"], "sophistication": "high"},
    "apt41": {"name": "APT41", "ttps": ["T1059", "T1505", "T1021"], "sophistication": "high"},
    "ransomware_operator": {"name": "Ransomware Operator", "ttps": ["T1486", "T1490", "T1048"], "sophistication": "medium"},
}


def get_profile(name: str) -> dict[str, Any] | None:
    return PROFILES.get(name)


def list_profiles() -> list[str]:
    return list(PROFILES.keys())


def match_profile(ttp: str) -> list[dict[str, Any]]:
    return [p for p in PROFILES.values() if ttp in p.get("ttps", [])]
