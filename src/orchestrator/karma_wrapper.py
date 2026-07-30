"""Karma V2 OSINT wrapper."""

import logging

logger = logging.getLogger("karma_wrapper")


class KarmaV2Wrapper:
    def __init__(self):
        self._available = False

    def scan(self, target: str, mode: str = "host") -> dict:
        logger.info(f"KarmaV2 scan requested for {target} (mode={mode})")
        return {
            "status": "unavailable",
            "target": target,
            "mode": mode,
            "note": "KarmaV2 not installed",
        }
