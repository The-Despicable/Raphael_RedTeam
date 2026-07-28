import logging
from typing import Any

logger = logging.getLogger("scope")


class ScopeConfig:
    def __init__(self) -> None:
        self.domains: list[str] = []
        self.ip_ranges: list[str] = []
        self.persona: str = "z3r0"

    def check(self, target: str) -> bool:
        if not self.domains and not self.ip_ranges:
            return True
        for domain in self.domains:
            if target.endswith(domain):
                return True
        return False


default_scope = ScopeConfig()
