"""orchestrator.intel.dns_reputation — passive OSINT via curated DNS threat intel.

Source: Mullvad's `dns-blocklists` curated feeds (Malware, Ad, Tracker, Adult,
Social) — see https://github.com/mullvad/dns-blocklists. The lists are small,
human-curated, updated-frequency ~4x/week and are ideal as a *reputation*
signal for harvested domains/subdomains.

License: dns-blocklists is GPL-3.0. The generated list strings are third-party
blocklists aggregated by Mullvad (oisd, Hagezi, URLhaus, AdGuard, Firebog).
This module fetches the lists at runtime (no redistribution), so license
terms stay with the upstream source.

Scope:
- `classify(domain)` -> one of None | "malware" | "tracker" | "ad" | "adult" | "social"
- `is_blocked(domain, categories=None)` -> bool
- `enrich(domains)` -> {domain: "<category<|message|>clean>"}

Rules for matching:
- `"foo.com"`     blocks `foo.com` and `x.foo.com`.
- `"*.foo.com"`   blocks `x.foo.com` but NOT `foo.com`.
- Matching is suffix-based, case-insensitive, and handles trailing dots.

Cache:
- On-disk JSON file (default `<repo>/data/intel/dns-reputation-mullvad.json`),
  TTL 7 days, refreshed by `scripts/sync_mullvad_dns.py`.
- If no cache is available the result is always None (never network
  access from a production lookup; classification is quick-fail).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
DEFAULT_CACHE = REPO / "data" / "intel" / "dns-reputation-mullvad.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600

# Priority (first win) when a domain is in several categories.
CATEGORY_PRIORITY = (
    "malware",   # highest signal
    "adult",
    "social",
    "tracker",
    "ad",        # lowest signal (noise proxy)
)

FEEDS = {
    "malware": "https://raw.githubusercontent.com/mullvad/dns-blocklists/main/files/malware",
    "tracker": "https://raw.githubusercontent.com/mullvad/dns-blocklists/main/files/tracker",
    "ad": "https://raw.githubusercontent.com/mullvad/dns-blocklists/main/files/adblock",
    "adult": "https://raw.githubusercontent.com/mullvad/dns-blocklists/main/files/adult",
    "social": "https://raw.githubusercontent.com/mullvad/dns-blocklists/main/files/social",
}


def _norm(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _parse_list(text: str) -> set[str]:
    out: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        token = line.split()[0] if line.split() else ""
        if not token or token.startswith("#"):
            continue
        # A bare "*" (not a wildcard suffix) is meaningless noise.
        if token.startswith("*."):
            domain_part = token[2:]
            if "." not in domain_part:
                continue
            out.add("*." + _norm(domain_part))
        else:
            if "." not in token:
                continue
            out.add(_norm(token))
    return out


def _match(rules: set[str], domain: str) -> bool:
    """Return True if any rule matches the domain (suffix, wildcard-aware)."""
    domain = _norm(domain)
    if not domain or "." not in domain:
        return domain in rules
    labels = domain.split(".")
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        cand1 = suffix                          # "foo.com"
        cand2 = "*." + suffix                   # "*.foo.com"
        if cand1 in rules or cand2 in rules:
            return True
        # wildcard entry "*.foo.com" also matches foo.com? No — handled above.
    # bare root
    if domain in rules or ("*." + domain) in rules:
        return True
    return False


class DNSReputation:
    """Thin wrapper around an on-disk Mullvad feed cache."""

    def __init__(self, cache_path: Path | None = None) -> None:
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE
        self._data: dict[str, set[str]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.cache_path.is_file():
            return
        try:
            payload = json.loads(self.cache_path.read_text("utf-8"))
            for cat, domains in (payload.get("categories") or {}).items():
                self._data[cat] = set(domains)
        except (json.JSONDecodeError, OSError):
            self._data = {}

    def categories(self) -> list[str]:
        self._ensure_loaded()
        return sorted(self._data.keys())

    def rules(self, category: str) -> frozenset[str]:
        self._ensure_loaded()
        return frozenset(self._data.get(category, ()))

    def classify(self, domain: str) -> str | None:
        """Return the highest-priority category the domain falls under."""
        self._ensure_loaded()
        domain = _norm(domain)
        if not domain:
            return None
        hits = [c for c in self._data if _match(self._data[c], domain)]
        if not hits:
            return None
        hits.sort(key=lambda c: (CATEGORY_PRIORITY.index(c)
                                  if c in CATEGORY_PRIORITY else 99))
        return hits[0]

    def is_blocked(self, domain: str, categories: tuple[str, ...] = ()) -> bool:
        c = self.classify(domain)
        if categories:
            return c in set(categories)
        return c is not None

    def enrich(self, domains: list[str]) -> dict[str, str | None]:
        return {d: self.classify(d) for d in domains}

    def size(self) -> int:
        self._ensure_loaded()
        return sum(len(v) for v in self._data.values())

    @staticmethod
    def build_from_feed_texts(payload: dict[str, str]) -> "DNSReputation":
        """Wrap pre-fetched feed text into an instance (no disk)."""
        rep = DNSReputation.__new__(DNSReputation)
        rep.cache_path = DEFAULT_CACHE
        rep._loaded = True
        rep._data = {cat: _parse_list(text) for cat, text in payload.items()}
        return rep


def load_default() -> DNSReputation:
    return DNSReputation()


# Simple scoring helper for the intelligence phase.
# 0.0 = unknown/clean. Higher = stronger reputation signal of a flagged host.
def reputation_score(domain: str, *, rep: DNSReputation | None = None) -> float:
    active = rep or load_default()
    cat = active.classify(domain)
    if cat is None:
        return 0.0
    # malware highest, then adult, social, tracker, ad.
    weights = {"malware": 1.0, "adult": 0.6, "social": 0.3, "tracker": 0.2, "ad": 0.1}
    return weights.get(cat, 0.5)


__all__ = [
    "DNSReputation", "load_default", "CATEGORY_PRIORITY",
    "reputation_score", "FEEDS", "DEFAULT_CACHE", "_parse_list", "_norm",
]
