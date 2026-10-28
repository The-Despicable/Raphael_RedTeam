"""OSINT intel package."""
from .dns_reputation import (
    DEFAULT_CACHE,
    DNSReputation,
    FEEDS,
    CATEGORY_PRIORITY,
    load_default,
    reputation_score,
    _parse_list,
)
from .dns_reputation import DNSReputation as _DR


def enrich(domains):
    return _DR().enrich(domains)

__all__ = ["DNSReputation", "load_default", "reputation_score",
           "FEEDS", "CATEGORY_PRIORITY", "DEFAULT_CACHE", "_parse_list", "enrich"]
