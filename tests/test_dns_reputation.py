"""Unit tests for orchestrator.intel.dns_reputation (offline, cached feed)."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from orchestrator.intel.dns_reputation import DNSReputation, _parse_list, reputation_score


def test_parse_list_handles_wildcards_and_comments():
    text = "evil.example.com\n*.tracker.io\n# comment\n\nads.com\n* junk\n"
    rules = _parse_list(text)
    assert "evil.example.com" in rules
    assert "*.tracker.io" in rules
    assert "ads.com" in rules
    assert len(rules) == 3


def test_classify_wildcard_and_suffix(tmp_path):
    payload = {
        "malware": "evil.example.com\n*.c2evil.example.com",
        "tracker": "analytics.victim.com\n*.tracker.io",
        "ad": "ads.spam.example",
    }
    fake = tmp_path / "cache.json"
    fake.write_text(__import__("json").dumps(
        {"categories": {k: sorted(_parse_list(v)) for k, v in payload.items()}}
    ))
    rep = DNSReputation(fake)
    assert rep.classify("evil.example.com") == "malware"
    assert rep.classify("x.c2evil.example.com") == "malware"
    assert rep.classify("foo.tracker.io") == "tracker"
    assert rep.classify("example.com") is None
    enriched = rep.enrich(["evil.example.com", "foo.tracker.io", "example.com"])
    assert enriched["evil.example.com"] == "malware"
    assert enriched["example.com"] is None
    assert rep.size() >= 4
    assert reputation_score("evil.example.com", rep=rep) >= 0.9


def test_empty_cache_loads_gracefully(tmp_path):
    missing = tmp_path / "nope.json"
    rep = DNSReputation(missing)
    assert rep.classify("anything.example") is None
    assert rep.size() == 0
    assert rep.categories() == []


def test_wildcard_does_not_match_parent():
    text = "*.sub.example.com"
    rules = _parse_list(text)
    assert "*._" not in rules
    rep = DNSReputation.__new__(DNSReputation)
    rep.cache_path = Path("/dev/null")
    rep._loaded = True
    rep._data = {"ad": rules}
    # wildcard match on sub-sub-host
    assert rep.classify("x.sub.example.com") == "ad"
    # parent host itself is not covered by the wildcard
    assert rep.classify("example.com") is None
