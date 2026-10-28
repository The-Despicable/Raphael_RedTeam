"""Brain-side cloakfetch tool: scope gate, parse_args, fail-closed (offline)."""
from __future__ import annotations

import asyncio
import json
import sys
import types

import pytest

from brain.cloak_tool import (
    CloakError,
    CloakFetchTool,
    CloakScopeError,
)
from brain.config import Settings


def _fake_cb(monkeypatch):
    mod = types.ModuleType("cloakbrowser")

    class Resp:
        status = 200
        ok = True

    class Page:
        url = "https://example.com/"
        def title(self):
            return "Example Domain"
        def goto(self, *a, **k):
            return Resp()
        def wait_for_timeout(self, ms):
            return None
        def content(self):
            return "<html><body>brain</body></html>"
        @property
        def context(self):
            return None
        def evaluate(self, s):
            return "MockAgent/1.0"
        def screenshot(self, full_page=False):
            return b"\x89PNG fake"
        def close(self):
            pass

    class Browser:
        def new_page(self):
            return Page()
        def close(self):
            pass

    mod.launch = lambda **kw: Browser()
    mod.ensure_binary = lambda: "/tmp/mock-chrome"
    monkeypatch.setitem(sys.modules, "cloakbrowser", mod)
    return mod


def _tool(monkeypatch, scope, **kw):
    """Build a CloakFetchTool whose scope source is an inline env doc."""
    env_open = kw.pop("env_open", None)
    if scope is not None:
        monkeypatch.setenv("CLOAK_SCOPE_INLINE", json.dumps(scope))
    else:
        monkeypatch.delenv("CLOAK_SCOPE_INLINE", raising=False)
        monkeypatch.delenv("CLOAK_SCOPE", raising=False)
        monkeypatch.setenv("CLOAK_ALLOW_OPEN", "1" if env_open == "1" else "0")
    return CloakFetchTool(Settings(**kw))


# ---------------------------------------------------------------------------
# scope document parsing
# ---------------------------------------------------------------------------


class TestScopeDocument:
    def test_no_scope_fail_closed(self, monkeypatch):
        t = _tool(monkeypatch, None, env_open="0")
        with pytest.raises(CloakScopeError, match="no scope configured"):
            t.scope_document()

    def test_allow_open_opt_out(self, monkeypatch):
        t = _tool(monkeypatch, None, env_open="1")
        doc = t.scope_document()
        assert doc["enforced"] is False
        assert doc["allow_urls"] == ["*"]

    def test_missing_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CLOAK_SCOPE", str(tmp_path / "missing.json"))
        t = CloakFetchTool(Settings())
        with pytest.raises(CloakScopeError, match="file missing"):
            t.scope_document()

    def test_invalid_json(self, monkeypatch, tmp_path):
        p = tmp_path / "scope.json"
        p.write_text("{not json")
        monkeypatch.setenv("CLOAK_SCOPE", str(p))
        t = CloakFetchTool(Settings())
        with pytest.raises(CloakScopeError, match="not JSON"):
            t.scope_document()

    def test_empty_allow_rejected(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": []})
        with pytest.raises(CloakScopeError, match="no allow_urls"):
            t.scope_document()

    def test_stripped_scheme_and_slash(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["https://Example.com/"]})
        assert t.scope_document()["allow_urls"] == ["example.com"]

    def test_ua_scope_form(self, monkeypatch):
        t = _tool(monkeypatch, {
            "scope": {"in_scope": [{"asset_identifier": "*.example.com"}]}
        })
        assert t.scope_document()["allow_urls"] == ["*.example.com"]

    def test_deny_urls_parsed(self, monkeypatch):
        t = _tool(monkeypatch, {
            "allow_urls": ["example.com"], "deny_urls": ["blog.example.com"]
        })
        assert t.scope_document()["deny_urls"] == ["blog.example.com"]


# ---------------------------------------------------------------------------
# check_url
# ---------------------------------------------------------------------------


class TestCheckUrl:
    def test_in_scope(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        assert t.check_url("https://example.com/x") == "https://example.com/x"

    def test_wildcard_subdomain(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["*.example.com"]})
        assert t.check_url("https://app.example.com") == "https://app.example.com"

    def test_wildcard_does_not_match_apex(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["*.example.com"]})
        with pytest.raises(CloakScopeError):
            t.check_url("https://example.com")

    def test_out_of_scope(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        with pytest.raises(CloakScopeError, match="outside scope"):
            t.check_url("https://evil.example.org")

    def test_deny_wins_over_allow(self, monkeypatch):
        t = _tool(monkeypatch, {
            "allow_urls": ["example.com"], "deny_urls": ["blog.example.com"]
        })
        with pytest.raises(CloakScopeError, match="denied"):
            t.check_url("https://blog.example.com")

    def test_no_host(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        with pytest.raises(CloakScopeError, match="no host"):
            t.check_url("   ")


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------


class TestParseArgs:
    def test_url_flag(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        assert t.parse_args(["-url", "https://example.com"])["url"] == \
            "https://example.com"

    def test_bare_url(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        assert t.parse_args(["https://example.com"])["url"] == "https://example.com"

    def test_target_fallback(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        assert t.parse_args([], target="https://example.com")["url"] == \
            "https://example.com"

    def test_no_url(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        with pytest.raises(CloakScopeError, match="no url"):
            t.parse_args([])

    def test_unknown_flag(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        with pytest.raises(CloakScopeError, match="unknown flag"):
            t.parse_args(["-bogus"])

    def test_flags_combo(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        o = t.parse_args(["https://example.com", "-screenshot", "-no-html",
                          "-wait", "1500"])
        assert o["screenshot"] is True
        assert o["full_html"] is False
        assert o["wait_ms"] == 1500

    def test_quoted_args(self, monkeypatch):
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        o = t.parse_args(["-url 'https://example.com'"])
        assert o["url"] == "https://example.com"


# ---------------------------------------------------------------------------
# fetch (faked module, offline)
# ---------------------------------------------------------------------------


class TestFetch:
    def test_in_scope_fetch(self, monkeypatch):
        _fake_cb(monkeypatch)
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        res = asyncio.run(t.fetch("https://example.com/x"))
        assert res["ok"] is True
        assert res["status_code"] == 200
        assert res["title"] == "Example Domain"
        assert res["engine"] == "cloakbrowser"
        assert "brain" in res["html"]
        assert res["routed"] == "local"

    def test_out_of_scope_not_launched(self, monkeypatch):
        _fake_cb(monkeypatch)
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        with pytest.raises(CloakScopeError):
            asyncio.run(t.fetch("https://evil.example.org"))

    def test_from_args(self, monkeypatch):
        _fake_cb(monkeypatch)
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        res = asyncio.run(t.from_args(["-url", "https://example.com"]))
        assert res["ok"] is True

    def test_from_args_screenshot(self, monkeypatch):
        _fake_cb(monkeypatch)
        t = _tool(monkeypatch, {"allow_urls": ["example.com"]})
        res = asyncio.run(
            t.from_args(["https://example.com", "-screenshot"])
        )
        assert res["screenshot_b64"].startswith("iVBOR")


# ---------------------------------------------------------------------------
# optional live (needs the real vendored binary + CLOAK_LIVE=1)
# ---------------------------------------------------------------------------


class TestLive:
    def test_example_com(self, monkeypatch):
        import os
        if os.environ.get("CLOAK_LIVE") != "1":
            pytest.skip("set CLOAK_LIVE=1 to run (uses the real vendored binary)")
        t = CloakFetchTool(Settings())
        # no scope -> explicitly allow
        os.environ["CLOAK_SCOPE_INLINE"] = json.dumps(
            {"allow_urls": ["example.com"]}
        )
        res = asyncio.run(t.fetch("https://example.com/", timeout=60))
        assert res["ok"] and res["status_code"] == 200
        assert res["title"] == "Example Domain"
