"""cloakbrowser scope gate + runner (offline via faked module)."""
from __future__ import annotations

import sys
import types

import pytest

from src.bridge.external_target_manager import (
    EgressProfile, ExternalTargetManager, NotConfiguredError,
    PolicyViolationError,
)
from src.bridge.cloak import CloakBrowserRunner


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
            return "<html><body>x</body></html>"
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

    def launch(**kw):
        return Browser()
    def ensure_binary():
        return "/tmp/mock-chrome"

    mod.launch = launch
    mod.ensure_binary = ensure_binary
    monkeypatch.setitem(sys.modules, "cloakbrowser", mod)
    return mod


class TestFailClosed:
    def test_no_profile(self, manager):
        with pytest.raises(NotConfiguredError, match="fail closed"):
            CloakBrowserRunner(manager).fetch_sync("https://example.com")

    def test_binary_available_returns_path(self, loaded_manager, monkeypatch):
        cb = _fake_cb(monkeypatch)
        assert CloakBrowserRunner(loaded_manager).binary() == "/tmp/mock-chrome"


def _scoped_manager(manager, urls=("example.com",), egress="direct"):
    prof = EgressProfile.from_obj({
        "engagement_id": "cloak-test",
        "cidrs": ["10.10.10.0/24"],
        "urls": list(urls),
        "egress": egress,
    })
    manager.profile = prof
    return manager


class TestScope:
    def test_out_of_scope_rejected(self, manager, monkeypatch):
        _fake_cb(monkeypatch)
        m = _scoped_manager(manager)
        with pytest.raises(PolicyViolationError, match="outside engagement scope"):
            CloakBrowserRunner(m).fetch_sync("https://evil.example.org/x")

    def test_url_in_urls_passes(self, manager, monkeypatch):
        _fake_cb(monkeypatch)
        m = _scoped_manager(manager)
        res = CloakBrowserRunner(m).fetch_sync("https://example.com/path", timeout=5)
        assert res["title"] == "Example Domain"
        assert res["status_code"] == 200
        assert res["ok"] is True
        assert "x" in res["html"]
        assert res["user_agent"] == "MockAgent/1.0"

    def test_screenshot_base64_returned(self, manager, monkeypatch):
        _fake_cb(monkeypatch)
        m = _scoped_manager(manager)
        res = CloakBrowserRunner(m).fetch_sync(
            "https://example.com/", screenshot=True, timeout=5
        )
        assert res["screenshot_b64"].startswith("iVBOR")

    def test_target_audit_recorded(self, manager, monkeypatch):
        _fake_cb(monkeypatch)
        m = _scoped_manager(manager)
        CloakBrowserRunner(m).fetch_sync("https://example.com/", timeout=5)
        import json as _j
        lines = (m.audit_root / "cloak-test" / "bridge" / "audit.jsonl") \
            .read_text().splitlines()
        last = _j.loads(lines[-1])
        assert last["action"] == "web.cloak"
        assert last["status"] == "ok"

    def test_tor_egress_uses_socks_proxy(self, manager, monkeypatch):
        _fake_cb(monkeypatch)
        m = _scoped_manager(manager, egress="tor")
        cb = sys.modules["cloakbrowser"]
        seen = {}
        orig = cb.launch
        def cap(**kw):
            seen.update(kw)
            return orig(**kw)
        cb.launch = cap
        CloakBrowserRunner(m).fetch_sync("https://example.com/", timeout=5)
        assert seen["proxy"] == "socks5://127.0.0.1:9050"


class TestLive:
    def test_example_com(self, loaded_manager, monkeypatch):
        import os
        if os.environ.get("CLOAK_LIVE") != "1":
            pytest.skip("set CLOAK_LIVE=1 to run (downloads the binary)")
        # use a profile that allows example.com
        profile = EgressProfile.from_obj({
            "engagement_id": "cloak-live",
            "cidrs": ["10.10.10.0/24"],
            "urls": ["example.com"],
            "egress": "direct",
        })
        loaded_manager.profile = profile
        runner = CloakBrowserRunner(loaded_manager)
        out = __import__("asyncio").run(runner.fetch("https://example.com/", timeout=60))
        assert out["ok"] and out["title"] == "Example Domain"
        assert out["status_code"] == 200