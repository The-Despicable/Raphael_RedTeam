"""Engagement-scoped stealth-browser fetch (CloakBrowser).

A Playwright-shaped Chromium with source-level fingerprint changes:
the same API as Playwright, just swap the import. Scope-gated like every
other operation here; the egress policy (tor/vpn/direct/proxy) of the loaded
profile becomes the browser's proxy, so the fetch never leaks past the
engagement boundary.
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .external_target_manager import (
    NotConfiguredError,
    PolicyViolationError,
    _clip,
)

DEFAULT_HTML_BYTES = 250_000
DEFAULT_WAIT_MS = 2000


class CloakBrowserRunner:
    def __init__(self, manager: Any):
        self.manager = manager

    def _module(self) -> Any:
        root = Path(self.manager.repo_root) / "tools" / "cloakbrowser"
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        try:
            import cloakbrowser as cb
            return cb
        except ImportError as e:  # noqa: BLE001
            raise NotConfiguredError(f"cloakbrowser package unavailable at {root}: {e}") from e

    def binary(self) -> str:
        cb = self._module()
        try:
            return str(cb.ensure_binary())
        except Exception as e:  # noqa: BLE001
            raise NotConfiguredError(f"cloakbrowser binary unavailable: {e}") from e

    def _proxy(self) -> Optional[str]:
        prof = self.manager._require_profile()
        if prof.egress.value in ("tor", "proxy_tor"):
            return f"socks5://{prof.tor_socks}"
        return os.environ.get("CLOAKBROWSER_PROXY") or None

    def fetch_sync(
        self,
        url: str,
        timeout: float = 30.0,
        *,
        screenshot: bool = False,
        full_html: bool = True,
        wait_ms: int = DEFAULT_WAIT_MS,
        humanize: bool = False,
    ) -> Dict[str, Any]:
        if not url or not isinstance(url, str):
            raise PolicyViolationError("cloakbrowser url is empty")
        prof = self.manager._require_profile()
        ok, reason = self.manager._scope_check(url)
        if not ok:
            raise PolicyViolationError(
                f"target {url!r} is outside engagement scope ({reason})",
                data={"action": "web.cloak", "engagement": prof.engagement_id},
            )

        cb = self._module()
        proxy = self._proxy()
        started = time.monotonic()
        browser = None
        page = None
        result: Dict[str, Any] = {
            "url": url,
            "engine": "cloakbrowser",
            "engagement": prof.engagement_id,
        }
        try:
            browser = cb.launch(
                headless=True,
                proxy=proxy,
                timeout=int(max(1, timeout) * 1000),
            )
            page = browser.new_page()
            resp = page.goto(
                url,
                timeout=int(max(1, timeout) * 1000),
                wait_until="domcontentloaded",
            )
            try:
                page.wait_for_timeout(int(max(0, wait_ms)))
            except Exception:
                pass
            title = page.title()
            final_url = page.url
            html = page.content() if full_html else ""
            if len(html) > DEFAULT_HTML_BYTES:
                html = html[:DEFAULT_HTML_BYTES] + "\n<!-- clipped -->"
            cookies = []
            try:
                cookies = page.context.cookies() if page.context else []
            except Exception:
                pass
            user_agent = ""
            try:
                user_agent = page.evaluate("navigator.userAgent")
            except Exception:
                pass
            screenshot_b64 = ""
            if screenshot:
                try:
                    screenshot_b64 = base64.b64encode(
                        page.screenshot(full_page=False)
                    ).decode()
                except Exception:
                    pass
            result.update({
                "status_code": getattr(resp, "status", None),
                "ok": bool(getattr(resp, "ok", True)),
                "final_url": final_url,
                "title": title,
                "html": _clip(html, DEFAULT_HTML_BYTES),
                "html_bytes": len(html),
                "cookies": cookies,
                "user_agent": user_agent,
                "screenshot_b64": screenshot_b64,
            })
        finally:
            try:
                if page:
                    page.close()
                if browser:
                    browser.close()
            except Exception:
                pass

        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        result["routed"] = "cloakbrowser"
        self.manager.audit({
            "action": "web.cloak",
            "target": url,
            "status": "ok" if result.get("ok") else "failed",
            "bytes": len(result.get("html", "")) or 0,
            "duration_ms": result["duration_ms"],
            "detail": {
                "status_code": result.get("status_code"),
                "final_url": result.get("final_url"),
                "title": result.get("title"),
                "proxy": proxy,
            },
        })
        return result

    async def fetch(
        self,
        url: str,
        timeout: float = 30.0,
        **opts: Any,
    ) -> Dict[str, Any]:
        return await asyncio.to_thread(self.fetch_sync, url, timeout, **opts)