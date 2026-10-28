"""Self-hosted stealth-browser fetch for the Autonomous Brain (CloakBrowser).

Runs the vendored ``tools/cloakbrowser`` package in-process, gated by a URL
scope document so a broad-internet crawl stays inside declared bounds.

Scope sources, in order:
  1. ``CLOAK_SCOPE``            — path to a JSON scope document
  2. ``CLOAK_SCOPE_INLINE``     — JSON string
  3. ``CLOAK_ALLOW_OPEN=1``     — explicit opt-out (no gate)

Accepted documents::

    {"allow_urls": ["example.com", "*.target.example"], "deny_urls": ["blog.example.com"]}
    {"scope": {"in_scope": [{"asset_identifier": "*.example.com"}]}}

Hostname entries are plain or ``*.``-globs matched against the URL host.
Without a scope document the tool refuses to run (fail closed) — matching the
bridge's engagement gate.
"""
from __future__ import annotations

import asyncio
import base64
import fnmatch
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

from .config import Settings, get_settings

DEFAULT_HTML_BYTES = 250_000
DEFAULT_WAIT_MS = 2000
HARD_MAX_TIMEOUT = 240.0


class CloakError(RuntimeError):
    """Raised when the tool cannot run at all (not vendored / not configured)."""


class CloakScopeError(ValueError):
    """Raised when a request leaves the declared scope (fail closed)."""


def _host_of(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    host = urlsplit(url).hostname or ""
    return host.strip().lower().rstrip(".")


class CloakFetchTool:
    """Local, scope-gated stealth-browser runner."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------
    # package / scope
    # ------------------------------------------------------------------

    def _module(self) -> Any:
        here = Path(__file__).resolve().parent.parent
        root = here / "tools" / "cloakbrowser"
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        try:
            import cloakbrowser as cb
            return cb
        except ImportError as e:  # noqa: BLE001
            raise CloakError(f"cloakbrowser package unavailable at {root}: {e}") from e

    def binary(self) -> str:
        cb = self._module()
        try:
            return str(cb.ensure_binary())
        except Exception as e:  # noqa: BLE001
            raise CloakError(f"cloakbrowser binary unavailable: {e}") from e

    def scope_document(self) -> Dict[str, Any]:
        path = getattr(self.settings, "cloak_scope_file", None) or \
            os.environ.get("CLOAK_SCOPE", "")
        inline = os.environ.get("CLOAK_SCOPE_INLINE", "")
        doc: Dict[str, Any] = {}
        if path:
            p = Path(path).expanduser()
            if not p.is_file():
                raise CloakScopeError(f"CLOAK_SCOPE file missing: {p}")
            try:
                doc = json.loads(p.read_text())
            except json.JSONDecodeError as e:
                raise CloakScopeError(f"scope file is not JSON: {e}") from e
        elif inline:
            try:
                doc = json.loads(inline)
            except json.JSONDecodeError as e:
                raise CloakScopeError(f"CLOAK_SCOPE_INLINE invalid: {e}") from e
        elif getattr(self.settings, "cloak_allow_open", False) or \
                os.environ.get("CLOAK_ALLOW_OPEN") in ("1", "true", "yes"):
            return {"allow_urls": ["*"], "deny_urls": [], "enforced": False}
        else:
            raise CloakScopeError(
                "no scope configured — set CLOAK_SCOPE to a JSON scope "
                "document, or CLOAK_ALLOW_OPEN=1 for an explicit open fetch"
            )
        if not isinstance(doc, dict):
            raise CloakScopeError("scope document must be an object")

        allow = doc.get("allow_urls") or doc.get("allow") or []
        if not allow and isinstance(doc.get("scope"), dict):
            entries = doc["scope"].get("in_scope") or []
            allow = [
                e.get("asset_identifier") if isinstance(e, dict) else e
                for e in entries
            ]
        deny = doc.get("deny_urls") or doc.get("deny") or doc.get("out_of_scope") or []
        allow = [str(a).strip().lower().lstrip("https://").lstrip("http://").rstrip("/")
                 for a in (allow or []) if str(a).strip()]
        deny = [str(d).strip().lower().lstrip("https://").lstrip("http://").rstrip("/")
                for d in (deny or []) if str(d).strip()]
        if not allow:
            raise CloakScopeError("scope document declares no allow_urls")
        return {
            "allow_urls": allow,
            "deny_urls": deny,
            "enforced": True,
        }

    def check_url(self, url: str) -> str:
        doc = self.scope_document()
        host = _host_of(url)
        if not host:
            raise CloakScopeError(f"url {url!r} has no host")
        for d in doc["deny_urls"]:
            if self._match(host, d):
                raise CloakScopeError(f"host {host!r} is denied by scope ({d})")
        for a in doc["allow_urls"]:
            if self._match(host, a):
                return url
        raise CloakScopeError(f"host {host!r} is outside scope (allow_urls)")

    @staticmethod
    def _match(host: str, entry: str) -> bool:
        e = entry.strip().lower().rstrip(".")
        if e.startswith("*."):
            suffix = e[1:]
            return host.endswith(suffix) and len(host) > len(suffix)
        return host == e or host.endswith("." + e) if e.startswith(".") else host == e

    # ------------------------------------------------------------------
    # fetch
    # ------------------------------------------------------------------

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
        self.check_url(url)
        cb = self._module()
        proxy = getattr(self.settings, "cloak_proxy", None) or \
            os.environ.get("CLOAKBROWSER_PROXY") or None
        max_html = int(getattr(self.settings, "cloak_max_html", DEFAULT_HTML_BYTES))
        started = time.monotonic()
        browser = None
        page = None
        result: Dict[str, Any] = {"url": url, "engine": "cloakbrowser"}
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
            html = page.content() if full_html else ""
            if len(html) > max_html:
                html = html[:max_html] + "\n<!-- clipped -->"
            ua = ""
            try:
                ua = page.evaluate("navigator.userAgent")
            except Exception:
                pass
            shot = ""
            if screenshot:
                try:
                    shot = base64.b64encode(page.screenshot(full_page=False)).decode()
                except Exception:
                    pass
            result.update({
                "status_code": getattr(resp, "status", None),
                "ok": bool(getattr(resp, "ok", True)),
                "final_url": page.url,
                "title": page.title(),
                "html": html,
                "html_bytes": len(html),
                "user_agent": ua,
                "screenshot_b64": shot,
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
        result["routed"] = "local"
        return result

    async def fetch(
        self,
        url: str,
        timeout: float = 30.0,
        **opts: Any,
    ) -> Dict[str, Any]:
        return await asyncio.to_thread(self.fetch_sync, url, timeout, **opts)

    # ------------------------------------------------------------------
    # argv interface used by /tools/execute
    # ------------------------------------------------------------------

    def parse_args(
        self, args: Sequence[str], target: Optional[str] = None
    ) -> Dict[str, Any]:
        opts: Dict[str, Any] = {"url": None, "screenshot": False,
                                "full_html": True, "wait_ms": DEFAULT_WAIT_MS}
        import shlex

        toks: List[str] = []
        for a in args or []:
            toks.extend(shlex.split(str(a)))
        i = 0
        while i < len(toks):
            tok = toks[i]
            nxt = toks[i + 1] if i + 1 < len(toks) else ""
            if tok in ("-url", "--url") and nxt:
                opts["url"] = nxt
                i += 2
            elif tok in ("-screenshot", "--screenshot"):
                opts["screenshot"] = True
                i += 1
            elif tok in ("-wait", "--wait") and nxt:
                opts["wait_ms"] = int(nxt)
                i += 2
            elif tok in ("-no-html", "--no-html"):
                opts["full_html"] = False
                i += 1
            elif tok in ("-humanize", "--humanize"):
                opts["humanize"] = True
                i += 1
            elif tok.startswith("-"):
                raise CloakScopeError(f"unknown flag {tok!r}")
            elif opts["url"] is None:
                opts["url"] = tok
                i += 1
            else:
                raise CloakScopeError("multiple urls given; pass one url")
        if opts["url"] is None and target:
            opts["url"] = str(target)
        if opts["url"] is None:
            raise CloakScopeError("no url given")
        return opts

    async def from_args(
        self,
        args: Sequence[str],
        target: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        opts = self.parse_args(args, target)
        return await self.fetch(
            opts["url"],
            timeout=float(timeout or 30.0),
            screenshot=bool(opts.get("screenshot")),
            full_html=bool(opts.get("full_html", True)),
            wait_ms=int(opts.get("wait_ms", DEFAULT_WAIT_MS)),
            humanize=bool(opts.get("humanize")),
        )


def _main(argv: Optional[Sequence[str]] = None) -> int:
    import sys

    tool = CloakFetchTool()
    try:
        result = asyncio.run(tool.from_args(list(argv if argv is not None else sys.argv[1:])))
    except (CloakScopeError, CloakError) as e:
        print(f"cloakfetch: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_main())
