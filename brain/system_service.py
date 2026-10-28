"""External system integration: Tor, Sliver, Neo4j.

Each subsystem degrades gracefully when unavailable. State is queried lazily
and surfaced via /health without crashing the service on startup.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

import httpx

from .config import Settings, get_settings

log = logging.getLogger("brain.system")


async def _probe_tcp(host: str, port: int, timeout: float = 1.5) -> bool:
    """Cheap TCP probe (does not send data). The pending connect future is
    cancelled/suppressed on failure so asyncio never logs
    'exception was never retrieved' for leaked sockets."""
    fut = asyncio.ensure_future(asyncio.open_connection(host, port))
    try:
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        fut.cancel()
        try:
            await fut
        except (asyncio.CancelledError, OSError):
            pass
        return False


def _split_hostport(s: str, default_port: int) -> tuple[str, int]:
    if not s:
        return "", default_port
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return host, int(port) if port.isdigit() else default_port
    return s, default_port


# ---------------------------------------------------------------------------
# Tor
# ---------------------------------------------------------------------------


class TorService:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.socks_host, self.socks_port = _split_hostport(
            self.settings.tor_socks, 9050
        )
        self.control_host, self.control_port = _split_hostport(
            self.settings.tor_control, 9051
        )

    async def health(self) -> Dict[str, Any]:
        socks_up = await _probe_tcp(self.socks_host, self.socks_port) if self.socks_host else False
        ctrl_up = (
            await _probe_tcp(self.control_host, self.control_port)
            if self.control_host
            else False
        )
        return {
            "configured": bool(self.settings.tor_socks),
            "socks": f"{self.socks_host}:{self.socks_port}",
            "control": f"{self.control_host}:{self.control_port}",
            "socks_reachable": socks_up,
            "control_reachable": ctrl_up,
            "control_pass_configured": bool(self.settings.tor_control_pass),
        }

    def socks_proxy_url(self) -> Optional[str]:
        if not self.settings.tor_socks:
            return None
        return f"socks5://{self.socks_host}:{self.socks_port}"


# ---------------------------------------------------------------------------
# Sliver
# ---------------------------------------------------------------------------


class SliverService:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.operator_config_path = self.settings.sliver_operator_config
        self._backend: Optional[Any] = None
        self._initialized = False

    def _load_backend(self) -> Optional[Any]:
        if self._initialized:
            return self._backend
        self._initialized = True
        if not self.operator_config_path:
            log.info("Sliver operator config not set; Sliver unavailable")
            return None
        try:
            from orchestrator.c2.sliver_backend import SliverBackend  # type: ignore

            self._backend = SliverBackend(config_path=self.operator_config_path)
            log.info("Sliver backend loaded from %s", self.operator_config_path)
        except Exception as e:  # noqa: BLE001
            log.warning("Sliver backend load failed: %s", str(e)[:200])
            self._backend = None
        return self._backend

    async def health(self) -> Dict[str, Any]:
        backend = self._load_backend()
        return {
            "configured": bool(self.operator_config_path),
            "operator_config": self.operator_config_path,
            "backend_loaded": backend is not None,
            "backend_type": type(backend).__name__ if backend else None,
        }

    def backend(self) -> Optional[Any]:
        return self._load_backend()


# ---------------------------------------------------------------------------
# Neo4j
# ---------------------------------------------------------------------------


class Neo4jService:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.uri = self.settings.neo4j_uri
        self.user = self.settings.neo4j_user
        self.password = self.settings.neo4j_pass
        self._driver: Optional[Any] = None

    def _load_driver(self) -> Optional[Any]:
        if self._driver is not None:
            return self._driver
        if not (self.uri and self.user and self.password):
            log.info("Neo4j credentials incomplete; skipping driver")
            return None
        try:
            from neo4j import AsyncGraphDatabase  # type: ignore

            self._driver = AsyncGraphDatabase.driver(
                self.uri, auth=(self.user, self.password)
            )
            log.info("Neo4j driver created for %s", self.uri)
        except Exception as e:  # noqa: BLE001
            log.warning("Neo4j driver creation failed: %s", str(e)[:200])
            self._driver = None
        return self._driver

    async def health(self) -> Dict[str, Any]:
        driver = self._load_driver()
        reachable = False
        if driver is not None:
            try:
                async with driver.session() as s:
                    await s.run("RETURN 1")
                    reachable = True
            except Exception as e:  # noqa: BLE001
                log.debug("Neo4j ping failed: %s", str(e)[:120])
        return {
            "configured": bool(self.uri and self.user),
            "uri": self.uri,
            "driver_loaded": driver is not None,
            "reachable": reachable,
        }

    async def close(self) -> None:
        if self._driver is not None:
            try:
                await self._driver.close()
            except Exception:
                pass
            self._driver = None


# ---------------------------------------------------------------------------
# Kali Tools HTTP
# ---------------------------------------------------------------------------


class KaliToolsHealthService:
    """Probes the Kali tools HTTP service. Actual tool execution lives in
    tools_service.py via the orchestrator.kali_tools_client wrapper."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.url = self.settings.kali_tools_url.rstrip("/")

    async def health(self) -> Dict[str, Any]:
        if not self.url:
            return {"configured": False, "reachable": False}
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                r = await client.get(f"{self.url}/health")
                return {
                    "configured": True,
                    "url": self.url,
                    "reachable": r.status_code < 500,
                    "http_status": r.status_code,
                }
        except (httpx.RequestError, httpx.HTTPError) as e:
            return {
                "configured": True,
                "url": self.url,
                "reachable": False,
                "error": str(e)[:120],
            }


# ---------------------------------------------------------------------------
# Aggregate system health
# ---------------------------------------------------------------------------


class SystemHealthService:
    """Aggregates all subsystem probes. The snapshot is cached for `ttl`
    seconds so Docker's 30s HEALTHCHECK (and any monitoring scraper) does not
    hammer Tor/Neo4j/Kali with fresh TCP/HTTP probes on every /health call."""

    def __init__(
        self,
        tor: Optional[TorService] = None,
        sliver: Optional[SliverService] = None,
        neo4j: Optional[Neo4jService] = None,
        kali: Optional[KaliToolsHealthService] = None,
        ttl: float = 10.0,
    ):
        self.tor = tor or TorService()
        self.sliver = sliver or SliverService()
        self.neo4j = neo4j or Neo4jService()
        self.kali = kali or KaliToolsHealthService()
        self.ttl = ttl
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_ts: float = 0.0
        self._lock = asyncio.Lock()

    async def snapshot(self) -> Dict[str, Any]:
        async with self._lock:
            now = time.monotonic()
            if self._cache is not None and (now - self._cache_ts) < self.ttl:
                return self._cache

            # Run probes concurrently.
            tor_h, sliver_h, neo4j_h, kali_h = await asyncio.gather(
                self.tor.health(),
                self.sliver.health(),
                self.neo4j.health(),
                self.kali.health(),
                return_exceptions=True,
            )

            def _safe(x: Any) -> Dict[str, Any]:
                if isinstance(x, Exception):
                    return {"error": str(x)[:160]}
                return x  # type: ignore[return-value]

            self._cache = {
                "tor": _safe(tor_h),
                "sliver": _safe(sliver_h),
                "neo4j": _safe(neo4j_h),
                "kali_tools": _safe(kali_h),
                "cached_for_seconds": self.ttl,
            }
            self._cache_ts = now
            return self._cache

    async def close(self) -> None:
        await self.neo4j.close()
