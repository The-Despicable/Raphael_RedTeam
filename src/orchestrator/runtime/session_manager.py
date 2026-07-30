import logging, os, time
from typing import Optional
from .docker_client import DockerSandbox
from .caido_bootstrap import CaidoProxy

logger = logging.getLogger("runtime.session")

_SESSION_CACHE: dict[str, dict] = {}


class SandboxSession:
    def __init__(self, image: str = None):
        self.sandbox = DockerSandbox(image=image)
        self.caido = CaidoProxy()
        self._created_at = 0
        self._last_used = 0

    def start(self, mounts: list[dict] = None, with_caido: bool = False) -> bool:
        try:
            cid = self.sandbox.create_container(mounts=mounts, exposed_ports=(48080,))
            self._created_at = time.time()
            self._last_used = time.time()
            caido_ok = False
            if with_caido:
                caido_ok = self._start_caido()
            logger.info(f"Sandbox session started (container={cid[:12]}, caido={caido_ok})")
            return True
        except Exception as e:
            logger.error(f"Sandbox session start failed: {e}")
            self.sandbox.stop()
            return False

    def _start_caido(self) -> bool:
        self.sandbox.exec_command(
            ["caido-cli", "serve", "--port", "48080", "--no-open"],
            timeout=5,
        )
        import time as _time
        for _ in range(15):
            r = self.sandbox.exec_command(
                ["bash", "-c", "ss -tln | grep -q 48080 && echo ready || echo not"],
                timeout=5,
            )
            if r.get("stdout", "").strip() == "ready":
                break
            _time.sleep(1)
        else:
            logger.warning("Caido did not start in time")
            return False
        _time.sleep(2)
        ok = self.caido.bootstrap(self.sandbox)
        if ok:
            self.caido.set_container_proxy(self.sandbox)
        return ok

    def exec(self, cmd: list[str], timeout: int = 30, workdir: str = None) -> dict:
        self._last_used = time.time()
        if self.caido.capture_enabled():
            cmd = ["env", "http_proxy=http://127.0.0.1:48080",
                   "https_proxy=http://127.0.0.1:48080",
                   "HTTP_PROXY=http://127.0.0.1:48080",
                   "HTTPS_PROXY=http://127.0.0.1:48080"] + cmd
        return self.sandbox.exec_command(cmd, timeout=timeout, workdir=workdir)

    def copy_to(self, src: str, dst: str):
        self.sandbox.copy_to_container(src, dst)

    def stop(self):
        self.sandbox.stop()
        logger.info("Sandbox session stopped")

    @property
    def running(self) -> bool:
        return self.sandbox.running

    @property
    def age(self) -> float:
        return time.time() - self._created_at if self._created_at else 0

    @property
    def idle_time(self) -> float:
        return time.time() - self._last_used if self._last_used else 0

    @property
    def caido_running(self) -> bool:
        return self.caido.capture_enabled()


def create_session(image: str = None, mounts: list[dict] = None, with_caido: bool = False) -> Optional[SandboxSession]:
    session = SandboxSession(image=image)
    if session.start(mounts=mounts, with_caido=with_caido):
        return session
    return None


def get_or_create_session(session_id: str = None, image: str = None,
                          mounts: list[dict] = None) -> SandboxSession:
    if session_id and session_id in _SESSION_CACHE:
        session = _SESSION_CACHE[session_id]
        if session.running:
            return session
        logger.info(f"Cached session {session_id} is dead, creating new one")
    session = create_session(image=image, mounts=mounts)
    if session:
        sid = session_id or f"sandbox_{int(time.time())}"
        _SESSION_CACHE[sid] = session
    return session


def cleanup_old_sessions(max_age: int = 3600, max_idle: int = 600):
    now = time.time()
    for sid, session in list(_SESSION_CACHE.items()):
        if session.age > max_age or session.idle_time > max_idle:
            logger.info(f"Cleaning up session {sid} (age={session.age:.0f}s, idle={session.idle_time:.0f}s)")
            session.stop()
            del _SESSION_CACHE[sid]
