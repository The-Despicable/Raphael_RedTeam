from typing import Optional
from .models import C2Session, ImplantConfig, TaskResult, SessionStatus


class NoopBackend:
    def __init__(self):
        self._name = "noop"

    @property
    def available(self) -> bool:
        return False

    async def list_sessions(self) -> list[C2Session]:
        return []

    async def generate_implant(self, config: ImplantConfig) -> bytes:
        return b""

    async def send_task(self, session_id: str, command: str) -> TaskResult:
        return TaskResult(
            session_id=session_id, task_id="",
            output="", error="No C2 backend available",
            completed=False,
        )

    async def start_socks(self, session_id: str, port: int = 1081) -> Optional[str]:
        return None

    async def stop_socks(self, session_id: str):
        raise RuntimeError("Not implemented")

    async def stop(self):
        raise RuntimeError("Not implemented")
