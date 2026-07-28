import time
import logging
import uuid
from typing import Any, Callable, Optional

import asyncio

logger = logging.getLogger("engagement_queue")


class QueueEntry:
    def __init__(self, target: str, phases: list[str], persona: str = "", webhook_url: str = "") -> None:
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.phases = phases
        self.persona = persona
        self.webhook_url = webhook_url
        self.status = "pending"
        self.current_phase = ""
        self.phases_completed = 0
        self.findings_count = 0
        self.error = ""
        self.result: dict | None = None
        self.created_at = time.time()
        self.updated_at = time.time()


class EngagementQueue:
    def __init__(self) -> None:
        self._entries: list[QueueEntry] = []

    def enqueue(self, target: str, phases: list[str], persona: str = "", webhook_url: str = "") -> str:
        entry = QueueEntry(target, phases, persona, webhook_url)
        self._entries.append(entry)
        return entry.id

    def get(self, entry_id: str) -> QueueEntry | None:
        for e in self._entries:
            if e.id == entry_id:
                return e
        return None

    def list(self) -> list[QueueEntry]:
        return self._entries

    def update(self, entry_id: str, status: str = "", result: dict | None = None, findings_count: int = 0) -> None:
        for e in self._entries:
            if e.id == entry_id:
                if status:
                    e.status = status
                if result is not None:
                    e.result = result
                e.findings_count = findings_count
                e.updated_at = time.time()
                break

    def stats(self) -> dict:
        total = len(self._entries)
        completed = sum(1 for e in self._entries if e.status == "complete")
        failed = sum(1 for e in self._entries if e.status == "failed")
        running = sum(1 for e in self._entries if e.status == "running")
        return {"total": total, "completed": completed, "failed": failed, "running": running}

    async def run_loop(self, handler: Callable) -> None:
        while True:
            pending = [e for e in self._entries if e.status == "pending"]
            for entry in pending:
                entry.status = "running"
                entry.updated_at = time.time()
                try:
                    result = await handler(entry.target, entry.phases)
                    entry.status = "complete"
                    entry.result = result
                except Exception as exc:
                    entry.status = "failed"
                    entry.error = str(exc)
                    entry.result = {"error": str(exc)}
                entry.updated_at = time.time()
            await asyncio.sleep(5)


_queue: EngagementQueue | None = None


def get_queue() -> EngagementQueue:
    global _queue
    if _queue is None:
        _queue = EngagementQueue()
    return _queue
