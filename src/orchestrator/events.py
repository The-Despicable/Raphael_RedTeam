"""Minimal event bus for orchestrator agents."""

import asyncio
import logging
from typing import Any

logger = logging.getLogger("events")


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list] = {}

    def subscribe(self, event_type: str, callback) -> None:
        self._subscribers.setdefault(event_type, []).append(callback)

    async def emit(self, event_type: str, **data) -> None:
        for cb in self._subscribers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(event_type, data)
                else:
                    cb(event_type, data)
            except Exception:
                logger.exception(f"EventBus handler failed for {event_type}")


event_bus = EventBus()
