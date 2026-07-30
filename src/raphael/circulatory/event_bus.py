"""Event Bus — asyncio pub/sub coordination for Raphael organs."""
import asyncio
import logging
from typing import Callable, Awaitable, Any

logger = logging.getLogger("raphael.event_bus")

EventHandler = Callable[[str, dict[str, Any]], Awaitable[None]]

class EventBus:
    """Async pub/sub. Components subscribe to event types, publish to notify."""

    def __init__(self):
        self._subscribers: dict[str, list[EventHandler]] = {}

    def subscribe(self, event_type: str, callback: EventHandler):
        """Register a callback for an event type."""
        self._subscribers.setdefault(event_type, []).append(callback)
        logger.debug(f"Subscribed {callback.__name__} to {event_type}")

    def unsubscribe(self, event_type: str, callback: EventHandler):
        """Remove a callback."""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type]
                if cb is not callback
            ]

    async def publish(self, event_type: str, payload: dict[str, Any] | None = None):
        """Publish an event to all subscribers (fire-and-forget)."""
        if payload is None:
            payload = {}
        callbacks = self._subscribers.get(event_type, [])
        if not callbacks:
            return
        # Fire concurrently — one failing doesn't block others
        await asyncio.gather(
            *[cb(event_type, payload) for cb in callbacks],
            return_exceptions=True
        )
        logger.debug(f"Published {event_type} to {len(callbacks)} subscribers")
