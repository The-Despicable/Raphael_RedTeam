from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Type
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from raphael.blackboard.schemas import SCHEMA_REGISTRY

logger = logging.getLogger(__name__)


class BlackboardException(Exception):
    """Raised when a blackboard write violates a contract."""
    pass


@dataclass
class WriteResult:
    """Result of a blackboard write operation."""
    event_type: str
    success: bool
    error: Optional[str] = None
    validation_time_ms: float = 0.0


class Blackboard:
    """Enforced write layer between components and the EventBus.

    Every write MUST pass schema validation. No exceptions.
    """

    def __init__(self, eventbus: "EventBus"):  # type: ignore
        self._bus = eventbus
        self._write_history: list[WriteResult] = []
        self._max_history: int = 1000
        self._enforce_strict: bool = True

    @property
    def bus(self):
        return self._bus

    def _record(self, result: WriteResult) -> None:
        self._write_history.append(result)
        if len(self._write_history) > self._max_history:
            self._write_history = self._write_history[-self._max_history:]

    async def write(
        self,
        event_type: str,
        data: Dict[str, Any],
        trace_id: Optional[str] = None,
    ) -> WriteResult:
        """Write data to the blackboard with enforced schema validation.

        Args:
            event_type: Must match a key in SCHEMA_REGISTRY
            data: Raw dict, validated against the matching schema
            trace_id: Optional trace to propagate

        Returns:
            WriteResult with success/failure

        Raises:
            BlackboardException: If strict mode is off and validation fails
        """
        import time
        start = time.perf_counter()

        schema = SCHEMA_REGISTRY.get(event_type)
        if schema is None:
            msg = f"Unknown event_type: {event_type}. Registered: {list(SCHEMA_REGISTRY.keys())}"
            logger.error(msg)
            result = WriteResult(event_type=event_type, success=False, error=msg)
            self._record(result)
            if self._enforce_strict:
                raise BlackboardException(msg)
            return result

        try:
            validated = schema(**data)
        except ValidationError as e:
            msg = f"Schema validation failed for {event_type}: {e}"
            logger.error(msg)
            result = WriteResult(event_type=event_type, success=False, error=msg)
            self._record(result)
            if self._enforce_strict:
                raise BlackboardException(msg)
            return result

        try:
            event = await self._bus.publish(
                event_type=event_type,
                payload=validated.model_dump(),
                trace_id=trace_id,
            )
            elapsed = (time.perf_counter() - start) * 1000
            logger.debug(f"Blackboard write: {event_type} → {event.id} ({elapsed:.1f}ms)")
            result = WriteResult(
                event_type=event_type,
                success=True,
                validation_time_ms=elapsed,
            )
            self._record(result)
            return result
        except Exception as e:
            msg = f"EventBus publish failed for {event_type}: {e}"
            logger.error(msg)
            result = WriteResult(event_type=event_type, success=False, error=msg)
            self._record(result)
            if self._enforce_strict:
                raise BlackboardException(msg)
            return result

    def subscribe(self, event_type: str, handler):
        """Subscribe a handler to receive validated events.

        Decorates the handler with schema validation on the read side too.
        """
        schema = SCHEMA_REGISTRY.get(event_type)

        async def validated_handler(raw_event):
            if schema is not None:
                try:
                    validated = schema.model_validate(raw_event.payload)
                    raw_event.payload = validated.model_dump()
                except ValidationError as e:
                    logger.error(f"Read-side validation failed for {event_type}: {e}")
                    return
            await handler(raw_event)

        self._bus.subscribe(event_type, validated_handler)

    def get_write_stats(self) -> Dict[str, Any]:
        if not self._write_history:
            return {"total": 0, "success": 0, "fail": 0}
        successes = sum(1 for r in self._write_history if r.success)
        return {
            "total": len(self._write_history),
            "success": successes,
            "fail": len(self._write_history) - successes,
            "success_rate": successes / len(self._write_history),
        }

    def get_recent_failures(self, count: int = 10) -> list[WriteResult]:
        return [r for r in self._write_history[-count:] if not r.success]

    def reset_stats(self) -> None:
        self._write_history.clear()

    @property
    def strict_mode(self) -> bool:
        return self._enforced_strict

    @strict_mode.setter
    def strict_mode(self, value: bool) -> None:
        self._enforced_strict = value
        logger.warning(f"Blackboard strict enforcement: {'ON' if value else 'OFF (DEBUG ONLY)'}")