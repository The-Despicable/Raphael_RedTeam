"""Spinal Reflex — direct circuit breaker inhibition. No event bus latency."""
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from raphael.executor.executor import Executor

logger = logging.getLogger("raphael.spinal_reflex")

class SpinalReflex:
    """
    Direct method call. No event. No queue.
    The thermoregulator calls inhibit() which directly pauses the executor,
    THEN publishes an event for logging.
    """

    def __init__(self, executor: "Executor"):
        self._executor = executor

    def inhibit(self, reason: str) -> None:
        """Directly pause the executor. Called from thermoregulator tick."""
        self._executor.pause(reason)
        logger.warning(f"SPINAL REFLEX: Executor inhibited — {reason}")

    def release(self) -> None:
        """Resume the executor."""
        self._executor.resume()
        logger.info("SPINAL REFLEX: Executor released")
