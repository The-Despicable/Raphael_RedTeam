from __future__ import annotations

import asyncio
import logging
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThermoregulatorConfig:
    normal_threshold: float = 0.3
    elevated_threshold: float = 0.5
    high_threshold: float = 0.7
    critical_threshold: float = 0.85
    check_interval: float = 1.0
    pause_on_critical: bool = True
    resume_threshold: float = 0.3


class Thermoregulator:
    def __init__(self, config: ThermoregulatorConfig):
        self.config = config
        self.current_risk = 0.0
        self.current_level = RiskLevel.NORMAL
        self.paused = False
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._risk_sources: Dict[str, Callable[[], float]] = {}
        self._risk_refs: Dict[str, weakref.ReferenceType] = {}
        self._callbacks: List[Callable[[RiskLevel, float], None]] = []
        self._last_check = datetime.now(timezone.utc)

    def register_risk_source(self, name: str, getter: Callable[[], float]) -> None:
        self._risk_sources[name] = getter

    def register_callback(self, callback: Callable[[RiskLevel, float], None]) -> None:
        self._callbacks.append(callback)

    def watch(self, name: str, obj: Any, attr: str = "risk_score") -> None:
        """Watch an object's risk attribute via weak reference.

        Args:
            name: Identifier for this risk source
            obj: Object to watch
            attr: Attribute name on object that holds risk score (0-1)
        """
        def getter():
            ref = self._risk_refs.get(name)
            if ref is None:
                return 0.0
            target = ref()
            if target is None:
                return 0.0  # Object garbage collected
            return getattr(target, attr, 0.0)

        ref = weakref.ref(obj)
        self._risk_refs[name] = ref
        self._risk_sources[name] = getter

    def unwatch(self, name: str) -> None:
        """Stop watching a risk source."""
        self._risk_refs.pop(name, None)
        self._risk_sources.pop(name, None)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Thermoregulator started")
    
    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Thermoregulator stopped")
    
    async def _loop(self) -> None:
        while self._running:
            await self._check_risk()
            await asyncio.sleep(1.0 / max(0.1, self.config.check_interval))
    
    async def _check_risk(self) -> None:
        total_risk = 0.0
        for name, getter in self._risk_sources.items():
            try:
                risk = getter()
                total_risk = max(total_risk, risk)
            except Exception as e:
                logger.debug(f"Risk source {name} failed: {e}")
        
        self.current_risk = min(1.0, total_risk)
        self._update_level()
        self._last_check = datetime.now(timezone.utc)
    
    def _update_level(self) -> None:
        old_level = self.current_level
        
        if self.current_risk >= self.config.critical_threshold:
            self.current_level = RiskLevel.CRITICAL
        elif self.current_risk >= self.config.high_threshold:
            self.current_level = RiskLevel.HIGH
        elif self.current_risk >= self.config.elevated_threshold:
            self.current_level = RiskLevel.ELEVATED
        else:
            self.current_level = RiskLevel.NORMAL
        
        if self.current_level != old_level:
            logger.warning(f"Risk level changed: {old_level} -> {self.current_level} (risk={self.current_risk:.2f})")
            for callback in self._callbacks:
                try:
                    callback(self.current_level, self.current_risk)
                except Exception as e:
                    logger.error(f"Risk callback failed: {e}")
        
        if self.config.pause_on_critical:
            if self.current_level == RiskLevel.CRITICAL and not self.paused:
                self.paused = True
                logger.critical("THERMOREGULATOR: PAUSED - Critical risk threshold exceeded")
            elif self.current_level != RiskLevel.CRITICAL and self.paused:
                if self.current_risk <= self.config.resume_threshold:
                    self.paused = False
                    logger.info("Thermoregulator: Resumed - risk below resume threshold")
    
    def is_paused(self) -> bool:
        return self.paused
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "current_risk": self.current_risk,
            "level": self.current_level.value,
            "paused": self.paused,
            "sources": list(self._risk_sources.keys()),
            "last_check": self._last_check.isoformat(),
        }