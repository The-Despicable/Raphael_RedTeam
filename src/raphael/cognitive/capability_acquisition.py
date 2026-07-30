from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from raphael.cognitive.models import Capability, CapabilityModel, CapabilityState, AffordanceType

logger = logging.getLogger(__name__)


@dataclass
class AcquisitionPlan:
    capability_id: str
    technique_sequence: List[str]
    estimated_cost: float
    estimated_time: float
    risk: float
    prerequisites: List[str] = field(default_factory=list)


class CapabilityAcquisitionPipeline:
    """Manages parallel capability acquisition with cost estimation and dependency resolution."""
    
    def __init__(
        self,
        capability_model: CapabilityModel,
        target_model: Any,
        technique_registry: Dict[str, Any],
        max_parallel: int = 3,
    ):
        self.capability_model = capability_model
        self.target_model = target_model
        self.techniques = technique_registry
        self.max_parallel = max_parallel
        self._active_acquisitions: Dict[str, asyncio.Task] = {}
        self._plans: Dict[str, AcquisitionPlan] = {}
    
    def create_plan(self, capability_id: str) -> Optional[AcquisitionPlan]:
        """Create an acquisition plan for a capability."""
        cap = self.capability_model.capabilities.get(capability_id)
        if not cap or cap.state == CapabilityState.AVAILABLE:
            return None
        
        providing_techniques = [
            t for t in self.techniques.values()
            if cap.id in getattr(t, 'provides_capabilities', [])
        ]
        
        if not providing_techniques:
            providing_techniques = [
                t for t in self.techniques.values()
                if any(a in getattr(t, 'provides_affordances', []) for a in cap.provides)
            ]
        
        if not providing_techniques:
            return None
        
        best = min(providing_techniques, key=lambda t: getattr(t, 'cost', 1.0) + getattr(t, 'detection_risk', 0.1))
        
        prerequisites = []
        for dep_id in cap.prerequisites:
            dep = self.capability_model.capabilities.get(dep_id)
            if dep and dep.state != CapabilityState.AVAILABLE:
                prerequisites.append(dep_id)
        
        plan = AcquisitionPlan(
            capability_id=capability_id,
            technique_sequence=[best.id],
            estimated_cost=getattr(best, 'cost', 1.0),
            estimated_time=getattr(best, 'estimated_time', 60.0),
            risk=getattr(best, 'detection_risk', 0.1),
            prerequisites=prerequisites,
        )
        
        self._plans[capability_id] = plan
        return plan
    
    async def acquire(self, capability_id: str) -> bool:
        """Acquire a capability, handling dependencies first."""
        cap = self.capability_model.capabilities.get(capability_id)
        if not cap:
            return False
        
        if cap.state == CapabilityState.AVAILABLE:
            return True
        
        if cap.state == CapabilityState.COMPROMISED:
            task = self._active_acquisitions.get(capability_id)
            if task:
                await task
                return cap.state == CapabilityState.AVAILABLE
        
        for dep_id in cap.prerequisites:
            dep = self.capability_model.capabilities.get(dep_id)
            if dep and dep.state != CapabilityState.AVAILABLE:
                logger.info(f"Acquiring dependency {dep_id} for {capability_id}")
                await self.acquire(dep_id)
        
        if len(self._active_acquisitions) >= self.max_parallel:
            done, _ = await asyncio.wait(
                self._active_acquisitions.values(),
                return_when=asyncio.FIRST_COMPLETED,
            )
        
        task = asyncio.create_task(self._execute_acquisition(capability_id))
        self._active_acquisitions[capability_id] = task
        
        try:
            result = await task
            return result
        finally:
            self._active_acquisitions.pop(capability_id, None)
    
    async def _execute_acquisition(self, capability_id: str) -> bool:
        """Execute the acquisition plan."""
        plan = self._plans.get(capability_id)
        if not plan:
            plan = self.create_plan(capability_id)
            if not plan:
                return False
        
        cap = self.capability_model.capabilities[capability_id]
        cap.state = CapabilityState.COMPROMISED
        cap.last_used = datetime.now(timezone.utc)
        
        try:
            for tech_id in plan.technique_sequence:
                await asyncio.sleep(0.1)
            
            cap.state = CapabilityState.AVAILABLE
            cap.last_used = datetime.now(timezone.utc)
            logger.info(f"Capability acquired: {capability_id}")
            return True
            
        except Exception as e:
            logger.error(f"Acquisition failed for {capability_id}: {e}")
            cap.state = CapabilityState.UNAVAILABLE
            return False
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "active_acquisitions": len(self._active_acquisitions),
            "pending_plans": len(self._plans),
            "available": len(self.capability_model.get_available()),
            "acquiring": len(self.capability_model.get_by_state(CapabilityState.COMPROMISED)),
            "unavailable": len(self.capability_model.get_by_state(CapabilityState.UNAVAILABLE)),
        }