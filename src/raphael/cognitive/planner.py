from __future__ import annotations

import asyncio
import math
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple

from raphael.cognitive.models import (
    TargetModel, CapabilityModel, Affordance, Constraint, Capability,
    AffordanceType, CapabilityState
)


class MemoryPrior:
    """Manages technique priors from episodic memory."""
    
    def __init__(self):
        self.priors: Dict[str, float] = {}
        self.success_counts: Dict[str, int] = {}
        self.failure_counts: Dict[str, int] = {}
        self.default_recon_prior = 0.6
        self.default_exploit_prior = 0.3
    
    def get_prior(self, technique_id: str, technique_type: str) -> float:
        if technique_id in self.priors:
            return self.priors[technique_id]
        if technique_type == "recon":
            return self.default_recon_prior
        elif technique_type == "exploit":
            return self.default_exploit_prior
        return 0.5
    
    def update(self, technique_id: str, success: bool) -> None:
        if success:
            self.success_counts[technique_id] = self.success_counts.get(technique_id, 0) + 1
        else:
            self.failure_counts[technique_id] = self.failure_counts.get(technique_id, 0) + 1
        
        total = self.success_counts.get(technique_id, 0) + self.failure_counts.get(technique_id, 0)
        if total > 0:
            self.priors[technique_id] = (self.success_counts[technique_id] + 1) / (total + 2)


@dataclass
class TechniqueNode:
    technique_id: str
    technique: Any
    parent: Optional['TechniqueNode'] = None
    children: List['TechniqueNode'] = field(default_factory=list)
    visits: int = 0
    value: float = 0.0
    prior: float = 0.5
    depth: int = 0
    affordances_gained: List[str] = field(default_factory=list)
    constraints_added: List[str] = field(default_factory=list)
    cost: float = 1.0
    
    def ucb1(self, exploration: float = 1.4) -> float:
        if self.visits == 0:
            return float('inf')
        exploitation = self.value / self.visits
        exploration_term = exploration * math.sqrt(math.log(self.parent.visits) / self.visits) if self.parent else 0
        return exploitation + exploration_term


class GreedyPlanner:
    """Greedy one-step-ahead planner with MCTS for deeper lookahead."""
    
    def __init__(
        self,
        techniques: Dict[str, Any],
        target_model: TargetModel,
        capability_model: CapabilityModel,
        memory_prior: MemoryPrior,
        negative_cache: Any,
    ):
        self.techniques = techniques
        self.target_model = target_model
        self.capability_model = capability_model
        self.memory_prior = memory_prior
        self.negative_cache = negative_cache

        # Event waiters for state changes
        self._service_discovered_event = asyncio.Event()
        self._exploit_verified_event = asyncio.Event()
        self._detection_event = asyncio.Event()
        self._affordance_added_event = asyncio.Event()
        self._technique_result_event = asyncio.Event()
    
    def select_next_step(self) -> Optional[str]:
        executable = self._get_executable_techniques()
        
        if not executable:
            return None
        
        scored = []
        for tech_id in executable:
            score = self._score_technique(tech_id)
            scored.append((tech_id, score))
        
        scored.sort(key=lambda x: x[1], reverse=True)
        
        if scored and scored[0][1] > 0.3:
            return scored[0][0]
        
        return self._mcts_select(executable)

    def set_thermoregulator(self, thermoregulator) -> None:
        """Set the thermoregulator for pause checking."""
        self.thermoregulator = thermoregulator

    async def planning_loop(self, max_empty_cycles: int = 3) -> AsyncIterator[str]:
        """Main planning loop - yields next technique_id until engagement complete.
        
        Yields:
            technique_id: The next technique to execute
            
        The loop:
        1. Waits for state change (service.discovered, exploit.verified, etc.)
        2. Checks thermoregulator - waits if paused
        3. Selects next technique via select_next_step()
        3. Yields technique_id for execution
        4. Waits for outcome (exploit.verified or technique.result)
        
        Args:
            max_empty_cycles: Max consecutive cycles with no techniques before exiting
        """
        # Event waiters for different state changes
        self._service_discovered_event = asyncio.Event()
        self._exploit_verified_event = asyncio.Event()
        self._detection_event = asyncio.Event()
        self._affordance_added_event = asyncio.Event()
        
        empty_cycles = 0
        
        while True:
            # Wait for any state change
            await self._wait_for_state_change()
            
            # Check thermoregulator - wait if paused
            if hasattr(self, 'thermoregulator') and self.thermoregulator.is_paused():
                await asyncio.sleep(1.0)
                continue
            
            # Select next step
            technique_id = self.select_next_step()
            if technique_id is None:
                # No executable techniques - wait for new data
                empty_cycles += 1
                if empty_cycles >= max_empty_cycles and not self.techniques:
                    # No techniques registered at all - exit
                    return
                await asyncio.sleep(2.0)
                continue
            
            empty_cycles = 0
            yield technique_id
            
            # Wait for outcome (exploit.verified or technique.result)
            await self._wait_for_outcome(technique_id)

    async def _wait_for_state_change(self) -> None:
        """Wait for any relevant state change event."""
        events = [
            self._service_discovered_event.wait(),
            self._exploit_verified_event.wait(),
            self._detection_event.wait(),
            self._affordance_added_event.wait(),
        ]
        tasks = [asyncio.create_task(e) for e in events]
        done, pending = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED,
            timeout=30.0,
        )
        # Debounce: let concurrent events settle
        await asyncio.sleep(0.05)
        # Clear all events for next cycle
        for evt in [self._service_discovered_event, self._exploit_verified_event,
                    self._detection_event, self._affordance_added_event]:
            evt.clear()
        # Cancel any pending waits
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _wait_for_outcome(self, technique_id: str) -> None:
        """Wait for the outcome of a technique execution."""
        # In production, this would wait for exploit.verified or technique.result
        # For now, just wait a reasonable time
        await asyncio.sleep(5.0)

    def on_service_discovered(self) -> None:
        """Called when service.discovered event received."""
        self._service_discovered_event.set()

    def on_exploit_verified(self) -> None:
        self._exploit_verified_event.set()

    def on_detection(self) -> None:
        self._detection_event.set()

    def on_affordance_added(self) -> None:
        self._affordance_added_event.set()

    def _get_executable_techniques(self) -> List[str]:
        executable = []
        
        for tech_id, tech in self.techniques.items():
            if self.negative_cache.is_dead(tech_id, self.target_model):
                continue
            
            prereqs = getattr(tech, 'prerequisites', [])
            if not all(self.target_model.affordances.get(p) for p in prereqs):
                continue
            
            blockers = getattr(tech, 'blockers', [])
            blocked = False
            for constraint in self.target_model.constraints.values():
                if tech_id in constraint.blocks:
                    blocked = True
                    break
            if blocked:
                continue
            
            required_caps = getattr(tech, 'required_capabilities', [])
            if not all(
                self.capability_model.capabilities.get(cid, Capability(state=CapabilityState.UNKNOWN)).state == CapabilityState.AVAILABLE
                for cid in required_caps
            ):
                continue
            
            executable.append(tech_id)
        
        return executable
    
    def _score_technique(self, tech_id: str) -> float:
        tech = self.techniques[tech_id]
        
        prior = self.memory_prior.get_prior(tech_id, getattr(tech, 'type', 'recon'))
        
        new_affordances = self._estimate_new_affordances(tech)
        affordance_value = sum(
            1.0 for a in new_affordances 
            if a not in self.target_model.affordances
        ) * 0.2
        
        constraint_value = self._estimate_constraint_reduction(tech) * 0.15
        
        cost = getattr(tech, 'cost', 1.0)
        cost_penalty = min(0.3, cost * 0.1)
        
        risk = getattr(tech, 'detection_risk', 0.1)
        risk_penalty = risk * 0.2
        
        score = prior + affordance_value + constraint_value - cost_penalty - risk_penalty
        return max(0.0, score)
    
    def _estimate_new_affordances(self, tech) -> List[str]:
        return getattr(tech, 'provides_affordances', [])
    
    def _estimate_constraint_reduction(self, tech) -> float:
        blockers = getattr(tech, 'blockers', [])
        reduced = 0
        for c in self.target_model.constraints.values():
            if any(b in c.blocks for b in blockers):
                reduced += c.severity
        return reduced
    
    def _mcts_select(self, executable: List[str], iterations: int = 50) -> Optional[str]:
        if not executable:
            return None
        
        root = TechniqueNode(technique_id="root", technique=None, prior=1.0)
        
        for tech_id in executable:
            tech = self.techniques[tech_id]
            prior = self.memory_prior.get_prior(tech_id, getattr(tech, 'type', 'recon'))
            child = TechniqueNode(
                technique_id=tech_id,
                technique=tech,
                parent=root,
                prior=prior,
                depth=1,
                cost=getattr(tech, 'cost', 1.0),
            )
            root.children.append(child)
        
        for _ in range(iterations):
            node = self._select(root)
            
            if node.depth < 3 and node.technique_id != "root":
                self._expand(node)
            
            reward = self._simulate(node)
            
            self._backpropagate(node, reward)
        
        if root.children:
            best = max(root.children, key=lambda c: c.visits)
            return best.technique_id
        return executable[0] if executable else None
    
    def _select(self, node: TechniqueNode) -> TechniqueNode:
        while node.children:
            node = max(node.children, key=lambda c: c.ucb1())
        return node
    
    def _expand(self, node: TechniqueNode) -> None:
        executable = self._get_executable_techniques()
        for tech_id in executable:
            if tech_id != node.technique_id:
                tech = self.techniques[tech_id]
                prior = self.memory_prior.get_prior(tech_id, getattr(tech, 'type', 'recon'))
                child = TechniqueNode(
                    technique_id=tech_id,
                    technique=tech,
                    parent=node,
                    prior=prior,
                    depth=node.depth + 1,
                    cost=getattr(tech, 'cost', 1.0),
                )
                node.children.append(child)
    
    def _simulate(self, node: TechniqueNode) -> float:
        current = node
        total_reward = 0.0
        steps = 0
        
        while steps < 5:
            if not current.children:
                break
            current = random.choice(current.children)
            reward = self._score_technique(current.technique_id)
            total_reward += reward * (0.9 ** steps)
            steps += 1
        
        return total_reward
    
    def _backpropagate(self, node: TechniqueNode, reward: float) -> None:
        current = node
        while current:
            current.visits += 1
            current.value += reward
            current = current.parent

    def register_event_bus(self, eventbus: 'EventBus') -> None:
        """Register event bus to receive state change events."""
        eventbus.subscribe("service.discovered", lambda e: self.on_service_discovered())
        eventbus.subscribe("exploit.verified", lambda e: self.on_exploit_verified())
        eventbus.subscribe("detection.triggered", lambda e: self.on_detection())
        eventbus.subscribe("affordance.added", lambda e: self.on_affordance_added())
        eventbus.subscribe("technique.result", lambda e: self._technique_result_event.set())