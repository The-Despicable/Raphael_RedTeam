from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable

from raphael.cognitive.models import TargetModel, CapabilityModel
from raphael.cognitive.planner import GreedyPlanner, MemoryPrior
from raphael.cognitive.episodic_memory import EpisodicMemory

logger = logging.getLogger(__name__)


@dataclass
class ModificationProposal:
    proposal_id: str
    modification_type: str
    target: str
    old_value: Any
    new_value: Any
    reasoning: str
    confidence: float
    test_plan: List[str] = field(default_factory=list)
    status: str = "proposed"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SelfModificationEngine:
    """Allows the system to modify its own decision logic based on experience."""
    
    def __init__(
        self,
        planner: GreedyPlanner,
        memory_prior: MemoryPrior,
        episodic_memory: EpisodicMemory,
        target_model: TargetModel,
        capability_model: CapabilityModel,
    ):
        self.planner = planner
        self.memory_prior = memory_prior
        self.episodic_memory = episodic_memory
        self.target_model = target_model
        self.capability_model = capability_model
        
        self._proposals: Dict[str, ModificationProposal] = {}
        self._accepted_modifications: List[str] = []
        self._modification_history: List[Dict] = []
    
    def propose_weight_change(self, technique_id: str, new_prior: float, reasoning: str) -> str:
        """Propose changing a technique's memory prior."""
        old_prior = self.memory_prior.get_prior(technique_id, "exploit")
        
        proposal = ModificationProposal(
            proposal_id=str(uuid.uuid4()),
            modification_type="weight_change",
            target=technique_id,
            old_value=old_prior,
            new_value=new_prior,
            reasoning=reasoning,
            confidence=0.7,
            test_plan=[f"Run engagement with {technique_id} at priority {new_prior}"],
        )
        
        self._proposals[proposal.proposal_id] = proposal
        return proposal.proposal_id
    
    def propose_heuristic(self, rule: Dict[str, Any], reasoning: str) -> str:
        """Propose a new heuristic rule for the hypothesizer."""
        proposal = ModificationProposal(
            proposal_id=str(uuid.uuid4()),
            modification_type="heuristic_add",
            target="hypothesizer_rules",
            old_value=None,
            new_value=rule,
            reasoning=reasoning,
            confidence=0.6,
            test_plan=["Test on next engagement with matching unknown"],
        )
        
        self._proposals[proposal.proposal_id] = proposal
        return proposal.proposal_id
    
    def propose_priority_change(self, technique_id: str, new_priority: float, reasoning: str) -> str:
        """Propose changing technique priority in planner."""
        proposal = ModificationProposal(
            proposal_id=str(uuid.uuid4()),
            modification_type="priority_change",
            target=technique_id,
            old_value=None,
            new_value=new_priority,
            reasoning=reasoning,
            confidence=0.6,
            test_plan=[f"Observe planner selection with {technique_id} at priority {new_priority}"],
        )
        
        self._proposals[proposal.proposal_id] = proposal
        return proposal.proposal_id
    
    async def evaluate_and_apply(self) -> List[str]:
        """Evaluate all proposals and apply accepted ones."""
        accepted = []
        
        for proposal_id, proposal in list(self._proposals.items()):
            if proposal.status != "proposed":
                continue
            
            if proposal.confidence >= 0.7 and self._is_safe(proposal):
                await self._apply(proposal)
                proposal.status = "accepted"
                accepted.append(proposal_id)
                self._accepted_modifications.append(proposal_id)
                logger.info(f"Accepted modification: {proposal.modification_type} on {proposal.target}")
            else:
                proposal.status = "rejected"
                logger.info(f"Rejected modification: {proposal.modification_type} on {proposal.target}")
        
        return accepted
    
    def _is_safe(self, proposal: ModificationProposal) -> bool:
        """Check if modification is safe to apply."""
        if proposal.modification_type == "weight_change":
            if isinstance(proposal.old_value, float) and isinstance(proposal.new_value, float):
                change = abs(proposal.new_value - proposal.old_value)
                if change > 0.3:
                    return False
        
        if proposal.modification_type == "heuristic_remove":
            return False
        
        return True
    
    async def _apply(self, proposal: ModificationProposal) -> None:
        """Apply an accepted modification."""
        if proposal.modification_type == "weight_change":
            self.memory_prior.priors[proposal.target] = proposal.new_value
        
        elif proposal.modification_type == "heuristic_add":
            logger.info(f"Would add heuristic: {proposal.new_value}")
        
        elif proposal.modification_type == "priority_change":
            logger.info(f"Would change priority for {proposal.target}")
        
        self._modification_history.append({
            "proposal_id": proposal.proposal_id,
            "type": proposal.modification_type,
            "target": proposal.target,
            "old": proposal.old_value,
            "new": proposal.new_value,
            "applied_at": datetime.now(timezone.utc).isoformat(),
        })
    
    def get_pending_proposals(self) -> List[ModificationProposal]:
        return [p for p in self._proposals.values() if p.status == "proposed"]
    
    def get_history(self) -> List[Dict]:
        return self._modification_history