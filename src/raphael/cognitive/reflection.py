from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from raphael.cognitive.models import TargetModel, CapabilityModel
from raphael.cognitive.episodic_memory import EpisodicMemory, Episode

logger = logging.getLogger(__name__)


@dataclass
class ReflectionResult:
    technique_weight_changes: Dict[str, float] = field(default_factory=dict)
    new_heuristic_rules: List[Dict] = field(default_factory=list)
    capability_updates: Dict[str, Dict] = field(default_factory=dict)
    new_prior_beliefs: Dict[str, float] = field(default_factory=dict)
    strategic_insights: List[str] = field(default_factory=list)


class ReflectionEngine:
    """Post-engagement reflection - replays decisions, updates weights, learns."""
    
    def __init__(
        self,
        target_model: TargetModel,
        capability_model: CapabilityModel,
        episodic_memory: EpisodicMemory,
        memory_prior: Any,
    ):
        self.target_model = target_model
        self.capability_model = capability_model
        self.episodic_memory = episodic_memory
        self.memory_prior = memory_prior
    
    def reflect(self, episode: Episode) -> ReflectionResult:
        """Run full reflection cycle on completed episode."""
        result = ReflectionResult()
        
        result.technique_weight_changes = self._replay_decisions(episode)
        result.new_heuristic_rules = self._extract_heuristics(episode)
        result.capability_updates = self._update_capabilities(episode)
        result.new_prior_beliefs = self._update_priors(episode)
        result.strategic_insights = self._extract_insights(episode)
        
        return result
    
    def _replay_decisions(self, episode: Episode) -> Dict[str, float]:
        """Replay each technique decision and evaluate."""
        changes = {}
        
        for tech_id in episode.technique_sequence:
            old_prior = self.memory_prior.get_prior(tech_id, "exploit")
            
            if episode.success:
                new_prior = min(0.95, old_prior + 0.02)
            else:
                new_prior = max(0.05, old_prior - 0.01)
            
            if abs(new_prior - old_prior) > 0.01:
                self.memory_prior.priors[tech_id] = new_prior
                changes[tech_id] = new_prior - old_prior
        
        return changes
    
    def _extract_heuristics(self, episode: Episode) -> List[Dict]:
        """Extract new heuristic rules from episode."""
        heuristics = []
        
        if episode.success and len(episode.technique_sequence) >= 2:
            heuristics.append({
                "rule": f"sequence_{'_'.join(episode.technique_sequence)}",
                "condition": "target_has_affordances",
                "action": "execute_sequence",
                "sequence": list(episode.technique_sequence),
                "confidence": 0.7,
                "source_episode": episode.episode_id,
            })
        
        for constraint in episode.constraints_encountered:
            pass
        
        return heuristics
    
    def _update_capabilities(self, episode: Episode) -> Dict[str, Dict]:
        """Update capability reliability based on episode."""
        updates = {}
        
        return updates
    
    def _update_priors(self, episode: Episode) -> Dict[str, float]:
        """Update memory priors from episode outcome."""
        new_priors = {}
        
        for tech_id in episode.technique_sequence:
            prior = self.episodic_memory.get_prior(tech_id)
            new_priors[tech_id] = prior
        
        return new_priors
    
    def _extract_insights(self, episode: Episode) -> List[str]:
        """Extract high-level strategic insights."""
        insights = []
        
        if episode.success:
            insights.append(f"Engagement successful: {len(episode.technique_sequence)} techniques, risk={episode.final_risk:.2f}")
            
            if episode.affordances_gained:
                insights.append(f"Key affordances gained: {', '.join(episode.affordances_gained)}")
            
            if episode.constraints_encountered:
                insights.append(f"Constraints bypassed: {', '.join(episode.constraints_encountered)}")
        else:
            insights.append(f"Engagement failed at technique {episode.technique_sequence[-1] if episode.technique_sequence else 'unknown'}")
            
            if episode.constraints_encountered:
                insights.append(f"Blocked by: {', '.join(episode.constraints_encountered)}")
        
        return insights