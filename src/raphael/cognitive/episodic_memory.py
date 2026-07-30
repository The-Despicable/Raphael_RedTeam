from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from raphael.cognitive.planner import TechniqueNode

logger = logging.getLogger(__name__)


@dataclass
class Episode:
    episode_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_signature: str = ""
    timestamp: float = field(default_factory=time.time)
    technique_sequence: List[str] = field(default_factory=list)
    affordances_gained: List[str] = field(default_factory=list)
    constraints_encountered: List[str] = field(default_factory=list)
    success: bool = False
    final_risk: float = 0.0
    final_value: float = 0.0
    duration: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class EpisodicMemory:
    def __init__(self, max_episodes: int = 10000, persistence_path: Optional[Path] = None):
        self.max_episodes = max_episodes
        self.persistence_path = persistence_path
        self._episodes: List[Episode] = []
        self._target_index: Dict[str, List[int]] = defaultdict(list)
        self._technique_index: Dict[str, List[int]] = defaultdict(list)
        self._success_counts: Dict[str, int] = defaultdict(int)
        self._failure_counts: Dict[str, int] = defaultdict(int)
        self._load()
    
    def _load(self) -> None:
        if not self.persistence_path or not self.persistence_path.exists():
            return
        try:
            with open(self.persistence_path) as f:
                data = json.load(f)
            for ep_data in data.get("episodes", []):
                ep = Episode(**ep_data)
                self._add_index(ep)
            logger.info(f"Loaded {len(self._episodes)} episodes from {self.persistence_path}")
        except Exception as e:
            logger.warning(f"Failed to load episodic memory: {e}")
    
    def _save(self) -> None:
        if not self.persistence_path:
            return
        try:
            data = {
                "episodes": [
                    {
                        "episode_id": ep.episode_id,
                        "target_signature": ep.target_signature,
                        "timestamp": ep.timestamp,
                        "technique_sequence": ep.technique_sequence,
                        "affordances_gained": ep.affordances_gained,
                        "constraints_encountered": ep.constraints_encountered,
                        "success": ep.success,
                        "final_risk": ep.final_risk,
                        "final_value": ep.final_value,
                        "duration": ep.duration,
                        "metadata": ep.metadata,
                    }
                    for ep in self._episodes
                ]
            }
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persistence_path, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning(f"Failed to save episodic memory: {e}")
    
    def _add_index(self, episode: Episode) -> None:
        self._target_index[episode.target_signature].append(len(self._episodes) - 1)
        for tech in episode.technique_sequence:
            self._technique_index[tech].append(len(self._episodes) - 1)
    
    def record_episode(
        self,
        target_signature: str,
        technique_sequence: List[str],
        affordances_gained: List[str],
        constraints_encountered: List[str],
        success: bool,
        final_risk: float,
        final_value: float,
        duration: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Episode:
        episode = Episode(
            target_signature=target_signature,
            technique_sequence=technique_sequence,
            affordances_gained=affordances_gained,
            constraints_encountered=constraints_encountered,
            success=success,
            final_risk=final_risk,
            final_value=final_value,
            duration=duration,
            metadata=metadata or {},
        )
        
        self._episodes.append(episode)
        self._add_index(episode)
        
        for tech in technique_sequence:
            if success:
                self._success_counts[tech] += 1
            else:
                self._failure_counts[tech] += 1
        
        self._evict()
        self._save()
        
        return episode
    
    def get_prior(self, technique_id: str) -> float:
        successes = self._success_counts.get(technique_id, 0)
        failures = self._failure_counts.get(technique_id, 0)
        total = successes + failures
        if total == 0:
            return 0.5
        return (successes + 1) / (total + 2)
    
    def get_similar_episodes(
        self,
        target_signature: str,
        limit: int = 10,
    ) -> List[Episode]:
        indices = self._target_index.get(target_signature, [])
        episodes = [self._episodes[i] for i in indices if i < len(self._episodes)]
        episodes.sort(key=lambda e: e.timestamp, reverse=True)
        return episodes[:limit]
    
    def get_technique_stats(self, technique_id: str) -> Dict[str, Any]:
        indices = self._technique_index.get(technique_id, [])
        episodes = [self._episodes[i] for i in indices if i < len(self._episodes)]
        
        if not episodes:
            return {"count": 0, "success_rate": 0.5, "avg_duration": 0.0}
        
        successes = sum(1 for e in episodes if e.success)
        return {
            "count": len(episodes),
            "success_rate": successes / len(episodes),
            "avg_duration": sum(e.duration for e in episodes) / len(episodes),
            "avg_risk": sum(e.final_risk for e in episodes) / len(episodes),
            "avg_value": sum(e.final_value for e in episodes) / len(episodes),
        }
    
    def get_frequent_sequences(self, min_count: int = 2, max_length: int = 5) -> List[Dict[str, Any]]:
        sequences: Dict[tuple, int] = defaultdict(int)
        
        for ep in self._episodes:
            if ep.success:
                for i in range(len(ep.technique_sequence)):
                    for j in range(i + 1, min(i + max_length + 1, len(ep.technique_sequence) + 1)):
                        seq = tuple(ep.technique_sequence[i:j])
                        sequences[seq] += 1
        
        frequent = [
            {"sequence": list(seq), "count": count, "success_rate": 1.0}
            for seq, count in sequences.items()
            if count >= min_count
        ]
        frequent.sort(key=lambda x: x["count"], reverse=True)
        return frequent
    
    def _evict(self) -> None:
        if len(self._episodes) <= self.max_episodes:
            return
        
        remove_count = len(self._episodes) - self.max_episodes
        removed = self._episodes[:remove_count]
        self._episodes = self._episodes[remove_count:]
        
        self._target_index.clear()
        self._technique_index.clear()
        for i, ep in enumerate(self._episodes):
            self._add_index(ep)
    
    def get_stats(self) -> Dict[str, Any]:
        total = len(self._episodes)
        successes = sum(1 for e in self._episodes if e.success)
        return {
            "total_episodes": total,
            "successful_episodes": successes,
            "success_rate": successes / total if total > 0 else 0,
            "unique_targets": len(self._target_index),
            "unique_techniques": len(self._technique_index),
        }


class ProceduralMemory:
    def __init__(self, persistence_path: Optional[Path] = None):
        self.persistence_path = persistence_path
        self._skills: Dict[str, "Skill"] = {}
        self._load()
    
    def _load(self) -> None:
        if not self.persistence_path or not self.persistence_path.exists():
            return
        try:
            with open(self.persistence_path) as f:
                data = json.load(f)
            for skill_data in data.get("skills", []):
                skill = Skill(**skill_data)
                self._skills[skill.skill_id] = skill
            logger.info(f"Loaded {len(self._skills)} skills from procedural memory")
        except Exception as e:
            logger.warning(f"Failed to load procedural memory: {e}")
    
    def _save(self) -> None:
        if not self.persistence_path:
            return
        try:
            data = {
                "skills": [
                    {
                        "skill_id": s.skill_id,
                        "name": s.name,
                        "description": s.description,
                        "technique_sequence": s.technique_sequence,
                        "preconditions": s.preconditions,
                        "postconditions": s.postconditions,
                        "success_count": s.success_count,
                        "failure_count": s.failure_count,
                        "avg_duration": s.avg_duration,
                        "avg_risk": s.avg_risk,
                        "created_at": s.created_at,
                        "last_used": s.last_used,
                    }
                    for s in self._skills.values()
                ]
            }
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persistence_path, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning(f"Failed to save procedural memory: {e}")
    
    def learn_skill(
        self,
        name: str,
        description: str,
        technique_sequence: List[str],
        preconditions: List[str],
        postconditions: List[str],
    ) -> "Skill":
        skill_id = str(uuid.uuid4())
        skill = Skill(
            skill_id=skill_id,
            name=name,
            description=description,
            technique_sequence=technique_sequence,
            preconditions=preconditions,
            postconditions=postconditions,
        )
        self._skills[skill_id] = skill
        self._save()
        return skill
    
    def record_execution(self, skill_id: str, success: bool, duration: float, risk: float) -> None:
        skill = self._skills.get(skill_id)
        if not skill:
            return
        
        if success:
            skill.success_count += 1
        else:
            skill.failure_count += 1
        
        total = skill.success_count + skill.failure_count
        skill.avg_duration = (skill.avg_duration * (total - 1) + duration) / total
        skill.avg_risk = (skill.avg_risk * (total - 1) + risk) / total
        skill.last_used = time.time()
        
        self._save()
    
    def get_applicable_skills(self, preconditions: List[str]) -> List["Skill"]:
        return [
            s for s in self._skills.values()
            if all(p in preconditions for p in s.preconditions)
        ]
    
    def get_best_skill(self, goal_conditions: List[str]) -> Optional["Skill"]:
        applicable = [
            s for s in self._skills.values()
            if any(g in s.postconditions for g in goal_conditions)
        ]
        if not applicable:
            return None
        
        return max(applicable, key=lambda s: s.success_count / max(1, s.success_count + s.failure_count))


@dataclass
class Skill:
    skill_id: str
    name: str
    description: str
    technique_sequence: List[str]
    preconditions: List[str]
    postconditions: List[str]
    success_count: int = 0
    failure_count: int = 0
    avg_duration: float = 0.0
    avg_risk: float = 0.0
    created_at: float = field(default_factory=time.time)
    last_used: float = 0.0
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.5


class SemanticMemory:
    def __init__(self, persistence_path: Optional[Path] = None):
        self.persistence_path = persistence_path
        self._facts: Dict[str, Dict[str, Any]] = {}
        self._relations: Dict[str, Dict[str, float]] = {}
        self._load()
    
    def _load(self) -> None:
        if not self.persistence_path or not self.persistence_path.exists():
            return
        try:
            with open(self.persistence_path) as f:
                data = json.load(f)
            self._facts = data.get("facts", {})
            self._relations = data.get("relations", {})
            logger.info(f"Loaded {len(self._facts)} facts from semantic memory")
        except Exception as e:
            logger.warning(f"Failed to load semantic memory: {e}")
    
    def _save(self) -> None:
        if not self.persistence_path:
            return
        try:
            data = {"facts": self._facts, "relations": self._relations}
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persistence_path, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning(f"Failed to save semantic memory: {e}")
    
    def add_fact(self, subject: str, predicate: str, obj: Any, confidence: float = 1.0) -> None:
        key = f"{subject}:{predicate}"
        if key not in self._facts:
            self._facts[key] = {"object": obj, "confidence": confidence, "updated": time.time()}
        else:
            old_conf = self._facts[key]["confidence"]
            self._facts[key] = {"object": obj, "confidence": max(old_conf, confidence), "updated": time.time()}
        self._save()
    
    def get_fact(self, subject: str, predicate: str) -> Optional[Any]:
        key = f"{subject}:{predicate}"
        return self._facts.get(key, {}).get("object")
    
    def add_relation(self, subject: str, relation: str, target: str, strength: float = 1.0) -> None:
        if subject not in self._relations:
            self._relations[subject] = {}
        self._relations[subject][f"{relation}:{target}"] = strength
        self._save()
    
    def get_relations(self, subject: str) -> Dict[str, float]:
        return self._relations.get(subject, {})
    
    def query(self, subject: Optional[str] = None, predicate: Optional[str] = None) -> List[Dict[str, Any]]:
        results = []
        for key, value in self._facts.items():
            subj, pred = key.split(":", 1)
            if subject and subj != subject:
                continue
            if predicate and pred != predicate:
                continue
            results.append({"subject": subj, "predicate": pred, **value})
        return results