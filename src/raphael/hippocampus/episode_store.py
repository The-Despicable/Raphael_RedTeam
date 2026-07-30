"""
Hippocampus Lite — episodic memory with weighted similarity.
Stores engagement narratives. Matches current profile to past engagements
using weighted Jaccard similarity that distinguishes constraints from affordances.
"""
from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from raphael.models.target_model import TargetModel
from raphael.models.engagement_state import EngagementState

logger = logging.getLogger("raphael.hippocampus")


@dataclass
class Episode:
    """A full engagement narrative stored in hippocampal memory."""
    engagement_id: str
    target_address: str
    timestamp: float = 0.0
    target_profile_snapshot: dict = field(default_factory=dict)
    sequence: list[dict] = field(default_factory=list)  # list of {cycle, technique, outcome, delta}
    decisions: list[dict] = field(default_factory=list)  # list of {cycle, chosen, runner_up, reason}
    outcome: str = "unknown"  # "success" | "partial" | "failure" | "interrupted"
    reflection: str = ""


@dataclass
class MatchResult:
    """A matched past episode with similarity score."""
    episode: Episode
    similarity: float
    suggested_next_technique: Optional[str] = None


class Hippocampus:
    """
    Episodic memory store with weighted similarity matching.
    
    Weighted similarity treats constraints and affordances differently:
    - Matching constraint + constraint → positive (same blocker)
    - Matching affordance + affordance → positive (same capability)
    - Constraint in A vs. same string in B's affordances → negative (opposite states)
    
    This prevents bad matches like "WAF present" ↔ "no WAF".
    """

    STORE_PATH = Path(__file__).parent.parent / "data" / "hippocampus_episodes.json"

    def __init__(self, store_path: Optional[str] = None):
        self._path = Path(store_path) if store_path else self.STORE_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._episodes: list[Episode] = []
        self._load()

    def _load(self):
        """Load episodes from disk."""
        if self._path.exists():
            try:
                with open(self._path) as f:
                    data = json.load(f)
                    for ep_data in data:
                        self._episodes.append(Episode(**ep_data))
                logger.info(f"Hippocampus loaded {len(self._episodes)} past episodes")
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Hippocampus load failed: {e}")

    def _save(self):
        """Persist episodes to disk."""
        with open(self._path, "w") as f:
            json.dump([asdict(ep) for ep in self._episodes], f, indent=2, default=str)

    def store(self, state: EngagementState, outcome: str = "interrupted",
              reflection: str = ""):
        """Store the current engagement as an episode."""
        episode = Episode(
            engagement_id=state.engagement_id,
            target_address=state.target_address,
            timestamp=time.time(),
            target_profile_snapshot=state.target.to_dict(),
            outcome=outcome,
            reflection=reflection,
        )
        self._episodes.append(episode)
        self._save()
        logger.info(f"Hippocampus stored episode {state.engagement_id} ({outcome})")

    def find_similar(self, state: EngagementState, min_similarity: float = 0.15) -> list[MatchResult]:
        """
        Find past episodes similar to the current engagement state.
        Uses weighted similarity scoring.
        """
        if not self._episodes:
            return []

        current_domain = state.target.domains.get("network")
        if not current_domain:
            return []

        current_affs = current_domain.affordances
        current_cons = current_domain.constraints

        matches = []
        for ep in self._episodes:
            snapshot = ep.target_profile_snapshot
            ep_domain = snapshot.get("domains", {}).get("network", {})
            ep_affs = set(ep_domain.get("affordances", []))
            ep_cons = set(ep_domain.get("constraints", []))

            score = self._weighted_similarity(current_affs, current_cons, ep_affs, ep_cons)
            if score >= min_similarity:
                # Find next technique suggestion (what came after similar state)
                suggested = self._find_next_technique(ep, current_affs, current_cons)
                matches.append(MatchResult(
                    episode=ep,
                    similarity=score,
                    suggested_next_technique=suggested,
                ))

        matches.sort(key=lambda m: m.similarity, reverse=True)
        return matches[:3]  # top 3 matches

    def _weighted_similarity(self, affs_a: set, cons_a: set,
                              affs_b: set, cons_b: set) -> float:
        """
        Weighted Jaccard that distinguishes constraints from affordances.
        
        Scoring:
        - affordance ∩ affordance → +1 each
        - constraint ∩ constraint → +1 each  
        - affordance ∩ constraint → -1 each (opposite state)
        - Items in only one set → 0
        """
        if not affs_a and not cons_a and not affs_b and not cons_b:
            return 0.0

        # Separate positive and negative matches
        pos_aff = len(affs_a & affs_b)
        pos_con = len(cons_a & cons_b)
        
        # Cross-domain negative matches (same string, opposite type)
        neg_aff_con = len(affs_a & cons_b)
        neg_con_aff = len(cons_a & affs_b)
        neg_total = neg_aff_con + neg_con_aff

        # Total unique items across both profiles
        total_unique = len(affs_a | cons_a | affs_b | cons_b)
        if total_unique == 0:
            return 0.0

        # Weighted score: positive matches add, negative matches subtract
        # Normalize by total unique items
        weighted_score = (pos_aff * 1.0 + pos_con * 1.0 - neg_total * 1.5) / total_unique
        
        # Clamp to [0, 1]
        return max(0.0, min(1.0, weighted_score))

    def _find_next_technique(self, episode: Episode,
                              current_affs: set, current_cons: set) -> Optional[str]:
        """
        Given a past episode and the current profile state,
        find what technique was executed next in the episode
        after a similar profile state was reached.
        
        Simplified for Lite: returns the first technique in the episode's
        sequence that hasn't already been attempted in the current engagement.
        """
        attempted_in_current = set()
        # We don't have access to current engagement's full sequence here
        # Instead, suggest the first technique from the matched episode
        for step in episode.sequence:
            tech = step.get("technique")
            if tech:
                return tech
        return None

    def get_recent_episodes(self, n: int = 5) -> list[Episode]:
        """Get the N most recent episodes."""
        return self._episodes[-n:]

    @property
    def episode_count(self) -> int:
        return len(self._episodes)


# Singleton
_hippocampus: Optional[Hippocampus] = None

def get_hippocampus() -> Hippocampus:
    global _hippocampus
    if _hippocampus is None:
        _hippocampus = Hippocampus()
    return _hippocampus
