"""episode.py — Episode recorder preserving full reasoning trajectory.

Episodes are separate from metrics. Metrics summarize; episodes preserve
the detailed reasoning trace for future analysis and training.

Key design:
- One Episode per reasoning/action cycle
- Preserves candidate actions NOT selected (not just chosen action)
- Append-only: events.jsonl, episodes.jsonl written sequentially
- Never overwritten by later evaluation passes
"""

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


# ── Episode Schema v1 ─────────────────────────────────────────

@dataclass
class Episode:
    """A single reasoning/action cycle within a run.
    
    Preserves the complete decision trajectory including alternatives
    that were considered but not selected.
    """
    episode_id: str = ""
    run_id: str = ""
    sequence_number: int = 0
    timestamp: float = 0.0
    
    # ── State snapshot (before) ────────────────────────────────
    objective: str = ""
    evidence_available: list = field(default_factory=list)
    """Evidence IDs available at this decision point."""
    active_hypotheses: list = field(default_factory=list)
    """Hypothesis IDs and current statuses."""
    
    # ── Deliberation ───────────────────────────────────────────
    candidate_actions: list = field(default_factory=list)
    """All actions considered, with scores."""
    planner_scores: list = field(default_factory=list)
    """Planner scores for each candidate action."""
    selected_action: Optional[dict] = None
    """The action that was ultimately selected."""
    
    # ── Execution & Result ─────────────────────────────────────
    authorization_result: Optional[dict] = None
    execution_result: Optional[dict] = None
    
    # ── State updates (after) ──────────────────────────────────
    observations_created: list = field(default_factory=list)
    """Observation IDs created by this action."""
    evidence_created: list = field(default_factory=list)
    """Evidence IDs created by this action."""
    belief_updates: list = field(default_factory=list)
    """Hypothesis confidence changes or status changes."""
    world_updates: list = field(default_factory=list)
    """World model changes (entities, relationships)."""
    
    # ── State snapshot (after) ─────────────────────────────────
    state_after_ref: Optional[dict] = None
    """Reference to key state after execution."""
    objective_progress: Optional[float] = None
    """0.0 = no progress, 1.0 = objective complete."""
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp
        return d
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ── Episode Recorder ──────────────────────────────────────────

class EpisodeRecorder:
    """Append-only recorder for episodes in a run.
    
    Writes episodes as JSONL to arena/results/raw/<run_id>/episodes.jsonl.
    Also maintains in-memory list for analysis.
    """
    
    def __init__(self, run_id: str, output_dir: Optional[str] = None):
        self.run_id = run_id
        self.episodes: list[Episode] = []
        self.sequence_counter = 0
        self._output_dir = output_dir
        self._file_handle = None
    
    def record(self, 
               objective: str,
               evidence_available: list,
               active_hypotheses: list,
               candidate_actions: list,
               planner_scores: list,
               selected_action: Optional[dict],
               authorization_result: Optional[dict],
               execution_result: Optional[dict],
               observations_created: list,
               evidence_created: list,
               belief_updates: list,
               world_updates: list,
               state_after_ref: Optional[dict] = None,
               objective_progress: Optional[float] = None) -> Episode:
        """Record an episode for a single reasoning/action cycle."""
        ep = Episode(
            episode_id=f"ep_{self.run_id}_{self.sequence_counter:04d}",
            run_id=self.run_id,
            sequence_number=self.sequence_counter,
            timestamp=time.time(),
            objective=objective,
            evidence_available=evidence_available,
            active_hypotheses=active_hypotheses,
            candidate_actions=candidate_actions,
            planner_scores=planner_scores,
            selected_action=selected_action,
            authorization_result=authorization_result,
            execution_result=execution_result,
            observations_created=observations_created,
            evidence_created=evidence_created,
            belief_updates=belief_updates,
            world_updates=world_updates,
            state_after_ref=state_after_ref,
            objective_progress=objective_progress,
        )
        self.episodes.append(ep)
        self.sequence_counter += 1
        
        # Append to file if output_dir is configured
        if self._output_dir:
            self._append_to_file(ep)
        
        return ep
    
    def _append_to_file(self, episode: Episode) -> None:
        """Append episode as JSONL to output file."""
        out_dir = Path(self._output_dir) / "raw" / self.run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        ep_file = out_dir / "episodes.jsonl"
        with open(ep_file, "a") as f:
            f.write(episode.to_json() + "\n")
    
    def get_episode(self, sequence_number: int) -> Optional[Episode]:
        """Get an episode by sequence number."""
        if 0 <= sequence_number < len(self.episodes):
            return self.episodes[sequence_number]
        return None
    
    def get_last_episode(self) -> Optional[Episode]:
        """Get the most recently recorded episode."""
        if self.episodes:
            return self.episodes[-1]
        return None
    
    def to_dict_list(self) -> list[dict]:
        """Serialize all episodes to a list of dicts."""
        return [ep.to_dict() for ep in self.episodes]
    
    def close(self):
        """Close any open file handles."""
        self._file_handle = None


# ── Events Recorder (lightweight side-channel) ────────────────

class EventsRecorder:
    """Append-only recorder for low-level events during a run.
    
    Lighter weight than episodes — used for receipts, component traces,
    and raw observations. Written as JSONL.
    """
    
    def __init__(self, run_id: str, output_dir: Optional[str] = None):
        self.run_id = run_id
        self.events: list[dict] = []
        self._output_dir = output_dir
    
    def record_event(self, event_type: str, data: dict) -> dict:
        """Record a timestamped event."""
        event = {
            "event_id": f"evt_{self.run_id}_{len(self.events):06d}",
            "run_id": self.run_id,
            "event_type": event_type,
            "timestamp": time.time(),
            "data": data,
        }
        self.events.append(event)
        
        if self._output_dir:
            out_dir = Path(self._output_dir) / "raw" / self.run_id
            out_dir.mkdir(parents=True, exist_ok=True)
            evt_file = out_dir / "events.jsonl"
            with open(evt_file, "a") as f:
                f.write(json.dumps(event, default=str) + "\n")
        
        return event
    
    def get_events_by_type(self, event_type: str) -> list[dict]:
        """Filter events by type."""
        return [e for e in self.events if e["event_type"] == event_type]
