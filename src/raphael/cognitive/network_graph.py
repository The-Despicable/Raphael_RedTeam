from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from raphael.cognitive.models import TargetModel, Affordance, AffordanceType

logger = logging.getLogger(__name__)


@dataclass
class NetworkNode:
    node_id: str
    target_model: TargetModel
    tier: int = 0
    parent_id: Optional[str] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    compromise_status: str = "uncompromised"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: str
    technique_used: Optional[str] = None
    confidence: float = 1.0
    bidirectional: bool = False


class NetworkGraph:
    """Multi-target network graph for lateral movement planning."""
    
    def __init__(self):
        self.nodes: Dict[str, NetworkNode] = {}
        self.edges: Dict[str, NetworkEdge] = {}
        self._adjacency: Dict[str, Set[str]] = {}
        self._reverse_adjacency: Dict[str, Set[str]] = {}
    
    def add_node(self, target_model: TargetModel, tier: int = 0, parent_id: Optional[str] = None) -> str:
        node_id = target_model.id
        
        if node_id not in self.nodes:
            self.nodes[node_id] = NetworkNode(
                node_id=node_id,
                target_model=target_model,
                tier=tier,
                parent_id=parent_id,
            )
            self._adjacency[node_id] = set()
            self._reverse_adjacency[node_id] = set()
        
        return node_id
    
    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        technique_used: Optional[str] = None,
        confidence: float = 1.0,
        bidirectional: bool = False,
    ) -> str:
        edge_id = str(uuid.uuid4())
        edge = NetworkEdge(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            technique_used=technique_used,
            confidence=confidence,
            bidirectional=bidirectional,
        )
        
        self.edges[edge_id] = edge
        self._adjacency[source_id].add(target_id)
        self._reverse_adjacency[target_id].add(source_id)
        
        if bidirectional:
            self._adjacency[target_id].add(source_id)
            self._reverse_adjacency[source_id].add(target_id)
        
        return edge_id
    
    def get_lateral_targets(self, source_id: str, max_tier: int = 2) -> List[Dict]:
        """Get potential lateral movement targets from a compromised node."""
        targets = []
        visited = set()
        
        def dfs(node_id: str, current_tier: int):
            if current_tier > max_tier or node_id in visited:
                return
            visited.add(node_id)
            
            for neighbor in self._adjacency.get(node_id, set()):
                neighbor_node = self.nodes.get(neighbor)
                if neighbor_node and neighbor_node.compromise_status == "uncompromised":
                    targets.append({
                        "node_id": neighbor,
                        "target": self.nodes[neighbor].target_model,
                        "tier": current_tier + 1,
                        "edge_type": "lateral",
                    })
                dfs(neighbor, current_tier + 1)
        
        dfs(source_id, 0)
        return targets
    
    def get_attack_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find shortest attack path between nodes."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
        
        queue = [(source_id, [source_id])]
        visited = {source_id}
        
        while queue:
            current, path = queue.pop(0)
            if current == target_id:
                return path
            
            for neighbor in self._adjacency.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    def get_compromise_status(self, node_id: str) -> str:
        return self.nodes.get(node_id, NetworkNode(node_id="", target_model=None)).compromise_status
    
    def set_compromise_status(self, node_id: str, status: str) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].compromise_status = status
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "compromised": sum(1 for n in self.nodes.values() if n.compromise_status != "uncompromised"),
            "tiers": {
                tier: sum(1 for n in self.nodes.values() if n.tier == tier)
                for tier in set(n.tier for n in self.nodes.values())
            },
        }