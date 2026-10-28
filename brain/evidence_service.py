"""Evidence and world-model service.

Wraps orchestrator.brain.evidence (EvidenceGraph, get/set_evidence_graph)
and orchestrator.brain.world (WorldModel) when available. Persists in the
local SQLite store regardless, so evidence survives restarts even when the
orchestrator isn't importable.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from .db import BrainDB

log = logging.getLogger("brain.evidence")


class EvidenceService:
    def __init__(self, db: BrainDB):
        self.db = db
        self._orch_graph: Optional[Any] = None
        self._world: Optional[Any] = None

    # ----------------------------------------------------------- orchestrator
    def _load_orchestrator(self) -> None:
        if self._orch_graph is not None:
            return
        try:
            from orchestrator.brain import evidence as _ev  # type: ignore
            from orchestrator.brain import world as _world  # type: ignore

            self._orch_graph = _ev.get_evidence_graph()
            self._world = _world.WorldModel()
            log.info("Loaded orchestrator evidence/world modules")
        except Exception as e:  # noqa: BLE001
            log.info("orchestrator evidence/world not available: %s", str(e)[:120])

    # --------------------------------------------------------------- ingest
    async def ingest(
        self,
        task_id: Optional[str],
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        merge: bool = True,
    ) -> Dict[str, Any]:
        """Persist nodes+edges. With merge=True (default), nodes whose node_id
        already exists for the same task scope are NOT re-inserted, so
        re-ingesting the same observation is idempotent instead of piling up
        duplicate rows."""
        nodes_added = 0
        edges_added = 0
        for n in nodes:
            node_id = n.get("id") or n.get("node_id") or f"n-{uuid.uuid4().hex[:8]}"
            node = {
                "task_id": task_id,
                "kind": n.get("kind", "unknown"),
                "node_id": node_id,
                "attributes": n.get("attributes", {}),
                "source": n.get("source"),
                "confidence": float(n.get("confidence", 1.0)),
            }
            if merge and await self.db.evidence_node_exists(node_id, task_id):
                continue
            await self.db.insert_evidence_node(node)
            nodes_added += 1
            if self._orch_graph is not None:
                try:
                    self._orch_graph.add_node(node["node_id"], node["kind"], node["attributes"])
                except Exception:
                    pass

        for e in edges:
            edge = {
                "task_id": task_id,
                "src": e["src"],
                "dst": e["dst"],
                "relation": e["relation"],
                "attributes": e.get("attributes", {}),
            }
            await self.db.insert_evidence_edge(edge)
            edges_added += 1
            if self._orch_graph is not None:
                try:
                    self._orch_graph.add_edge(edge["src"], edge["dst"], edge["relation"])
                except Exception:
                    pass

        totals = await self.db.count_evidence(task_id)
        return {
            "nodes_added": nodes_added,
            "edges_added": edges_added,
            "nodes_total": totals["nodes"],
            "edges_total": totals["edges"],
        }

    async def list_evidence(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        return await self.db.list_evidence(task_id)

    # ------------------------------------------------------------- world
    async def create_entity(
        self, type_: str, name: str, attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        node_id = f"{type_}-{uuid.uuid4().hex[:8]}"
        await self.db.insert_evidence_node(
            {
                "task_id": None,
                "kind": type_,
                "node_id": node_id,
                "attributes": {"name": name, **attributes},
                "source": "world-model",
                "confidence": 1.0,
            }
        )
        if self._orch_graph is not None:
            try:
                self._world.create_entity(type_, name, attributes)
            except Exception:
                pass
        return {
            "id": node_id,
            "type": type_,
            "name": name,
            "attributes": attributes,
        }

    async def create_relationship(
        self,
        src_type: str,
        src_name: str,
        dst_type: str,
        dst_name: str,
        relation: str,
        attributes: Dict[str, Any],
    ) -> Dict[str, Any]:
        src_id = f"{src_type}::{src_name}"
        dst_id = f"{dst_type}::{dst_name}"
        # Ensure both endpoints exist as evidence nodes (cheap idempotent insert).
        await self.db.insert_evidence_node(
            {
                "task_id": None,
                "kind": src_type,
                "node_id": src_id,
                "attributes": {"name": src_name},
                "source": "world-model",
                "confidence": 1.0,
            }
        )
        await self.db.insert_evidence_node(
            {
                "task_id": None,
                "kind": dst_type,
                "node_id": dst_id,
                "attributes": {"name": dst_name},
                "source": "world-model",
                "confidence": 1.0,
            }
        )
        await self.db.insert_evidence_edge(
            {
                "task_id": None,
                "src": src_id,
                "dst": dst_id,
                "relation": relation,
                "attributes": attributes,
            }
        )
        if self._orch_graph is not None:
            try:
                self._world.link_entities(src_type, src_name, dst_type, dst_name, relation)
            except Exception:
                pass
        return {"success": True, "detail": f"{src_id} -[{relation}]-> {dst_id}"}

    async def list_entities(self, type_filter: Optional[str] = None) -> Dict[str, Any]:
        data = await self.list_evidence()
        nodes = data["nodes"]
        if type_filter:
            nodes = [n for n in nodes if n.get("kind") == type_filter]
        return {
            "entities": [
                {
                    "id": n["node_id"],
                    "type": n.get("kind"),
                    "name": (n.get("attributes") or {}).get("name", n["node_id"]),
                    "attributes": n.get("attributes", {}),
                }
                for n in nodes
            ],
            "count": len(nodes),
        }
