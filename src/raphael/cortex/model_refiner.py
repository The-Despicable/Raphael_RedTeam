"""ModelRefiner — inward recon. Analyzes existing data at higher resolution with zero packets to target."""
from __future__ import annotations
import logging
import re
from typing import Optional
from raphael.models.engagement_state import EngagementState
from raphael.models.target_model import ConstraintDelta, TargetModel

logger = logging.getLogger("raphael.model_refiner")


class ModelRefiner:
    """
    When the planner is stuck, ModelRefiner re-examines existing data artifacts
    to extract additional affordances without sending any packets.
    
    This is the "inward recon" — mining existing data for hidden signal.
    """

    async def refine(self, state: EngagementState) -> Optional[ConstraintDelta]:
        """
        Analyze all existing data artifacts and return any new affordances found.
        Returns None if no new information can be extracted.
        """
        deltas = []
        domain = state.target.domains.get("network")

        if not domain:
            return None

        # Artifact 1: Port list — check for HTTP on non-standard ports
        port_list_aff = [a for a in domain.affordances if a.startswith("port_list:")]
        if port_list_aff:
            for aff in port_list_aff:
                ports_str = aff.split(":", 1)[1] if ":" in aff else ""
                for p in ports_str.split(","):
                    p = p.split("/")[0].strip()
                    if p.isdigit():
                        pnum = int(p)
                        # Non-standard HTTP ports
                        if pnum in (8000, 8080, 8888, 9000, 9090, 3000, 5000, 7443, 8443, 9443):
                            # Check if we already know about HTTP on this port
                            if f"port_{pnum}_open" in domain.affordances and f"http_service" not in domain.affordances:
                                # Check target model doesn't already have this port as http
                                already_http = any(
                                    a.startswith(f"port_{pnum}_") and "http" in a 
                                    for a in domain.affordances
                                )
                                if not already_http:
                                    deltas.append(ConstraintDelta(
                                        domain="network",
                                        new_affordances={f"port_{pnum}_http_inferred"},
                                        evidence=f"Inferred HTTP on non-standard port {pnum}",
                                    ))

        # Artifact 2: Look for patterns in how the target responded
        # (In future: analyze timing, error message versions, etc.)
        
        # Artifact 3: Check for domain name patterns in target address
        target = state.target_address
        if target and not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            # Domain name — check if we have whois data
            has_whois = any(a.startswith("whois_") for a in domain.affordances)
            if not has_whois:
                # We know it's a domain but haven't looked up whois
                pass  # whois technique will handle this

        # Merge all deltas
        if not deltas:
            logger.info("ModelRefiner: no additional signal found in existing data")
            return None

        merged = deltas[0]
        for d in deltas[1:]:
            merged.new_affordances.update(d.new_affordances)
            merged.new_constraints.update(d.new_constraints)
            merged.new_unknowns.update(d.new_unknowns)
        
        logger.info(f"ModelRefiner: extracted {len(merged.new_affordances)} new affordances from existing data")
        return merged


# Singleton
_refiner: Optional[ModelRefiner] = None

def get_refiner() -> ModelRefiner:
    global _refiner
    if _refiner is None:
        _refiner = ModelRefiner()
    return _refiner
