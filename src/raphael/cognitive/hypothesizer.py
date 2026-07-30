from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from raphael.cognitive.models import TargetModel, CapabilityModel, Affordance, Constraint, Unknown, AffordanceType

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    hypothesis_id: str
    question: str
    proposed_answer: str
    confidence: float
    reasoning: str
    test_techniques: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "heuristic"


class Hypothesizer:
    """Generates hypotheses to resolve unknowns using LLM + heuristic fallback."""
    
    def __init__(
        self,
        target_model: TargetModel,
        capability_model: CapabilityModel,
        llm_endpoint: Optional[str] = None,
        llm_api_key: Optional[str] = None,
    ):
        self.target_model = target_model
        self.capability_model = capability_model
        self.llm_endpoint = llm_endpoint or os.getenv("LLM_ENDPOINT", "http://localhost:3001/v1")
        self.llm_api_key = llm_api_key or os.getenv("LLM_API_KEY", "")
        self._heuristic_rules = self._load_heuristic_rules()
    
    async def generate_hypotheses(self, max_hypotheses: int = 5) -> List[Hypothesis]:
        """Generate hypotheses for all unresolved unknowns."""
        hypotheses = []
        
        for unknown in self.target_model.unknowns.values():
            unknown_hypotheses = await self._generate_for_unknown(unknown)
            hypotheses.extend(unknown_hypotheses)
        
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses[:max_hypotheses]
    
    async def _generate_for_unknown(self, unknown: Unknown) -> List[Hypothesis]:
        """Generate hypotheses for a single unknown."""
        llm_hypotheses = await self._try_llm(unknown)
        heuristic_hypotheses = self._generate_heuristic(unknown)
        
        all_hyp = llm_hypotheses + heuristic_hypotheses
        return all_hyp[:3]
    
    async def _try_llm(self, unknown: Unknown) -> List[Hypothesis]:
        """Attempt to generate hypothesis via LLM."""
        if not self.llm_api_key:
            return []
        
        try:
            import aiohttp
            
            prompt = self._build_llm_prompt(unknown)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.llm_endpoint}/chat/completions",
                    headers={"Authorization": f"Bearer {self.llm_api_key}"},
                    json={
                        "model": "nemotron-3-ultra",
                        "messages": [
                            {"role": "system", "content": "You are a penetration testing expert. Generate concise, testable hypotheses."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens": 500,
                    },
                    timeout=10,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content = data["choices"][0]["message"]["content"]
                        return self._parse_llm_response(content, unknown)
        except Exception as e:
            logger.debug(f"LLM hypothesis generation failed: {e}")
        
        return []
    
    def _build_llm_prompt(self, unknown: Unknown) -> str:
        """Build prompt for LLM."""
        context = {
            "target": self.target_model.metadata,
            "affordances": [f"{a.type.value}: {a.description}" for a in self.target_model.affordances.values()],
            "constraints": [f"{c.type.value}: {c.description}" for c in self.target_model.constraints.values()],
            "unknown": unknown.description,
        }
        
        return f"""Target Context: {json.dumps(context, indent=2)}

Unknown: {unknown.description}

Generate 1-3 testable hypotheses with confidence scores (0-1). Format as JSON:
{{
  "hypotheses": [
    {{"answer": "...", "confidence": 0.7, "reasoning": "...", "test_techniques": ["technique1", "technique2"]}}
  ]
}}"""
    
    def _parse_llm_response(self, content: str, unknown: Unknown) -> List[Hypothesis]:
        try:
            data = json.loads(content)
            hypotheses = []
            for h in data.get("hypotheses", []):
                hypotheses.append(Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    question=unknown.description,
                    proposed_answer=h.get("answer", ""),
                    confidence=h.get("confidence", 0.5),
                    reasoning=h.get("reasoning", ""),
                    test_techniques=h.get("test_techniques", []),
                    source="llm",
                ))
            return hypotheses
        except Exception:
            return []
    
    def _generate_heuristic(self, unknown: Unknown) -> List[Hypothesis]:
        """Heuristic fallback - rule-based hypothesis generation."""
        hypotheses = []
        
        category = "os"
        if "privilege" in unknown.description.lower():
            category = "privilege"
        elif "service" in unknown.description.lower():
            category = "service"
        elif "persist" in unknown.description.lower():
            category = "persistence"
        elif "egress" in unknown.description.lower() or "exfil" in unknown.description.lower():
            category = "egress"
        
        rules = {
            "os": [
                ("Target is Linux (most common server OS)", 0.7, "Linux dominates server market", ["os_fingerprint"]),
                ("Target is Windows (enterprise environments)", 0.3, "Common in enterprise", ["os_fingerprint", "smb_enum"]),
            ],
            "privilege": [
                ("Credentials are low-privilege user", 0.6, "Most compromised accounts are standard users", ["priv_check", "sudo_test"]),
                ("Credentials are admin/root", 0.3, "Possible but less common", ["priv_check", "sudo_test"]),
            ],
            "service": [
                ("Service runs as root/SYSTEM", 0.5, "Common misconfiguration", ["proc_check", "service_enum"]),
                ("Service runs as dedicated user", 0.4, "Better practice", ["proc_check", "service_enum"]),
            ],
            "persistence": [
                ("Cron/systemd available for persistence", 0.7, "Standard Linux persistence", ["cron_check", "systemd_enum"]),
                ("Scheduled tasks available", 0.6, "Standard Windows persistence", ["schtasks_enum", "registry_enum"]),
            ],
            "egress": [
                ("DNS exfiltration possible", 0.6, "DNS often allowed", ["dns_test"]),
                ("HTTP/HTTPS exfiltration possible", 0.5, "Web traffic usually allowed", ["http_test"]),
                ("All egress blocked", 0.2, "Highly restricted environment", ["egress_test"]),
            ],
        }
        
        if category in rules:
            for answer, conf, reasoning, techniques in rules[category]:
                hypotheses.append(Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    question=unknown.description,
                    proposed_answer=answer,
                    confidence=conf,
                    reasoning=reasoning,
                    test_techniques=techniques,
                    source="heuristic",
                ))
        
        return hypotheses
    
    def _load_heuristic_rules(self) -> Dict:
        return {}