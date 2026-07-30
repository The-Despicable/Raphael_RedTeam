import subprocess, sys, json, time
from pathlib import Path
from typing import Optional

from ..skills_bridge import SkillsBridge
from ..brain.skill_indexer import SkillIndexer
from ..brain.neural_memory import store_skill_memory


class SkillAgent:
    def __init__(self):
        self.bridge = SkillsBridge()
        self.indexer = SkillIndexer()
        self._index_built = False

    def _ensure_index(self):
        if self._index_built:
            return
        all_skills = []
        for sd in self.bridge.subdomain_index.values():
            all_skills.extend(sd)
        if all_skills:
            self.indexer.build_index(all_skills)
        self._index_built = True

    def find_relevant_skills(self, query: str, top_k: int = 10) -> list[dict]:
        self._ensure_index()
        return self.indexer.search(query, top_k=top_k)

    def execute_skill(self, skill_name: str, targets: list[str],
                      target_name: str = "", script: str = "agent.py") -> dict:
        start = time.time()
        result = self.bridge.execute_skill(skill_name, targets, script=script)
        latency = time.time() - start

        if result and "error" not in result:
            meta = self.bridge._ensure_parsed(skill_name)
            store_skill_memory(
                skill_name=skill_name,
                target=target_name or targets[0] if targets else "",
                subdomain=meta.get("subdomain", ""),
                result_summary=json.dumps(result)[:500],
                success=True,
                latency=latency,
            )
            return result

        if result and "error" in result:
            store_skill_memory(
                skill_name=skill_name,
                target=target_name or targets[0] if targets else "",
                subdomain="unknown",
                result_summary=result["error"],
                success=False,
                latency=latency,
            )

        return result or {"error": f"skill {skill_name} not found or failed"}

    def debate_evidence(self, target: str, claim: str) -> list[dict]:
        self._ensure_index()
        relevant = self.indexer.search(f"{target} {claim}", top_k=8)
        evidence = []
        for s in relevant:
            skill_dir = Path(self.bridge.repo_path) / "skills" / s["name"] / "references"
            refs = []
            if skill_dir.exists():
                refs = [str(f.relative_to(self.bridge.repo_path)) for f in skill_dir.iterdir() if f.is_file()]
            evidence.append({
                "skill": s["name"],
                "relevance": s["score"],
                "subdomain": s["subdomain"],
                "references": refs[:5],
            })
        return evidence

    def compose_pipeline(self, target: str, mode: str = "full") -> list[str]:
        self._ensure_index()
        query_map = {
            "recon": "network scanning osint reconnaissance",
            "exploit": "exploitation vulnerability injection pentest",
            "postex": "post-exploitation lateral movement privilege escalation",
            "cleanup": "forensics cleanup anti-forensics log suppression",
            "full": "penetration test methodology reconnaissance exploitation cleanup",
        }
        query = query_map.get(mode, mode)
        results = self.indexer.search(query, top_k=15)
        return [s["name"] for s in results]

    def stats(self) -> dict:
        return {
            "bridge_total_skills": self.bridge.total_skills(),
            "indexer_stats": self.indexer.stats(),
            "bridged_subdomains": len(self.bridge.subdomain_index),
        }
