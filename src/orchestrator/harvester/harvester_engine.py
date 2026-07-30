import asyncio
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from orchestrator.growth_db import GrowthDB
from orchestrator.harvester.cve_feeds import CVEFeedIngester
from orchestrator.harvester.github_scraper import GitHubPoCScraper
from orchestrator.harvester.technique_extractor import TechniqueExtractor
from orchestrator.harvester.confidence_scorer import ConfidenceScorer
from orchestrator.harvester.web_feeds import WebFeedPoller

logger = logging.getLogger("harvester.engine")

HARVESTER_DB = os.path.join(os.path.dirname(__file__), "..", "data", "harvester.db")


@dataclass
class HarvestCycle:
    cycle_id: str = ""
    target: str = ""
    cve_results: dict = field(default_factory=dict)
    repo_results: dict = field(default_factory=dict)
    feed_results: dict = field(default_factory=dict)
    techniques_extracted: int = 0
    techniques_integrated: int = 0
    errors: list = field(default_factory=list)
    started: float = 0.0
    completed: float = 0.0


class HarvesterEngine:
    def __init__(self, growth_db: Optional[GrowthDB] = None, db_path: str = HARVESTER_DB):
        self.db_path = db_path
        self.growth = growth_db or GrowthDB()
        self.cve_ingester = CVEFeedIngester(db_path)
        self.github_scraper = GitHubPoCScraper(db_path)
        self.feed_poller = WebFeedPoller(db_path)
        self.extractor = TechniqueExtractor(db_path)
        self.scorer = ConfidenceScorer()
        self._cycle_history: list[HarvCycle] = []
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS harvest_cycles (
                    id TEXT PRIMARY KEY,
                    cve_total INTEGER DEFAULT 0,
                    cve_new INTEGER DEFAULT 0,
                    repo_total INTEGER DEFAULT 0,
                    repo_new INTEGER DEFAULT 0,
                    feed_total INTEGER DEFAULT 0,
                    feed_new INTEGER DEFAULT 0,
                    techniques_extracted INTEGER DEFAULT 0,
                    techniques_integrated INTEGER DEFAULT 0,
                    errors TEXT DEFAULT '',
                    started REAL NOT NULL,
                    completed REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS integrated_techniques (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    technique_name TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL DEFAULT 'general',
                    description TEXT DEFAULT '',
                    mitre_id TEXT DEFAULT '',
                    commands TEXT DEFAULT '',
                    prerequisites TEXT DEFAULT '',
                    source_type TEXT DEFAULT '',
                    source_ref TEXT DEFAULT '',
                    confidence REAL DEFAULT 0.5,
                    success_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    last_used REAL DEFAULT 0,
                    created REAL NOT NULL,
                    UNIQUE(technique_name)
                );
            """)

    async def run_full_cycle(self, target: str = "") -> HarvestCycle:
        cycle = HarvestCycle(
            cycle_id=str(uuid.uuid4())[:12],
            target=target or "global",
            started=time.time(),
        )
        logger.info(f"  [Harvester] Cycle {cycle.cycle_id} — ingesting from web")

        cve_task = asyncio.create_task(self._ingest_cves())
        repo_task = asyncio.create_task(self._scrape_github())
        feed_task = asyncio.create_task(self._poll_feeds())
        extract_cve_task = asyncio.create_task(self._extract_from_pending_cves())
        extract_repo_task = asyncio.create_task(self._extract_from_new_repos())

        results = await asyncio.gather(
            cve_task, repo_task, feed_task, extract_cve_task, extract_repo_task,
            return_exceptions=True,
        )

        cycle.cve_results = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
        cycle.repo_results = results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])}
        cycle.feed_results = results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])}
        extract_cve_count = results[3] if not isinstance(results[3], Exception) else 0
        extract_repo_count = results[4] if not isinstance(results[4], Exception) else 0
        cycle.techniques_extracted = extract_cve_count + extract_repo_count

        integrated = await self._integrate_into_growthdb()
        cycle.techniques_integrated = integrated

        cycle.completed = time.time()
        self._record_cycle(cycle)
        self._cycle_history.append(cycle)

        elapsed = cycle.completed - cycle.started
        logger.info(
            f"  [Harvester] Cycle {cycle.cycle_id} done: "
            f"{cycle.techniques_extracted} extracted, {integrated} integrated ({elapsed:.1f}s)"
        )
        return cycle

    async def _ingest_cves(self) -> dict:
        return await self.cve_ingester.ingest_all()

    async def _scrape_github(self) -> dict:
        return await self.github_scraper.search_all()

    async def _poll_feeds(self) -> dict:
        return await self.feed_poller.poll_all()

    async def _extract_from_pending_cves(self) -> int:
        cves = self.cve_ingester.get_uningested(limit=30)
        count = 0
        for cve in cves:
            technique = self.extractor.extract_from_cve(cve)
            if technique:
                confidence = self.scorer.score_cve(cve)
                technique["confidence"] = confidence
                if self.extractor.store_technique(technique):
                    count += 1
        cve_ids = [c["id"] for c in cves]
        if cve_ids:
            self.cve_ingester.mark_ingested(cve_ids)
        logger.info(f"  Extracted {count} techniques from {len(cves)} CVEs")
        return count

    async def _extract_from_new_repos(self) -> int:
        repos = self.github_scraper.get_repos_for_analysis(limit=20)
        count = 0
        for repo in repos:
            technique = self.extractor.extract_from_repo(repo)
            if technique:
                confidence = self.scorer.score_repo(repo)
                technique["confidence"] = confidence
                if self.extractor.store_technique(technique):
                    count += 1
        repo_ids = [r["id"] for r in repos]
        if repo_ids:
            self.github_scraper.mark_analyzed(repo_ids)
        logger.info(f"  Extracted {count} techniques from {len(repos)} repos")
        return count

    async def _integrate_into_growthdb(self) -> int:
        techniques = self.extractor.get_techniques(min_confidence=0.3, limit=100)
        count = 0
        for tech in techniques:
            try:
                self.growth.record_technique_result(
                    technique_name=tech["technique_name"],
                    category=tech["category"],
                    success=True,
                    description=tech["description"][:200],
                )
                for mapping in tech.get("mitre_mapping", []):
                    if isinstance(mapping, dict) and "id" in mapping:
                        self.growth.record_knowledge_edge(
                            from_type="technique",
                            from_value=tech["technique_name"],
                            to_type="mitre_id",
                            to_value=mapping["id"],
                            weight=tech["confidence"],
                        )
                self._store_integrated(tech)
                count += 1
            except Exception as e:
                logger.debug(f"  Integration skip: {e}")
        logger.info(f"  Integrated {count} techniques into GrowthDB")
        return count

    def _store_integrated(self, tech: dict):
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR IGNORE INTO integrated_techniques
                   (technique_name, category, description, mitre_id, commands, prerequisites,
                    source_type, source_ref, confidence, created)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tech["technique_name"],
                    tech["category"],
                    tech["description"][:500],
                    json.dumps(tech.get("mitre_mapping", [])),
                    json.dumps(tech.get("commands", [])),
                    tech.get("prerequisites", ""),
                    tech.get("source_type", ""),
                    tech.get("source_id", ""),
                    tech["confidence"],
                    now,
                ),
            )

    def _record_cycle(self, cycle: HarvestCycle):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO harvest_cycles (id, cve_total, cve_new, repo_total, repo_new,
                   feed_total, feed_new, techniques_extracted, techniques_integrated, errors,
                   started, completed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cycle.cycle_id,
                    cycle.cve_results.get("nvd", {}).get("items", 0) +
                    cycle.cve_results.get("exploit_db", {}).get("items", 0) +
                    cycle.cve_results.get("packet_storm", {}).get("items", 0) +
                    cycle.cve_results.get("cisa_kev", {}).get("items", 0),
                    cycle.cve_results.get("nvd", {}).get("new", 0) +
                    cycle.cve_results.get("exploit_db", {}).get("new", 0) +
                    cycle.cve_results.get("packet_storm", {}).get("new", 0) +
                    cycle.cve_results.get("cisa_kev", {}).get("new", 0),
                    cycle.repo_results.get("total", 0),
                    cycle.repo_results.get("new", 0),
                    sum(f.get("articles", 0) for f in cycle.feed_results.values() if isinstance(f, dict)),
                    sum(f.get("new", 0) for f in cycle.feed_results.values() if isinstance(f, dict)),
                    cycle.techniques_extracted,
                    cycle.techniques_integrated,
                    json.dumps(cycle.errors),
                    cycle.started,
                    cycle.completed,
                ),
            )

    def search(self, query: str, source: str = "all") -> list[dict]:
        results = []
        if source in ("all", "cve", "technique"):
            cves = self.cve_ingester.search_cves(query)
            for c in cves:
                c["_source"] = "cve"
            results.extend(cves)
        if source in ("all", "technique"):
            techs = self.extractor.search_techniques(query)
            for t in techs:
                t["_source"] = "technique"
            results.extend(techs)
        if source in ("all", "repo"):
            repos = self.github_scraper.search_repos(cve_id=query)
            for r in repos:
                r["_source"] = "repo"
            results.extend(repos)
        return results

    def get_technique_for_target(self, target_os: str = "", services: list = None) -> list[dict]:
        services = services or []
        query_parts = [target_os] + services
        query = " ".join(query_parts)
        techs = self.extractor.search_techniques(query)
        cves = self.cve_ingester.search_cves(query, min_cvss=7.0)
        result = []
        for t in techs[:10]:
            result.append({**t, "_type": "technique"})
        for c in cves[:5]:
            result.append({**c, "_type": "cve"})
        return sorted(result, key=lambda x: x.get("confidence", x.get("cvss_score", 0)), reverse=True)

    def get_cycle_history(self, limit: int = 10) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM harvest_cycles ORDER BY completed DESC LIMIT ?", (limit,)
            ).fetchall()
            return [
                {
                    "id": r[0], "cve_total": r[1], "cve_new": r[2],
                    "repo_total": r[3], "repo_new": r[4],
                    "feed_total": r[5], "feed_new": r[6],
                    "techniques_extracted": r[7], "techniques_integrated": r[8],
                    "errors": json.loads(r[9]) if r[9] else [],
                    "started": r[10], "completed": r[11],
                }
                for r in rows
            ]

    def stats(self) -> dict:
        harvester = {}
        try:
            harvester["cve"] = self.cve_ingester.stats()
        except Exception:
            harvester["cve"] = {"error": "unavailable"}
        try:
            harvester["github"] = self.github_scraper.stats()
        except Exception:
            harvester["github"] = {"error": "unavailable"}
        try:
            harvester["feeds"] = self.feed_poller.stats()
        except Exception:
            harvester["feeds"] = {"error": "unavailable"}
        try:
            harvester["techniques"] = self.extractor.stats()
        except Exception:
            harvester["techniques"] = {"error": "unavailable"}
        try:
            cycles = self.get_cycle_history(limit=1)
            harvester["last_cycle"] = cycles[0] if cycles else None
        except Exception:
            harvester["last_cycle"] = None
        return {"harvester": harvester}

    async def run_continuous(self, interval: int = 3600, target: str = ""):
        logger.info(f"  [Harvester] Continuous mode — interval={interval}s")
        while True:
            try:
                await self.run_full_cycle(target=target)
            except Exception as e:
                logger.error(f"  [Harvester] Cycle failed: {e}")
            logger.info(f"  [Harvester] Next cycle in {interval}s")
            await asyncio.sleep(interval)

    async def close(self):
        await self.cve_ingester.close()
        await self.github_scraper.close()
        await self.feed_poller.close()
        await self.extractor.close()


_engine: Optional[HarvesterEngine] = None


def get_harvester() -> HarvesterEngine:
    global _engine
    if _engine is None:
        _engine = HarvesterEngine()
    return _engine
