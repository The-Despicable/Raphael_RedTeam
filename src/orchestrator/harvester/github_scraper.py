import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from typing import Optional

import httpx

logger = logging.getLogger("harvester.github")

SEARCH_QUERIES = [
    "CVE PoC exploit",
    "POC CVE-",
    "exploit CVE",
    "RCE exploit poc",
    "vulnerability poc",
    "CVE proof of concept",
    "exploit-db poc",
    "metasploit module",
    "CVE-2025 exploit",
    "CVE-2026 exploit",
    "ransomware poc",
    "loader malware source",
]

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "harvester.db")

GITHUB_API_BASE = "https://api.github.com"


class GitHubPoCScraper:
    def __init__(self, db_path: str = DB_PATH, token: Optional[str] = None):
        self.db_path = db_path
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        headers = {"User-Agent": "Raphael/2.0", "Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._http = httpx.AsyncClient(timeout=30, headers=headers)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS harvested_repos (
                    id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    html_url TEXT NOT NULL,
                    clone_url TEXT NOT NULL,
                    language TEXT DEFAULT '',
                    stars INTEGER DEFAULT 0,
                    topics TEXT DEFAULT '',
                    cve_refs TEXT DEFAULT '',
                    last_commit TEXT DEFAULT '',
                    first_seen REAL NOT NULL,
                    last_checked REAL NOT NULL,
                    analyzed INTEGER DEFAULT 0,
                    technique_extracted INTEGER DEFAULT 0
                );
            """)

    async def search_all(self) -> dict:
        results = {"total": 0, "new": 0, "errors": []}
        found_ids = set()

        for query in SEARCH_QUERIES:
            try:
                repos = await self._search_github(query)
                for repo in repos:
                    rid = repo["id"]
                    if rid not in found_ids:
                        found_ids.add(rid)
                        results["total"] += 1
                        if self._store_repo(repo):
                            results["new"] += 1
            except Exception as e:
                results["errors"].append(f"{query}: {e}")
                logger.warning(f"  GitHub search '{query}' failed: {e}")

        logger.info(f"  GitHub search: {results['total']} repos, {results['new']} new")
        return results

    async def _search_github(self, query: str) -> list[dict]:
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": 30,
        }
        resp = await self._http.get(f"{GITHUB_API_BASE}/search/repositories", params=params)
        resp.raise_for_status()
        data = resp.json()
        repos = []
        for item in data.get("items", []):
            cve_refs = self._extract_cves(item.get("name", "") + " " + (item.get("description", "") or ""))
            cve_refs += self._extract_cves_from_topics(item.get("topics", []))
            repos.append({
                "id": str(item["id"]),
                "full_name": item["full_name"],
                "description": (item.get("description") or "")[:500],
                "html_url": item["html_url"],
                "clone_url": item.get("clone_url", item["html_url"] + ".git"),
                "language": item.get("language") or "",
                "stars": item.get("stargazers_count", 0),
                "topics": ",".join(item.get("topics", [])),
                "cve_refs": json.dumps(list(set(cve_refs))),
                "last_commit": item.get("updated_at", ""),
            })
        return repos

    def _extract_cves(self, text: str) -> list[str]:
        if not text:
            return []
        return re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)

    def _extract_cves_from_topics(self, topics: list[str]) -> list[str]:
        refs = []
        for t in topics:
            if t.upper().startswith("CVE"):
                refs.append(t.upper())
        return refs

    def _store_repo(self, repo: dict) -> bool:
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM harvested_repos WHERE id = ?", (repo["id"],)
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE harvested_repos SET stars=?, last_commit=?, topics=?, cve_refs=?, last_checked=?
                       WHERE id=?""",
                    (repo["stars"], repo["last_commit"], repo["topics"],
                     repo["cve_refs"], now, repo["id"]),
                )
                return False
            else:
                conn.execute(
                    """INSERT INTO harvested_repos (id, full_name, description, html_url, clone_url,
                       language, stars, topics, cve_refs, last_commit, first_seen, last_checked)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (repo["id"], repo["full_name"], repo["description"], repo["html_url"],
                     repo["clone_url"], repo["language"], repo["stars"], repo["topics"],
                     repo["cve_refs"], repo["last_commit"], now, now),
                )
                return True

    def get_repos_for_analysis(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT id, full_name, description, html_url, clone_url, language, stars,
                   topics, cve_refs FROM harvested_repos
                   WHERE analyzed = 0 AND stars >= 3
                   ORDER BY stars DESC, last_checked DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [
                {
                    "id": r[0], "full_name": r[1], "description": r[2],
                    "html_url": r[3], "clone_url": r[4], "language": r[5],
                    "stars": r[6], "topics": r[7].split(",") if r[7] else [],
                    "cve_refs": json.loads(r[8]) if r[8] else [],
                }
                for r in rows
            ]

    def mark_analyzed(self, repo_ids: list[str]):
        if not repo_ids:
            return
        with sqlite3.connect(self.db_path) as conn:
            for rid in repo_ids:
                conn.execute("UPDATE harvested_repos SET analyzed = 1 WHERE id = ?", (rid,))

    def search_repos(self, cve_id: str = "", language: str = "") -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            q = "SELECT id, full_name, description, html_url, stars, language, cve_refs FROM harvested_repos WHERE 1=1"
            params = []
            if cve_id:
                q += " AND cve_refs LIKE ?"
                params.append(f"%{cve_id.upper()}%")
            if language:
                q += " AND language = ?"
                params.append(language)
            q += " ORDER BY stars DESC LIMIT 20"
            rows = conn.execute(q, params).fetchall()
            return [
                {
                    "id": r[0], "full_name": r[1], "description": r[2][:300],
                    "html_url": r[3], "stars": r[4], "language": r[5],
                    "cve_refs": json.loads(r[6]) if r[6] else [],
                }
                for r in rows
            ]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM harvested_repos").fetchone()[0]
            analyzed = conn.execute("SELECT COUNT(*) FROM harvested_repos WHERE analyzed = 1").fetchone()[0]
            by_lang = dict(conn.execute(
                "SELECT language, COUNT(*) FROM harvested_repos WHERE language != '' GROUP BY language ORDER BY COUNT(*) DESC"
            ).fetchall())
            return {
                "total": total,
                "analyzed": analyzed,
                "pending": total - analyzed,
                "by_language": by_lang,
            }

    async def close(self):
        await self._http.aclose()
