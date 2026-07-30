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

logger = logging.getLogger("harvester.feeds")

FEED_URLS = {
    "the_hacker_news": "https://feeds.feedburner.com/TheHackersNews",
    "krebs": "https://krebsonsecurity.com/feed/",
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
}

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "harvester.db")


class WebFeedPoller:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._http = httpx.AsyncClient(timeout=30, follow_redirects=True)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS feed_articles (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    published TEXT DEFAULT '',
                    summary TEXT DEFAULT '',
                    content TEXT DEFAULT '',
                    cve_refs TEXT DEFAULT '',
                    techniques TEXT DEFAULT '',
                    first_seen REAL NOT NULL,
                    processed INTEGER DEFAULT 0
                );
            """)

    async def poll_all(self) -> dict:
        results = {}
        tasks = []
        for name, url in FEED_URLS.items():
            tasks.append(self._poll_feed(name, url))
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        for name, outcome in zip(FEED_URLS.keys(), outcomes):
            if isinstance(outcome, Exception):
                results[name] = {"error": str(outcome), "articles": 0, "new": 0}
            else:
                results[name] = outcome
        return results

    async def _poll_feed(self, name: str, url: str) -> dict:
        try:
            resp = await self._http.get(url)
            resp.raise_for_status()
            text = resp.text
        except Exception as e:
            logger.warning(f"  Feed {name}: fetch failed — {e}")
            return {"error": str(e), "articles": 0, "new": 0}

        articles = self._parse_rss(text, name)
        new_count = 0
        for article in articles:
            if self._store_article(article):
                new_count += 1

        logger.info(f"  Feed {name}: {len(articles)} articles, {new_count} new")
        return {"articles": len(articles), "new": new_count}

    def _parse_rss(self, text: str, source: str) -> list[dict]:
        articles = []
        items = re.findall(r"<item>(.*?)</item>", text, re.DOTALL)
        if not items:
            items = re.findall(r"<entry>(.*?)</entry>", text, re.DOTALL)

        for item in items:
            title = self._extract_tag(item, "title")
            url = self._extract_tag(item, "link")
            if not url:
                url_match = re.search(r'<link[^>]*href="([^"]+)"', item)
                if url_match:
                    url = url_match.group(1)
            published = self._extract_tag(item, "pubDate") or self._extract_tag(item, "published") or self._extract_tag(item, "updated")
            summary = self._extract_tag(item, "description") or self._extract_tag(item, "summary") or ""
            summary = re.sub(r"<[^>]+>", "", summary)[:2000]
            content = self._extract_tag(item, "content:encoded") or summary
            content = re.sub(r"<[^>]+>", "", content)[:5000]
            full_text = f"{title} {summary} {content}"
            cve_refs = re.findall(r"CVE-\d{4}-\d{4,}", full_text, re.IGNORECASE)
            techniques = self._extract_technique_refs(full_text)

            article_id = hashlib.sha256(f"{source}:{url}:{title}".encode()).hexdigest()[:16]
            articles.append({
                "id": article_id,
                "title": (title or "Untitled")[:500],
                "url": (url or "")[:1000],
                "published": (published or "")[:100],
                "summary": summary[:2000],
                "content": content[:5000],
                "cve_refs": json.dumps(list(set(cve_refs))),
                "techniques": json.dumps(list(set(techniques))),
            })
        return articles

    def _extract_tag(self, text: str, tag: str) -> str:
        m = re.search(f"<{tag}[^>]*>(.*?)</{tag}>", text, re.DOTALL)
        return m.group(1).strip() if m else ""

    def _extract_technique_refs(self, text: str) -> list[str]:
        refs = []
        patterns = [
            r"(?i)(ransomware|malware|trojan|rat|backdoor|dropper|loader)",
            r"(?i)(phishing|spear.?phish|whaling|smishing|vishing)",
            r"(?i)(0.?day|zero.?day|unpatched|unpatched)",
            r"(?i)(supply.?chain|watering.?hole|drive.?by)",
            r"(?i)(credential.?stuffing|password.?spray|brute.?force)",
            r"(?i)(dll.?side.?loading|dll.?hijack|process.?hollowing)",
            r"(?i)(living.?off.?the.?land|lolbin|lolbas)",
        ]
        for pattern in patterns:
            m = re.search(pattern, text)
            if m:
                refs.append(m.group(0).lower().replace(" ", "_")[:50])
        return refs[:5]

    def _store_article(self, article: dict) -> bool:
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM feed_articles WHERE id = ?", (article["id"],)
            ).fetchone()
            if existing:
                return False
            conn.execute(
                """INSERT INTO feed_articles (id, source, title, url, published, summary, content, cve_refs, techniques, first_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (article["id"], article.get("source", "rss"), article["title"],
                 article["url"], article["published"], article["summary"],
                 article["content"], article["cve_refs"], article["techniques"], now),
            )
            return True

    def get_unprocessed(self, limit: int = 30) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, source, title, url, published, summary, cve_refs, techniques, first_seen FROM feed_articles WHERE processed = 0 ORDER BY first_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                {
                    "id": r[0], "source": r[1], "title": r[2], "url": r[3],
                    "published": r[4], "summary": r[5][:500],
                    "cve_refs": json.loads(r[6]) if r[6] else [],
                    "techniques": json.loads(r[7]) if r[7] else [],
                    "first_seen": r[8],
                }
                for r in rows
            ]

    def mark_processed(self, article_ids: list[str]):
        if not article_ids:
            return
        with sqlite3.connect(self.db_path) as conn:
            for aid in article_ids:
                conn.execute("UPDATE feed_articles SET processed = 1 WHERE id = ?", (aid,))

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM feed_articles").fetchone()[0]
            processed = conn.execute("SELECT COUNT(*) FROM feed_articles WHERE processed = 1").fetchone()[0]
            with_cves = conn.execute(
                "SELECT COUNT(*) FROM feed_articles WHERE cve_refs != '' AND cve_refs != '[]'"
            ).fetchone()[0]
            return {
                "total": total,
                "processed": processed,
                "pending": total - processed,
                "with_cve_refs": with_cves,
            }

    async def close(self):
        await self._http.aclose()
