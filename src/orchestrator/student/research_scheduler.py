"""
ResearchScheduler — Continuous learning loop for THE STUDENT.
Scans web for new CVEs, writeups, techniques. Ingests into KB.
Identifies knowledge gaps and queues research topics.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger("student.research")

RESEARCH_DB = os.path.join(os.path.dirname(__file__), "..", "data", "research.db")

# Real web sources for writeup ingestion
WRITEUP_FEEDS = {
    "the_hacker_news": "https://feeds.feedburner.com/TheHackersNews",
    "krebs": "https://krebsonsecurity.com/feed/",
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "portswigger_research": "https://portswigger.net/research/rss",
    "schneier": "https://www.schneier.com/feed/atom/",
}

# Vulnerability classification keywords for article decomposition
VULN_KEYWORDS = {
    "SQL Injection": ["sql injection", "sqli", "sqlmap", "blind sql", "time-based", "union select"],
    "SSRF": ["ssrf", "server-side request forgery", "server side request forgery", "metadata endpoint", "169.254.169.254"],
    "RCE": ["rce", "remote code execution", "command injection", "code execution", "shell", "reverse shell", "deserialization"],
    "XSS": ["xss", "cross-site scripting", "cross site scripting", "stored xss", "reflected xss"],
    "Authentication Bypass": ["auth bypass", "authentication bypass", "jwt", "session hijack", "login bypass", "oauth bypass"],
    "Privilege Escalation": ["privesc", "privilege escalation", "elevation", "local privilege", "lpe"],
    "File Inclusion": ["lfi", "rfi", "local file inclusion", "remote file inclusion", "path traversal"],
    "Broken Access Control": ["idor", "broken access control", "insecure direct object", "access control bypass"],
    "Cloud Security": ["aws", "azure", "gcp", "cloud", "s3 bucket", "iam", "cloudtrail"],
    "API Security": ["api key", "api token", "graphql introspection", "rest api", "api abuse"],
    "SSO/OAuth": ["sso", "oauth", "saml", "openid", "redirect_uri", "authorization code"],
    "Supply Chain": ["supply chain", "dependency confusion", "malicious package", "typ squatting"],
}


@dataclass
class ResearchSession:
    session_id: str = ""
    cves_found: int = 0
    writeups_found: int = 0
    techniques_extracted: int = 0
    gaps_identified: list[str] = field(default_factory=list)
    started: float = 0.0
    completed: float = 0.0


class ResearchScheduler:
    """
    Continuous research pipeline:
      - Scheduled CVE/writeup/trend scans from real web sources
      - Writeup decomposition into structured case studies
      - Web search for bug bounty writeups (HackerOne, PentesterLand)
      - Gap analysis (low-coverage technique classes)
      - Research topic queuing
    """

    def __init__(self, db_path: str = RESEARCH_DB):
        self.db_path = db_path
        self.research_queue: list[str] = []
        self.last_research: Optional[float] = None
        self._sessions: list[ResearchSession] = []
        self._http = httpx.AsyncClient(timeout=30, follow_redirects=True)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS research_sessions (
                    id TEXT PRIMARY KEY,
                    cves_found INTEGER DEFAULT 0,
                    writeups_found INTEGER DEFAULT 0,
                    techniques_extracted INTEGER DEFAULT 0,
                    gaps TEXT DEFAULT '[]',
                    started REAL NOT NULL,
                    completed REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ingested_writeups (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    source_url TEXT DEFAULT '',
                    source_name TEXT DEFAULT '',
                    vuln_class TEXT DEFAULT '',
                    target_stack TEXT DEFAULT '',
                    chain TEXT DEFAULT '[]',
                    key_takeaway TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    cve_refs TEXT DEFAULT '[]',
                    raw_summary TEXT DEFAULT '',
                    ingested_at REAL NOT NULL,
                    exported_to_kb INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS knowledge_gaps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    gap_description TEXT NOT NULL UNIQUE,
                    technique_class TEXT DEFAULT '',
                    severity TEXT DEFAULT 'medium',
                    queued_at REAL NOT NULL,
                    resolved_at REAL DEFAULT NULL
                );
            """)
            # Migration: add exported_to_kb for older databases
            try:
                conn.execute("ALTER TABLE ingested_writeups ADD COLUMN exported_to_kb INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass  # Column already exists

    async def run_research_cycle(self, hours_back: int = 48) -> ResearchSession:
        """
        Full research cycle: scan CVEs → fetch RSS feeds → decompose writeups → identify gaps.
        """
        session = ResearchSession(
            session_id=f"res_{int(time.time())}",
            started=time.time(),
        )
        logger.info("[Student/Research] Starting cycle (last %d hours)", hours_back)

        # Phase 1: Check for new CVEs with PoCs
        try:
            cve_count = await self._scan_cves(hours_back)
            session.cves_found = cve_count
            logger.info("[Student/Research] CVEs found: %d", cve_count)
        except Exception as e:
            logger.warning("[Student/Research] CVE scan failed: %s", e)

        # Phase 2: Fetch RSS feeds and decompose into writeups
        try:
            writeup_count = await self._ingest_writeups(hours_back)
            session.writeups_found = writeup_count
            logger.info("[Student/Research] Writeups ingested: %d", writeup_count)
        except Exception as e:
            logger.warning("[Student/Research] Writeup ingestion failed: %s", e)

        # Phase 3: Active web search for bug bounty writeups
        try:
            web_count = await self._research_web()
            session.writeups_found += web_count
            logger.info("[Student/Research] Web search writeups: %d", web_count)
        except Exception as e:
            logger.warning("[Student/Research] Web search failed: %s", e)

        # Phase 4: Identify knowledge gaps
        try:
            gaps = self._identify_gaps()
            session.gaps_identified = gaps
            self.research_queue.extend(gaps)
            logger.info("[Student/Research] Gaps: %d — %s", len(gaps), gaps[:3])
        except Exception as e:
            logger.warning("[Student/Research] Gap analysis failed: %s", e)

        session.completed = time.time()
        self.last_research = session.completed
        self._sessions.append(session)
        self._record_session(session)

        elapsed = session.completed - session.started
        logger.info(
            "[Student/Research] Cycle done: %d CVEs, %d writeups, %d gaps (%.1fs)",
            session.cves_found, session.writeups_found, len(session.gaps_identified), elapsed,
        )
        return session

    async def _scan_cves(self, hours_back: int) -> int:
        """Scan CVE sources via HarvesterEngine."""
        try:
            from orchestrator.harvester.harvester_engine import get_harvester
            engine = get_harvester()
            cycle = await engine.run_full_cycle()
            return cycle.techniques_extracted
        except ImportError:
            logger.warning("[Student/Research] HarvesterEngine not available, skipping CVE scan")
            return 0
        except Exception as e:
            logger.warning("[Student/Research] HarvesterEngine error: %s", e)
            return 0

    async def _ingest_writeups(self, hours_back: int) -> int:
        """
        Fetch real RSS feeds and decompose articles into structured case studies.
        
        Uses WebFeedPoller from the harvester for RSS ingestion, then decomposes
        each article into vulnerability class, target stack, chain steps, etc.
        """
        count = 0

        # Method 1: Use existing WebFeedPoller
        try:
            from orchestrator.harvester.web_feeds import WebFeedPoller
            poller = WebFeedPoller()
            feed_results = await poller.poll_all()

            # Get unprocessed articles
            articles = poller.get_unprocessed(limit=50)
            now = time.time()

            for article in articles:
                # Skip if already ingested
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT id FROM ingested_writeups WHERE id = ?", (article["id"],)
                    ).fetchone()
                    if existing:
                        continue

                # Decompose article into structured case study
                decomposed = self._decompose_article(article)
                if decomposed:
                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute(
                            """INSERT OR IGNORE INTO ingested_writeups
                               (id, title, source_url, source_name, vuln_class, target_stack,
                                chain, key_takeaway, tags, cve_refs, raw_summary, ingested_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                decomposed["id"],
                                decomposed["title"],
                                decomposed["source_url"],
                                decomposed.get("source_name", "rss"),
                                decomposed["vuln_class"],
                                json.dumps(decomposed["target_stack"]),
                                json.dumps(decomposed["chain"]),
                                decomposed["key_takeaway"],
                                json.dumps(decomposed["tags"]),
                                json.dumps(decomposed["cve_refs"]),
                                decomposed["summary"][:1000],
                                now,
                            ),
                        )
                        count += 1

                # Mark article as processed in the feed poller DB
                poller.mark_processed([article["id"]])

        except ImportError:
            logger.warning("[Student/Research] WebFeedPoller not available, trying direct RSS fetch")
        except Exception as e:
            logger.warning("[Student/Research] WebFeedPoller error: %s", e)

        # Method 2: Direct RSS fetch for writeup-specific sources
        try:
            direct_count = await self._fetch_rss_direct(hours_back)
            count += direct_count
        except Exception as e:
            logger.warning("[Student/Research] Direct RSS fetch error: %s", e)

        return count

    async def _fetch_rss_direct(self, hours_back: int) -> int:
        """Fetch RSS feeds directly for writeup-specific sources not covered by WebFeedPoller."""
        count = 0
        cutoff = time.time() - (hours_back * 3600)

        for source_name, feed_url in WRITEUP_FEEDS.items():
            try:
                resp = await self._http.get(feed_url)
                resp.raise_for_status()
                text = resp.text
            except Exception as e:
                logger.debug("[Student/Research] RSS fetch failed for %s: %s", source_name, e)
                continue

            # Parse RSS/Atom items
            items = re.findall(r"<item>(.*?)</item>", text, re.DOTALL)
            if not items:
                items = re.findall(r"<entry>(.*?)</entry>", text, re.DOTALL)

            now = time.time()
            for item in items:
                # Extract fields
                title = self._extract_tag(item, "title")
                link = self._extract_tag(item, "link")
                if not link:
                    link_match = re.search(r'<link[^>]*href="([^"]+)"', item)
                    if link_match:
                        link = link_match.group(1)
                pub_date = self._extract_tag(item, "pubDate") or self._extract_tag(item, "published") or ""
                description = self._extract_tag(item, "description") or self._extract_tag(item, "summary") or ""
                description = re.sub(r"<[^>]+>", "", description)[:3000]
                content = self._extract_tag(item, "content:encoded") or description
                content = re.sub(r"<[^>]+>", "", content)[:5000]

                full_text = f"{title} {description} {content}"

                # Generate ID
                article_id = hashlib.sha256(f"{source_name}:{link}:{title}".encode()).hexdigest()[:16]

                # Check not already ingested
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT id FROM ingested_writeups WHERE id = ?", (article_id,)
                    ).fetchone()
                    if existing:
                        continue

                # Decompose into case study
                decomposed = self._decompose_article({
                    "id": article_id,
                    "title": title or "Untitled",
                    "url": link or "",
                    "summary": description,
                    "content": content,
                    "cve_refs": re.findall(r"CVE-\d{4}-\d{4,}", full_text, re.IGNORECASE),
                    "source": source_name,
                })

                if decomposed:
                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute(
                            """INSERT OR IGNORE INTO ingested_writeups
                               (id, title, source_url, source_name, vuln_class, target_stack,
                                chain, key_takeaway, tags, cve_refs, raw_summary, ingested_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                decomposed["id"],
                                decomposed["title"][:500],
                                decomposed["source_url"],
                                source_name,
                                decomposed["vuln_class"],
                                json.dumps(decomposed["target_stack"]),
                                json.dumps(decomposed["chain"]),
                                decomposed["key_takeaway"],
                                json.dumps(decomposed["tags"]),
                                json.dumps(decomposed["cve_refs"]),
                                decomposed["summary"][:1000],
                                now,
                            ),
                        )
                        count += 1

        return count

    def _decompose_article(self, article: dict) -> Optional[dict]:
        """
        Decompose a news article/writeup into a structured case study.
        
        Extracts:
          - Vulnerability class (from keyword matching on title + content)
          - Target stack (tech keywords found in text)
          - Attack chain steps (sentences describing exploit flow)
          - Key takeaway (most informative sentence)
          - Tags (vuln class, CVE refs, techniques)
        """
        title = article.get("title", "")
        content = article.get("content", "")
        summary = article.get("summary", "")
        full_text = f"{title} {summary} {content}".lower()

        # 1. Identify vulnerability class via keyword matching
        vuln_class = "General Security"
        best_score = 0
        for vclass, keywords in VULN_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw.lower() in full_text)
            if score > best_score:
                best_score = score
                vuln_class = vclass

        # 2. Extract target stack components
        tech_keywords = [
            "nginx", "apache", "iis", "django", "flask", "rails", "nextjs",
            "react", "angular", "vue", "nodejs", "php", "python", "java",
            "ruby", "go", "rust", "mysql", "postgresql", "mongodb", "mssql",
            "redis", "elasticsearch", "kubernetes", "docker", "aws", "azure",
            "gcp", "cloudflare", "wordpress", "joomla", "drupal",
            "active directory", "windows", "linux", "macos",
            "graphql", "rest", "soap", "jwt", "oauth", "saml",
        ]
        target_stack = []
        for tech in tech_keywords:
            if tech.lower() in full_text:
                target_stack.append(tech)

        # 3. Extract CVE references
        cve_refs = article.get("cve_refs", [])
        if not cve_refs:
            cve_refs = re.findall(r"CVE-\d{4}-\d{4,}", full_text, re.IGNORECASE)
        cve_refs = list(set(cve_refs))[:10]

        # 4. Decompose attack chain from text
        chain = self._extract_chain(full_text, title)

        # 5. Extract key takeaway (most informative sentence)
        takeaway = self._extract_takeaway(title, summary, content)

        # 6. Build tags
        tags = [f"#{vuln_class.lower().replace(' ', '_')}"]
        for tech in target_stack[:5]:
            tags.append(f"#{tech.lower()}")
        for cve in cve_refs[:3]:
            tags.append(f"#{cve.lower()}")

        return {
            "id": article.get("id", hashlib.sha256(full_text.encode()).hexdigest()[:16]),
            "title": (title or "Untitled")[:500],
            "source_url": article.get("url", article.get("source_url", "")),
            "source_name": article.get("source", article.get("source_name", "web")),
            "vuln_class": vuln_class,
            "target_stack": target_stack,
            "chain": chain,
            "key_takeaway": takeaway,
            "tags": tags,
            "cve_refs": cve_refs,
            "summary": (summary or content)[:2000],
        }

    def _extract_chain(self, full_text: str, title: str) -> list[str]:
        """
        Extract attack chain steps from article text.
        Looks for sequential exploit descriptions.
        """
        chain = []

        # Look for chain indicators in the text
        chain_indicators = [
            r"(?:step|stage|phase)\s*(\d+)[:\s]+([^.]*\.)",
            r"(?:then|next|after that|subsequently|following that)\s+([^.]*\.)",
            r"(?:chaining|chain|combine|combining)\s+([^.]*\.)",
            r"(?:leveraging|using|via)\s+([^.]*to[^.]*\.)",
            r"(?:exploit|vulnerability|weakness)\s+([^.]*lead(?:s|ing)[^.]*\.)",
            r"(?:access|obtain|extract|exfiltrate)\s+([^.]*\.)",
        ]

        for pattern in chain_indicators:
            matches = re.findall(pattern, full_text, re.IGNORECASE)
            for m in matches:
                if isinstance(m, tuple):
                    step_text = m[1].strip()
                else:
                    step_text = m.strip()
                if len(step_text) > 10 and step_text not in chain:
                    chain.append(step_text[:200])

        # If no structured chain found, extract key sentences
        if not chain:
            sentences = re.split(r'[.!?]+', full_text)
            key_sentences = []
            for s in sentences:
                s = s.strip()
                if not s:
                    continue
                # Score sentence by security relevance
                score = 0
                for kw in ["vulnerability", "exploit", "attack", "bypass", "injection",
                            "disclose", "access", "credential", "shell", "remote"]:
                    if kw in s.lower():
                        score += 1
                if score >= 2 and len(s) > 20:
                    key_sentences.append(s[:200])

            chain = key_sentences[:5]

        return chain

    def _extract_takeaway(self, title: str, summary: str, content: str) -> str:
        """Extract the most informative takeaway from the article."""
        # Title is often the best takeaway
        if title and len(title) > 10:
            return title[:300]

        # Fall back to first informative sentence
        for text in [summary, content]:
            sentences = re.split(r'[.!?]+', text)
            for s in sentences:
                s = s.strip()
                if any(kw in s.lower() for kw in ["found", "discovered", "identified",
                                                     "vulnerable", "bypass", "exploit",
                                                     "critical", "disclose", "patch"]):
                    if len(s) > 15:
                        return s[:300]

        # Last resort
        return (summary or content)[:300]

    def _extract_tag(self, text: str, tag: str) -> str:
        """Extract XML/HTML tag content."""
        m = re.search(f"<{tag}[^>]*>(.*?)</{tag}>", text, re.DOTALL)
        return m.group(1).strip() if m else ""

    async def _research_web(self) -> int:
        """
        Active web research: search for bug bounty writeups and technique-focused content.
        Uses direct HTTP fetches to known writeup sources.
        """
        count = 0
        now = time.time()

        # Target writeup-specific URLs for bug bounty content
        research_urls = [
            # HackerOne Hacktivity
            {"url": "https://hackerone.com/hacktivity?sort_type=latest&page=1&filter=type%3Apublic",
             "source": "hackerone_hacktivity"},
            # PentesterLand writeups
            {"url": "https://pentester.land/writeups/",
             "source": "pentesterland"},
            # Latest exploit writeups
            {"url": "https://www.exploit-db.com/search?date=2026",
             "source": "exploit_db"},
        ]

        for entry in research_urls:
            try:
                resp = await self._http.get(entry["url"], headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                })
                if resp.status_code != 200:
                    continue

                html = resp.text

                # Extract article links from HTML
                # Look for common writeup patterns in the HTML
                article_links = re.findall(
                    r'<a[^>]*href="([^"]*)"[^>]*>([^<]{20,200})</a>',
                    html
                )

                for href, link_text in article_links[:20]:
                    # Filter for likely writeup content
                    if not any(kw in href.lower() + link_text.lower()
                               for kw in ["writeup", "cve", "exploit", "bug", "vuln",
                                          "hack", "security", "breach", "poc"]):
                        continue

                    url = href if href.startswith("http") else f"https://hackerone.com{href}"
                    article_id = hashlib.sha256(f"{entry['source']}:{url}".encode()).hexdigest()[:16]

                    with sqlite3.connect(self.db_path) as conn:
                        existing = conn.execute(
                            "SELECT id FROM ingested_writeups WHERE id = ?", (article_id,)
                        ).fetchone()
                        if existing:
                            continue

                    decomposed = self._decompose_article({
                        "id": article_id,
                        "title": link_text.strip(),
                        "url": url,
                        "summary": link_text.strip(),
                        "content": "",
                        "cve_refs": re.findall(r"CVE-\d{4}-\d{4,}", href + link_text, re.IGNORECASE),
                        "source": entry["source"],
                    })

                    if decomposed:
                        with sqlite3.connect(self.db_path) as conn:
                            conn.execute(
                                """INSERT OR IGNORE INTO ingested_writeups
                                   (id, title, source_url, source_name, vuln_class, target_stack,
                                    chain, key_takeaway, tags, cve_refs, raw_summary, ingested_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (
                                    decomposed["id"],
                                    decomposed["title"][:500],
                                    decomposed["source_url"],
                                    entry["source"],
                                    decomposed["vuln_class"],
                                    json.dumps(decomposed["target_stack"]),
                                    json.dumps(decomposed["chain"]),
                                    decomposed["key_takeaway"],
                                    json.dumps(decomposed["tags"]),
                                    json.dumps(decomposed["cve_refs"]),
                                    decomposed["summary"][:1000],
                                    now,
                                ),
                            )
                            count += 1

            except Exception as e:
                logger.debug("[Student/Research] Web search error for %s: %s", entry["source"], e)
                continue

        logger.info("[Student/Research] Web research: %d writeups ingested from direct sources", count)
        return count

    async def search_writeups(self, query: str, limit: int = 10) -> list[dict]:
        """
        Search ingested writeups by keyword.
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT id, title, source_url, source_name, vuln_class, target_stack,
                          chain, key_takeaway, tags, cve_refs, ingested_at
                   FROM ingested_writeups
                   WHERE title LIKE ? OR vuln_class LIKE ? OR tags LIKE ? OR raw_summary LIKE ?
                   ORDER BY ingested_at DESC
                   LIMIT ?""",
                (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit),
            ).fetchall()
            return [
                {
                    "id": r[0], "title": r[1], "source_url": r[2],
                    "source_name": r[3], "vuln_class": r[4],
                    "target_stack": json.loads(r[5]) if r[5] else [],
                    "chain": json.loads(r[6]) if r[6] else [],
                    "key_takeaway": r[7],
                    "tags": json.loads(r[8]) if r[8] else [],
                    "cve_refs": json.loads(r[9]) if r[9] else [],
                    "ingested_at": r[10],
                }
                for r in rows
            ]

    def _identify_gaps(self) -> list[str]:
        gaps = []

        try:
            from orchestrator.growth_db import GrowthDB
            gdb = GrowthDB()

            findings = gdb.get_findings(limit=500)
            covered = set()
            for f in findings:
                desc = (f.get("description") or "") if isinstance(f, dict) else ""
                goal = (f.get("goal_type") or "") if isinstance(f, dict) else ""
                combined = (desc + " " + goal).lower()
                for cat, keywords in VULN_KEYWORDS.items():
                    if any(kw in combined for kw in keywords):
                        covered.add(cat)

            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT vuln_class, COUNT(*) FROM ingested_writeups GROUP BY vuln_class"
                ).fetchall()
                for row in rows:
                    covered.add(row[0])

                total_writeups = conn.execute(
                    "SELECT COUNT(*) FROM ingested_writeups"
                ).fetchone()[0]

            for cls in VULN_KEYWORDS:
                if cls not in covered:
                    gaps.append(f"Low coverage in {cls} — no techniques or writeups found")

            if total_writeups < 5:
                gaps.append("Very few case studies ingested — need more writeup sources")

            now = time.time()
            with sqlite3.connect(self.db_path) as conn:
                for gap in gaps:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO knowledge_gaps "
                            "(gap_description, technique_class, queued_at) VALUES (?, ?, ?)",
                            (gap[:500], gap.split(" in ")[-1].split(" (")[0]
                             if " in " in gap else "general", now),
                        )
                    except Exception:
                        pass

        except ImportError:
            logger.warning("[Student/Research] GrowthDB not available for gap analysis")
        except Exception as e:
            logger.warning("[Student/Research] Gap analysis error: %s", e)

        return gaps

    def _record_session(self, session: ResearchSession):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO research_sessions
                   (id, cves_found, writeups_found, techniques_extracted, gaps, started, completed)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    session.session_id,
                    session.cves_found,
                    session.writeups_found,
                    session.techniques_extracted,
                    json.dumps(session.gaps_identified),
                    session.started,
                    session.completed,
                ),
            )

    def get_recent_sessions(self, limit: int = 10) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM research_sessions ORDER BY completed DESC LIMIT ?", (limit,)
            ).fetchall()
            return [
                {
                    "id": r[0], "cves_found": r[1], "writeups_found": r[2],
                    "techniques_extracted": r[3],
                    "gaps": json.loads(r[4]) if r[4] else [],
                    "started": r[5], "completed": r[6],
                }
                for r in rows
            ]

    def get_pending_gaps(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM knowledge_gaps WHERE resolved_at IS NULL ORDER BY queued_at DESC"
            ).fetchall()
            return [
                {
                    "id": r[0], "description": r[1],
                    "technique_class": r[2], "severity": r[3],
                    "queued_at": r[4],
                }
                for r in rows
            ]

    def get_ingested_writeups(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM ingested_writeups ORDER BY ingested_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [
                {
                    "id": r[0], "title": r[1], "source_url": r[2],
                    "source_name": r[3], "vuln_class": r[4],
                    "target_stack": json.loads(r[5]) if r[5] else [],
                    "chain": json.loads(r[6]) if r[6] else [],
                    "key_takeaway": r[7],
                    "tags": json.loads(r[8]) if r[8] else [],
                    "cve_refs": json.loads(r[9]) if r[9] else [],
                    "ingested_at": r[10],
                }
                for r in rows
            ]

    # ── StudentKB Integration ────────────────────────────────

    def extract_techniques_for_kb(self, limit: int = 50) -> list[dict]:
        """
        Extract unexported writeups as StudentKB-compatible technique records.

        Maps ingested_writeups columns to REQUIRED_FIELDS schema:
          vuln_class      → "class"
          target_stack    → "target_profiles"
          chain           → "detection" (chain steps as detection guidance)
          cve_refs        → "key_references"
          source_name     → "source" (prefixed "research_scheduler:")
          title + vuln_class → "technique_id" (hashed)
          title           → "name"
          ingested_at     → "learned" (ISO 8601)

        Returns:
            list[dict] ready for StudentKB.integrate()
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT id, title, source_url, source_name, vuln_class, target_stack,
                          chain, key_takeaway, tags, cve_refs, raw_summary, ingested_at
                   FROM ingested_writeups
                   WHERE exported_to_kb = 0
                   ORDER BY ingested_at DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()

        techniques = []
        for r in rows:
            (w_id, title, source_url, source_name, vuln_class,
             target_stack_json, chain_json, key_takeaway, tags_json,
             cve_refs_json, raw_summary, ingested_at) = r

            target_stack = json.loads(target_stack_json) if target_stack_json else []
            chain_steps = json.loads(chain_json) if chain_json else []
            cve_refs = json.loads(cve_refs_json) if cve_refs_json else []
            tags = json.loads(tags_json) if tags_json else []

            # Generate a stable technique_id from title + vuln_class
            technique_id = f"research_{hashlib.sha256(f'{source_name}:{title}:{vuln_class}'.encode()).hexdigest()[:12]}"

            # Build target_profiles from target_stack (concatenate tech stack)
            target_profiles = []
            if target_stack:
                target_profiles.append("+".join(target_stack[:5]))
            else:
                target_profiles.append("generic+webapp")

            # Use chain steps as detection guidance / technique description
            detection = chain_steps[:10] if chain_steps else []
            if key_takeaway and key_takeaway not in detection:
                detection.append(key_takeaway[:300])

            # Build key_references from CVE refs and source URL
            key_references = list(cve_refs)
            if source_url and source_url not in key_references:
                key_references.append(source_url)

            # Build subclass from vuln_class + first target_stack item
            subclass_parts = [vuln_class]
            if target_stack:
                subclass_parts.append(target_stack[0])
            subclass = " — ".join(subclass_parts) if len(subclass_parts) > 1 else vuln_class

            # Convert ingested_at (unix timestamp) to ISO 8601
            learned_iso = datetime.fromtimestamp(ingested_at, tz=timezone.utc).isoformat()

            technique = {
                "technique_id": technique_id,
                "name": (title or "Untitled Writeup")[:200],
                "class": vuln_class or "General Security",
                "subclass": subclass[:150],
                "confidence": 0.6,  # Moderate confidence — web-mined content
                "cvss_min": 5.0,    # Default when no CVSS available
                "target_profiles": target_profiles,
                "detection": detection,
                "chainable_with": [],  # Can be enhanced with chain analysis
                "source": f"research_scheduler:{source_name or 'web'}",
                "learned": learned_iso,
                "key_references": key_references,
                # Optional fields
                "tags": tags,
                "failure_reasons": [],
                "derived_from": w_id,
                "novel_chain": chain_steps[:5],
            }

            techniques.append(technique)

        return techniques

    def mark_exported_to_kb(self, technique_ids: list[str]) -> int:
        """
        Mark writeups as exported by matching derived_from (writeup id).
        Called after successful KB integration.

        Returns:
            Number of rows updated.
        """
        if not technique_ids:
            return 0
        with sqlite3.connect(self.db_path) as conn:
            placeholders = ",".join("?" for _ in technique_ids)
            conn.execute(
                f"UPDATE ingested_writeups SET exported_to_kb = 1 WHERE id IN ({placeholders})",
                technique_ids,
            )
            updated = conn.execute("SELECT changes()").fetchone()[0]
            conn.commit()
            return updated

    # ── Queued Research ──────────────────────────────────────

    async def _search_query(self, query: str) -> int:
        """
        Search the web for a specific research query and ingest results.
        Uses DuckDuckGo lite for zero-API search.

        Args:
            query: Search query string

        Returns:
            Number of writeups ingested
        """
        count = 0
        now = time.time()

        try:
            encoded = urllib.parse.quote(query)
            url = f"https://lite.duckduckgo.com/lite/?q={encoded}"

            resp = await self._http.get(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "text/html",
            })
            if resp.status_code != 200:
                logger.debug("[Student/Research] Search query failed (status %d): %s", resp.status_code, query)
                return 0

            html = resp.text

            # Extract result links from DuckDuckGo lite HTML
            # Pattern: <a rel="nofollow" href="URL">TITLE</a>
            results = re.findall(
                r'<a[^>]*href="(https?://[^"]+)"[^>]*>([^<]{15,200})</a>',
                html,
            )

            for href, link_text in results[:15]:
                # Skip ads and non-writeup content
                if any(skip in href.lower() for skip in
                       ["duckduckgo.com", "ads.", "sponsor", "amazon.", "youtube.com"]):
                    continue
                if not any(kw in href.lower() + link_text.lower()
                           for kw in ["writeup", "cve", "exploit", "vulnerability",
                                      "security", "poc", "walkthrough", "bug"]):
                    continue

                article_id = hashlib.sha256(f"search:{href}".encode()).hexdigest()[:16]

                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT id FROM ingested_writeups WHERE id = ?", (article_id,)
                    ).fetchone()
                    if existing:
                        continue

                decomposed = self._decompose_article({
                    "id": article_id,
                    "title": link_text.strip(),
                    "url": href,
                    "summary": link_text.strip(),
                    "content": "",
                    "cve_refs": re.findall(r"CVE-\d{4}-\d{4,}", href + link_text, re.IGNORECASE),
                    "source": "web_search",
                })

                if decomposed:
                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute(
                            """INSERT OR IGNORE INTO ingested_writeups
                               (id, title, source_url, source_name, vuln_class, target_stack,
                                chain, key_takeaway, tags, cve_refs, raw_summary, ingested_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                decomposed["id"],
                                decomposed["title"][:500],
                                decomposed["source_url"],
                                "web_search",
                                decomposed["vuln_class"],
                                json.dumps(decomposed["target_stack"]),
                                json.dumps(decomposed["chain"]),
                                decomposed["key_takeaway"],
                                json.dumps(decomposed["tags"]),
                                json.dumps(decomposed["cve_refs"]),
                                decomposed["summary"][:1000],
                                now,
                            ),
                        )
                        count += 1

        except Exception as e:
            logger.warning("[Student/Research] Search query error '%s': %s", query[:60], e)

        return count

    async def run_queued_research(self, max_queries: int = 10) -> int:
        """
        Process research_queue by searching the web for each query.
        Called by KnowledgeBackgroundService between full cycles.

        Args:
            max_queries: Maximum number of queries to process (default 10)

        Returns:
            Number of writeups ingested from queued queries
        """
        total_ingested = 0
        processed = 0

        while self.research_queue and processed < max_queries:
            query = self.research_queue.pop(0)
            processed += 1
            logger.info("[Student/Research] Processing queued query: %s", query[:80])
            ingested = await self._search_query(query)
            total_ingested += ingested

        if processed > 0:
            logger.info(
                "[Student/Research] Queued research done: %d queries, %d writeups",
                processed,
                total_ingested,
            )

        return total_ingested

    async def close(self):
        await self._http.aclose()
