"""
Sci-Hub research module for THE STUDENT.
Fetches academic papers from arXiv cs.CR, downloads via Sci-Hub,
extracts text, decomposes into writeups stored in research.db.
"""
import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from typing import Optional

import httpx

logger = logging.getLogger("student.scihub")

SCI_HUB_DOMAINS = [
    "https://sci-hub.ru",
    "https://sci-hub.st",
    "https://sci-hub.se",
]

CLOAK_URL = "http://localhost:3401"
TOR_PROXY = "socks5h://localhost:9050"

ARXIV_API = "https://export.arxiv.org/api/query"

RESEARCH_DB = os.path.join(os.path.dirname(__file__), "..", "data", "research.db")

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


class SciHubResearcher:
    def __init__(self, db_path: str = RESEARCH_DB):
        self.db_path = db_path
        self._http = httpx.AsyncClient(
            timeout=45.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        self._ensure_db()

    def _ensure_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ingested_writeups (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    source_url TEXT,
                    source_name TEXT DEFAULT 'scihub',
                    vuln_class TEXT DEFAULT 'General',
                    target_stack TEXT DEFAULT '[]',
                    chain TEXT DEFAULT '[]',
                    key_takeaway TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    cve_refs TEXT DEFAULT '[]',
                    raw_summary TEXT DEFAULT '',
                    full_text TEXT DEFAULT '',
                    ingested_at REAL NOT NULL
                )
            """)
            # Migrate: add missing columns if table pre-exists without them
            for col in ('full_text', 'raw_summary', 'target_stack', 'chain', 'tags', 'cve_refs'):
                try:
                    conn.execute(f"ALTER TABLE ingested_writeups ADD COLUMN {col} TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass

    async def fetch_arxiv_papers(self, max_results: int = 100) -> list[dict]:
        """Fetch recent security papers from arXiv cs.CR."""
        params = {
            "search_query": "cat:cs.CR",
            "sortBy": "submittedDate",
            "sortOrder": "descending",
            "max_results": max_results,
        }
        logger.info("Fetching arXiv cs.CR papers...")
        resp = await self._http.get(ARXIV_API, params=params)
        resp.raise_for_status()

        import xml.etree.ElementTree as ET
        root = ET.fromstring(resp.text)
        ns = {
            'atom': 'http://www.w3.org/2005/Atom',
            'arxiv': 'http://arxiv.org/schemas/atom',
        }
        papers = []
        for entry in root.findall('atom:entry', ns):
            title_el = entry.find('atom:title', ns)
            summary_el = entry.find('atom:summary', ns)
            published_el = entry.find('atom:published', ns)
            id_el = entry.find('atom:id', ns)
            arxiv_id = ""
            if id_el is not None and id_el.text:
                arxiv_id = id_el.text.split('/')[-1] if '/' in id_el.text else id_el.text

            doi = ""
            pdf_url = ""
            for link in entry.findall('atom:link', ns):
                if link.get('title') == 'doi':
                    doi = link.get('href', '').replace('https://doi.org/', '')
                if link.get('title') == 'pdf':
                    pdf_url = link.get('href', '')

            authors = []
            for author in entry.findall('atom:author', ns):
                name_el = author.find('atom:name', ns)
                if name_el is not None and name_el.text:
                    authors.append(name_el.text)

            papers.append({
                'arxiv_id': arxiv_id,
                'title': (title_el.text or '').strip().replace('\n', ' ') if title_el is not None else '',
                'summary': (summary_el.text or '').strip().replace('\n', ' ') if summary_el is not None else '',
                'doi': doi,
                'pdf_url': pdf_url,
                'authors': authors,
                'published': (published_el.text or '') if published_el is not None else '',
            })

        logger.info("Fetched %d papers from arXiv", len(papers))
        return papers

    async def try_scihub(self, identifier: str) -> Optional[bytes]:
        """
        Try to download a paper from Sci-Hub by DOI or URL.
        Uses cloak service (Playwright browser) to handle Cloudflare,
        then downloads the PDF via Tor SOCKS5 proxy.
        """
        for domain in SCI_HUB_DOMAINS:
            try:
                url = f"{domain}/{identifier}"

                # Step 1: Browse via cloak to get the rendered HTML (handles Cloudflare)
                cloak_resp = await self._http.post(
                    f"{CLOAK_URL}/browse",
                    json={"url": url, "timeout": 45000},
                    timeout=50,
                )
                if cloak_resp.status_code != 200:
                    logger.debug("Cloak returned %s for %s", cloak_resp.status_code, domain)
                    continue

                cloak_data = cloak_resp.json()
                html = cloak_data.get("html", "")

                # Step 2: Extract PDF URL from the page
                pdf_url = None

                # Look for citation_pdf_url meta tag (standard Sci-Hub pattern)
                m = re.search(
                    r'<meta\s+name=["\']citation_pdf_url["\'][^>]*content=["\']([^"\']+)["\']',
                    html,
                )
                if m:
                    pdf_url = m.group(1)

                # Look for iframe with PDF
                if not pdf_url:
                    m = re.search(
                        r'<iframe[^>]*src=["\'](https?://[^"\']*\.pdf[^"\']*)["\']', html
                    )
                    if m:
                        pdf_url = m.group(1)

                # Look for embed
                if not pdf_url:
                    m = re.search(
                        r'<embed[^>]*src=["\'](https?://[^"\']*\.pdf[^"\']*)["\']', html
                    )
                    if m:
                        pdf_url = m.group(1)

                # Look for direct PDF links in the page
                if not pdf_url:
                    m = re.search(r'(https?://[^"\']+downloads[^"\']+\.pdf)', html)
                    if m:
                        pdf_url = m.group(1)

                if not pdf_url:
                    logger.debug("No PDF URL found in Sci-Hub page for %s", identifier[:40])
                    continue

                logger.debug("Found PDF URL: %s", pdf_url[:80])

                # Step 3: Download PDF through Tor proxy
                try:
                    transport = httpx.AsyncHTTPTransport(proxy=TOR_PROXY, retries=2)
                    async with httpx.AsyncClient(
                        transport=transport,
                        timeout=60,
                        follow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                    ) as tor_client:
                        pdf_resp = await tor_client.get(pdf_url)
                        if pdf_resp.status_code == 200 and b'%PDF' in pdf_resp.content[:10]:
                            logger.debug("PDF downloaded via Tor from %s", pdf_url[:60])
                            return pdf_resp.content
                except Exception as e:
                    logger.debug("Tor download failed for PDF %s: %s", pdf_url[:50], e)

                # Step 4 (fallback): Try direct HTTP download (some PDFs are on open servers)
                try:
                    pdf_resp = await self._http.get(pdf_url, timeout=30)
                    if pdf_resp.status_code == 200 and b'%PDF' in pdf_resp.content[:10]:
                        return pdf_resp.content
                except Exception:
                    pass

            except Exception as e:
                logger.debug("Sci-Hub %s failed for %s: %s", domain, identifier[:40], e)
                continue

        return None

    async def try_arxiv_direct(self, arxiv_id: str) -> Optional[bytes]:
        """Download PDF directly from arXiv (open access fallback)."""
        url = f"https://arxiv.org/pdf/{arxiv_id}"
        try:
            resp = await self._http.get(url, timeout=30.0)
            if resp.status_code == 200 and (b'%PDF' in resp.content[:10] or resp.content[:4] == b'%PDF'):
                logger.debug("Direct PDF from arXiv: %s", arxiv_id)
                return resp.content
        except Exception as e:
            logger.debug("arXiv direct download failed for %s: %s", arxiv_id, e)
        return None

    def extract_text(self, pdf_data: bytes) -> str:
        """Extract text from PDF using pdftotext."""
        tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
        try:
            tmp.write(pdf_data)
            tmp.flush()
            tmp.close()
            result = subprocess.run(
                ['pdftotext', tmp.name, '-'],
                capture_output=True, text=True, timeout=60,
            )
            return result.stdout.strip()
        except Exception as e:
            logger.warning("pdftotext failed: %s", e)
            return ""
        finally:
            try:
                os.unlink(tmp.name)
            except:
                pass

    def classify_vuln(self, text: str) -> list[str]:
        """Classify vulnerability types found in text."""
        text_lower = text.lower()
        found = []
        for vuln_class, keywords in VULN_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in text_lower:
                    found.append(vuln_class)
                    break
        return found if found else ["General Security"]

    def extract_techniques(self, text: str) -> list[str]:
        """Extract technique mentions from text."""
        techniques = []
        patterns = [
            r'(?:propose|present|introduce|develop|design|implement)\s+(?:a\s+|an\s+|novel\s+|new\s+|)?([^.]{10,100}\b(?:attack|defense|detection|framework|method|technique|approach|system|tool|algorithm)\b[^.]*\.)',
            r'\b(?:CVE-\d{4}-\d{4,})',
            r'\b(?:exploit|vulnerability|attack)\s+([^.]{10,150}\.(?:' + '|'.join([kw.replace(' ', '\\s+') for kw in ['sql injection', 'xss', 'ssrf', 'rce', 'buffer overflow', 'memory corruption', 'privilege escalation', 'side channel', 'fuzzing', 'reverse engineering', 'malware', 'ransomware', 'phishing']]) + r'))',
        ]
        for pat in patterns:
            found = re.findall(pat, text, re.IGNORECASE)
            if found:
                techniques.extend(found if isinstance(found[0], str) else [f[0] for f in found])
        return techniques[:10]

    def extract_tags(self, title: str, text: str, vuln_classes: list[str]) -> list[str]:
        tags = set()
        for vc in vuln_classes:
            tags.add(f"#{vc.lower().replace(' ', '_')}")
        if re.search(r'\b(machine learning|deep learning|neural network|llm|transformer|gpt)\b', text, re.IGNORECASE):
            tags.add("#ai_security")
        if re.search(r'\b(linux|windows|android|ios|macos|chrome|firefox)\b', text, re.IGNORECASE):
            tags.add("#platform_specific")
        if re.search(r'\b(cloud|aws|azure|gcp|kubernetes|docker)\b', text, re.IGNORECASE):
            tags.add("#cloud")
        if re.search(r'\b(cryptograph|encrypt|signature|hash|post-quantum)\b', text, re.IGNORECASE):
            tags.add("#cryptography")
        if re.search(r'\b(fuzzing|fuzz|symbolic execution|concolic)\b', text, re.IGNORECASE):
            tags.add("#automated_analysis")
        if re.search(r'\b(reverse engineer|binary analysis|disassembl|decompile)\b', text, re.IGNORECASE):
            tags.add("#reverse_engineering")
        if re.search(r'\b(malware|ransomware|botnet|trojan|backdoor)\b', text, re.IGNORECASE):
            tags.add("#malware")
        return sorted(tags)[:8]

    async def run_session(self, max_papers: int = 25) -> dict:
        """Full Sci-Hub research session."""
        papers = await self.fetch_arxiv_papers(max_results=100)
        report = {
            "papers_fetched": len(papers),
            "papers_with_doi": sum(1 for p in papers if p['doi']),
            "papers_attempted": 0,
            "pdfs_downloaded": 0,
            "pdfs_extracted": 0,
            "writeups_stored": 0,
            "failures": [],
            "paper_details": [],
        }

        for paper in papers[:max_papers]:
            report["papers_attempted"] += 1
            title_short = paper['title'][:80]

            # Build identifier list to try
            identifiers = []
            if paper['doi']:
                identifiers.append(paper['doi'])
            if paper['arxiv_id']:
                identifiers.append(f"https://arxiv.org/pdf/{paper['arxiv_id']}")
                identifiers.append(f"arxiv:{paper['arxiv_id']}")

            pdf_data = None
            used_id = ""
            for identifier in identifiers:
                pdf_data = await self.try_scihub(identifier)
                if pdf_data:
                    used_id = identifier[:50]
                    break

            if not pdf_data and paper.get('arxiv_id'):
                pdf_data = await self.try_arxiv_direct(paper['arxiv_id'])
                if pdf_data:
                    used_id = f"arxiv:{paper['arxiv_id']}"

            if not pdf_data:
                report["failures"].append({"title": title_short, "reason": "no pdf found"})
                continue

            report["pdfs_downloaded"] += 1

            text = self.extract_text(pdf_data)
            if not text or len(text) < 50:
                report["failures"].append({"title": title_short, "reason": "text extraction empty"})
                continue

            report["pdfs_extracted"] += 1

            # Classify
            vuln_classes = self.classify_vuln(text)
            techniques = self.extract_techniques(text)
            tags = self.extract_tags(paper['title'], text, vuln_classes)

            # Build decomposed writeup
            article_id = hashlib.sha256(f"scihub:{paper['arxiv_id']}".encode()).hexdigest()[:16]
            summary = paper['summary'][:500] if paper['summary'] else text[:500]
            key_takeaway = self._extract_takeaway(text, paper['title'])

            cve_refs = re.findall(r'CVE-\d{4}-\d{4,}', text + paper['title'], re.IGNORECASE)
            chain_steps = self._extract_chain(text)

            # Store in research.db
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO ingested_writeups
                       (id, title, source_url, source_name, vuln_class, target_stack,
                        chain, key_takeaway, tags, cve_refs, raw_summary, full_text, ingested_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        article_id,
                        paper['title'][:500],
                        paper.get('pdf_url', f"https://arxiv.org/abs/{paper.get('arxiv_id', '')}"),
                        "scihub",
                        vuln_classes[0],
                        json.dumps(list(set(re.findall(r'\b(aws|azure|gcp|linux|windows|android|ios|web|cloud|network|mobile|iot)\b', text, re.IGNORECASE)))),
                        json.dumps(chain_steps),
                        key_takeaway,
                        json.dumps(tags),
                        json.dumps(cve_refs),
                        paper['summary'][:1000] if paper['summary'] else text[:1000],
                        text[:2000],
                        time.time(),
                    ),
                )
            report["writeups_stored"] += 1
            report["paper_details"].append({
                "title": paper['title'],
                "arxiv_id": paper['arxiv_id'],
                "vuln_class": vuln_classes[0],
                "tags": tags,
                "cves": cve_refs,
            })

        await self._http.aclose()
        return report

    def _extract_takeaway(self, text: str, title: str) -> str:
        """Extract a one-sentence takeaway from the paper text."""
        # Look for abstract/conclusion sentences
        sentences = re.split(r'(?<=[.!?])\s+', text[:3000])
        key_sentences = [s for s in sentences if any(w in s.lower() for w in [
            'we propose', 'we present', 'we introduce', 'we develop',
            'our approach', 'our method', 'our framework', 'our system',
            'we show', 'we demonstrate', 'we find', 'our results',
            'this paper', 'this work', 'we contribute',
            'key finding', 'main contribution'
        ])]
        if key_sentences:
            return key_sentences[0][:300]
        # Fallback: first sentence of abstract
        if sentences:
            return sentences[0][:300]
        return title[:200]

    def _extract_chain(self, text: str) -> list[str]:
        """Extract attack chain or methodology steps from text."""
        steps = []
        patterns = [
            r'(?:first|step\s*1|stage\s*1|phase\s*1)[:\s]*([^.]{20,200}\.)',
            r'(?:second|step\s*2|stage\s*2|phase\s*2|then|next)[:\s]*([^.]{20,200}\.)',
            r'(?:third|step\s*3|stage\s*3|phase\s*3|finally)[:\s]*([^.]{20,200}\.)',
            r'(?:attack\s+chain|exploit\s+chain|kill\s+chain)[:\s]*([^.]{20,300}\.)',
            r'(?:methodology|approach|pipeline|framework)\s+(?:consists of|involves|comprises|has (?:the |)(?:following|these) steps?)[:\s]*([^.]{20,300}\.)',
        ]
        for pat in patterns:
            found = re.findall(pat, text, re.IGNORECASE)
            for f in found:
                step = f.strip()
                if step and len(step) > 20 and step not in steps:
                    steps.append(step)
        return steps[:5]
