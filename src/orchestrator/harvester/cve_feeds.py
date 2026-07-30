import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("harvester.cve")

FEED_SOURCES = {
    "nvd": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "type": "nvd_api",
        "enabled": True,
        "interval": 3600,
    },
    "exploit_db": {
        "url": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
        "type": "csv",
        "enabled": True,
        "interval": 7200,
    },
    "packet_storm": {
        "url": "https://packetstormsecurity.com/files/tags/exploit/page1/files.txt",
        "type": "txt",
        "enabled": True,
        "interval": 14400,
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "json",
        "enabled": True,
        "interval": 86400,
    },
}

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "harvester.db")


class CVEFeedIngester:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._http = httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "Raphael/2.0"},
        )

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS harvested_cves (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    cvss_score REAL DEFAULT 0.0,
                    affected_software TEXT DEFAULT '',
                    exploit_available INTEGER DEFAULT 0,
                    exploit_references TEXT DEFAULT '',
                    raw_data TEXT DEFAULT '',
                    first_seen REAL NOT NULL,
                    last_updated REAL NOT NULL,
                    ingested INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS feed_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    fetched_at REAL NOT NULL,
                    items_found INTEGER DEFAULT 0,
                    items_new INTEGER DEFAULT 0,
                    error TEXT DEFAULT ''
                );
            """)

    async def ingest_all(self) -> dict:
        results = {}
        tasks = []
        for name, cfg in FEED_SOURCES.items():
            if cfg.get("enabled", True):
                tasks.append(self._ingest_source(name, cfg))
        if tasks:
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for name, outcome in zip([n for n, c in FEED_SOURCES.items() if c.get("enabled", True)], outcomes):
                if isinstance(outcome, Exception):
                    results[name] = {"error": str(outcome), "items": 0, "new": 0}
                else:
                    results[name] = outcome
        return results

    async def _ingest_source(self, name: str, cfg: dict) -> dict:
        t0 = time.time()
        try:
            resp = await self._http.get(cfg["url"])
            resp.raise_for_status()
            text = resp.text
        except Exception as e:
            logger.warning(f"  Feed {name}: fetch failed — {e}")
            self._log_fetch(name, 0, 0, str(e))
            return {"error": str(e), "items": 0, "new": 0}

        parser = getattr(self, f"_parse_{cfg['type']}", None)
        if not parser:
            return {"error": f"no parser for type {cfg['type']}", "items": 0, "new": 0}

        try:
            items = parser(text, name)
        except Exception as e:
            logger.warning(f"  Feed {name}: parse failed — {e}")
            self._log_fetch(name, 0, 0, f"parse: {e}")
            return {"error": f"parse: {e}", "items": 0, "new": 0}

        new_count = self._store_items(items, name)
        elapsed = time.time() - t0
        self._log_fetch(name, len(items), new_count)
        logger.info(f"  Feed {name}: {len(items)} items, {new_count} new ({elapsed:.1f}s)")
        return {"items": len(items), "new": new_count, "elapsed": elapsed}

    def _parse_nvd_api(self, text: str, source: str) -> list[dict]:
        data = json.loads(text)
        items = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            descs = cve.get("descriptions", [])
            summary = next((d["value"] for d in descs if d.get("lang") == "en"), descs[0]["value"] if descs else "")
            metrics = cve.get("metrics", {})
            cvss = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            config = cve.get("configurations", [])
            software = []
            for cfg_node in config:
                for match in cfg_node.get("nodes", []):
                    for cpe in match.get("cpeMatch", []):
                        criteria = cpe.get("criteria", "")
                        if ":" in criteria:
                            parts = criteria.split(":")
                            if len(parts) > 4:
                                software.append(f"{parts[3]}:{parts[4]}")
            refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
            has_exploit = any("exploit" in r.lower() or "metasploit" in r.lower() or "github" in r.lower() for r in refs)
            items.append({
                "id": cve_id,
                "summary": summary[:1000],
                "cvss_score": cvss,
                "affected_software": ", ".join(sorted(set(software)))[:500],
                "exploit_available": 1 if has_exploit else 0,
                "exploit_references": json.dumps(refs[:20]),
                "raw_data": json.dumps(cve, default=str)[:2000],
            })
        return items

    def _parse_csv(self, text: str, source: str) -> list[dict]:
        items = []
        lines = text.strip().split("\n")
        if not lines:
            return items
        headers = [h.strip().strip('"') for h in lines[0].split(",")]
        for line in lines[1:]:
            if not line.strip():
                continue
            try:
                parts = list(csv_parse_line(line))
                row = dict(zip(headers, parts))
                cve_id = row.get("cve", row.get("id", "")).strip()
                if not cve_id:
                    continue
                desc = row.get("description", row.get("title", ""))
                refs = [row.get("url", ""), row.get("source_url", "")]
                refs = [r for r in refs if r]
                items.append({
                    "id": cve_id.upper() if cve_id.startswith("cve") else cve_id,
                    "summary": desc[:1000],
                    "cvss_score": float(row.get("cvss", row.get("score", 0)) or 0),
                    "affected_software": row.get("platform", row.get("type", ""))[:500],
                    "exploit_available": 1,
                    "exploit_references": json.dumps(refs),
                    "raw_data": json.dumps(row, default=str)[:2000],
                })
            except Exception:
                continue
        return items

    def _parse_json(self, text: str, source: str) -> list[dict]:
        data = json.loads(text)
        items = []
        if source == "cisa_kev":
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")
                if not cve_id:
                    continue
                items.append({
                    "id": cve_id,
                    "summary": vuln.get("shortDescription", "")[:1000],
                    "cvss_score": float(vuln.get("cvssScore", 0) or 0),
                    "affected_software": vuln.get("vendorProject", "")[:500],
                    "exploit_available": 1,
                    "exploit_references": json.dumps([
                        vuln.get("notes", ""),
                        vuln.get("dateAdded", ""),
                    ]),
                    "raw_data": json.dumps(vuln, default=str)[:2000],
                })
        return items

    def _parse_txt(self, text: str, source: str) -> list[dict]:
        items = []
        for line in text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            items.append({
                "id": hashlib.sha256(line.encode()).hexdigest()[:16],
                "summary": f"Packet Storm entry: {line}",
                "cvss_score": 0.0,
                "affected_software": "",
                "exploit_available": 1,
                "exploit_references": json.dumps([line]),
                "raw_data": line[:2000],
            })
        return items

    def _store_items(self, items: list[dict], source: str) -> int:
        new_count = 0
        with sqlite3.connect(self.db_path) as conn:
            for item in items:
                existing = conn.execute(
                    "SELECT id FROM harvested_cves WHERE id = ? AND source = ?",
                    (item["id"], source),
                ).fetchone()
                now = time.time()
                if existing:
                    conn.execute(
                        """UPDATE harvested_cves SET summary=?, cvss_score=?, affected_software=?,
                           exploit_available=?, exploit_references=?, last_updated=? WHERE id=? AND source=?""",
                        (item["summary"], item["cvss_score"], item["affected_software"],
                         item["exploit_available"], item["exploit_references"],
                         now, item["id"], source),
                    )
                else:
                    conn.execute(
                        """INSERT INTO harvested_cves (id, source, summary, cvss_score, affected_software,
                           exploit_available, exploit_references, raw_data, first_seen, last_updated, ingested)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                        (item["id"], source, item["summary"], item["cvss_score"],
                         item["affected_software"], item["exploit_available"],
                         item["exploit_references"], item["raw_data"],
                         now, now),
                    )
                    new_count += 1
        return new_count

    def _log_fetch(self, source: str, found: int, new: int, error: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO feed_log (source, fetched_at, items_found, items_new, error) VALUES (?, ?, ?, ?, ?)",
                (source, time.time(), found, new, error[:500] if error else ""),
            )

    def get_uningested(self, limit: int = 50) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT id, source, summary, cvss_score, affected_software, exploit_available,
                   exploit_references, raw_data FROM harvested_cves WHERE ingested = 0
                   ORDER BY cvss_score DESC, last_updated DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [
                {
                    "id": r[0], "source": r[1], "summary": r[2],
                    "cvss_score": r[3], "affected_software": r[4],
                    "exploit_available": bool(r[5]),
                    "exploit_references": json.loads(r[6]) if r[6] else [],
                    "raw_data": r[7],
                }
                for r in rows
            ]

    def mark_ingested(self, cve_ids: list[str]):
        with sqlite3.connect(self.db_path) as conn:
            for cid in cve_ids:
                conn.execute("UPDATE harvested_cves SET ingested = 1 WHERE id = ?", (cid,))

    def search_cves(self, query: str, min_cvss: float = 0.0) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT id, source, summary, cvss_score, affected_software, exploit_available,
                   exploit_references FROM harvested_cves
                   WHERE (summary LIKE ? OR affected_software LIKE ? OR id LIKE ?)
                   AND cvss_score >= ? ORDER BY cvss_score DESC LIMIT 20""",
                (f"%{query}%", f"%{query}%", f"%{query}%", min_cvss),
            ).fetchall()
            return [
                {
                    "id": r[0], "source": r[1], "summary": r[2][:300],
                    "cvss_score": r[3], "affected_software": r[4],
                    "exploit_available": bool(r[5]),
                    "exploit_references": json.loads(r[6]) if r[6] else [],
                }
                for r in rows
            ]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM harvested_cves").fetchone()[0]
            ingested = conn.execute("SELECT COUNT(*) FROM harvested_cves WHERE ingested = 1").fetchone()[0]
            with_exploit = conn.execute("SELECT COUNT(*) FROM harvested_cves WHERE exploit_available = 1").fetchone()[0]
            by_source = dict(conn.execute(
                "SELECT source, COUNT(*) FROM harvested_cves GROUP BY source"
            ).fetchall())
            return {
                "total": total,
                "ingested": ingested,
                "pending": total - ingested,
                "with_exploit": with_exploit,
                "by_source": by_source,
            }

    async def close(self):
        await self._http.aclose()


def csv_parse_line(line: str) -> list[str]:
    parts = []
    current = []
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts
