import json
import logging
import os
import re
import sqlite3
import time
from typing import Optional

import httpx

logger = logging.getLogger("harvester.extractor")

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "harvester.db")

TECHNIQUE_CATEGORIES = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
    "recon", "scan", "exploit",
]


class TechniqueExtractor:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._http = httpx.AsyncClient(timeout=30, follow_redirects=True)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS extracted_techniques (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    technique_name TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'exploit',
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    description TEXT NOT NULL,
                    code_snippet TEXT DEFAULT '',
                    commands TEXT DEFAULT '',
                    prerequisites TEXT DEFAULT '',
                    mitre_mapping TEXT DEFAULT '',
                    confidence REAL DEFAULT 0.5,
                    tested INTEGER DEFAULT 0,
                    effectiveness REAL DEFAULT 0.0,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    UNIQUE(technique_name, source_type, source_id)
                );
                CREATE INDEX IF NOT EXISTS idx_extracted_cat ON extracted_techniques(category, confidence);
            """)

    def extract_from_cve(self, cve: dict) -> Optional[dict]:
        cve_id = cve.get("id", "")
        summary = cve.get("summary", "")
        refs = cve.get("exploit_references", [])
        if isinstance(refs, str):
            try:
                refs = json.loads(refs)
            except (json.JSONDecodeError, TypeError):
                refs = []

        technique_name = f"exploit_{cve_id.lower().replace('-', '_')}"
        commands = self._generate_commands_from_cve(cve)
        prerequisites = self._extract_prerequisites(summary)

        return {
            "technique_name": technique_name,
            "category": "exploit",
            "source_type": "cve_feed",
            "source_id": cve_id,
            "description": summary[:1000],
            "code_snippet": "",
            "commands": json.dumps(commands),
            "prerequisites": prerequisites,
            "mitre_mapping": json.dumps(self._map_to_mitre(summary, cve_id)),
            "confidence": 0.3,
        }

    def extract_from_repo(self, repo: dict) -> Optional[dict]:
        full_name = repo.get("full_name", "")
        desc = repo.get("description", "")
        cve_refs = repo.get("cve_refs", [])
        lang = repo.get("language", "")

        technique_name = f"github_{full_name.replace('/', '_').replace('-', '_')}"
        category = self._classify_repo(desc, lang)

        commands = [
            f"git clone {repo.get('clone_url', '')}",
            f"cd {full_name.split('/')[-1]}",
        ]

        if lang.lower() in ("python",):
            commands.append("pip install -r requirements.txt 2>/dev/null; python exploit.py")
        elif lang.lower() in ("go",):
            commands.append("go build -o exploit . && ./exploit")
        elif lang.lower() in ("rust",):
            commands.append("cargo build --release && ./target/release/exploit")
        elif lang.lower() in ("java",):
            commands.append("javac Exploit.java && java Exploit")
        elif lang.lower() == "c":
            commands.append("gcc -o exploit exploit.c && ./exploit")
        elif lang.lower() in ("c++", "cpp"):
            commands.append("g++ -o exploit exploit.cpp && ./exploit")
        elif lang.lower() in ("powershell",):
            commands.append("powershell -ExecutionPolicy Bypass -File exploit.ps1")
        elif lang.lower() == "ruby":
            commands.append("ruby exploit.rb")

        return {
            "technique_name": technique_name,
            "category": category,
            "source_type": "extracted_repo",
            "source_id": repo.get("id", full_name),
            "description": desc[:1000] or f"GitHub PoC: {full_name}",
            "code_snippet": "",
            "commands": json.dumps(commands),
            "prerequisites": json.dumps({"language": lang, "cves": cve_refs}),
            "mitre_mapping": json.dumps(self._map_to_mitre(desc + " " + ",".join(cve_refs), full_name)),
            "confidence": 0.4,
        }

    def _generate_commands_from_cve(self, cve: dict) -> list[str]:
        cve_id = cve.get("id", "")
        affected = cve.get("affected_software", "")
        summary = cve.get("summary", "").lower()

        commands = [f"# CVE: {cve_id}", f"# Affected: {affected}"]

        if "sql injection" in summary or "sqli" in summary:
            commands.append("sqlmap -u 'http://TARGET/vuln.php?id=1' --batch --random-agent")
        elif "rce" in summary or "remote code" in summary or "command injection" in summary:
            commands.append("searchsploit " + cve_id)
            commands.append("nuclei -t cves/ -id " + cve_id + " -u http://TARGET")
        elif "xss" in summary or "cross-site" in summary:
            commands.append("dalfox url http://TARGET?q=test -w 50")
        elif "ssrf" in summary:
            commands.append("ffuf -u 'http://TARGET/page?url=FUZZ' -w /usr/share/seclists/Discovery/Web_Content/ssrf.txt")
        elif "file read" in summary or "lfi" in summary or "path traversal" in summary:
            commands.append("ffuf -u 'http://TARGET/page?file=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-graceful.txt")
        else:
            commands.append("searchsploit " + cve_id)
            commands.append("nuclei -t cves/ -id " + cve_id + " -u http://TARGET")
            commands.append(f"# Referenced: {cve.get('exploit_references', '')[:200]}")

        return commands

    def _extract_prerequisites(self, text: str) -> str:
        prereqs = []
        patterns = [
            (r"(?i)(?:requires|prerequisite|prior).{0,50}(?:auth|credential|login|authenticated)", "authentication required"),
            (r"(?i)(?:low|no|without)\s*(?:privilege|auth)", "no authentication required"),
            (r"(?i)(?:user.interaction|click|phish|social)", "user interaction required"),
            (r"(?i)(?:network|adjacent|local)\s*(?:access|network)", "network access"),
            (r"(?i)(?:physical|usb|local.access)", "physical access required"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, text):
                prereqs.append(label)
        return ", ".join(set(prereqs)) if prereqs else "unknown"

    def _classify_repo(self, desc: str, lang: str) -> str:
        dl = desc.lower()
        if any(w in dl for w in ("recon", "scanner", "enumeration", "discovery", "osint")):
            return "recon"
        if any(w in dl for w in ("exploit", "rce", "remote code", "shell", "webshell")):
            return "exploit"
        if any(w in dl for w in ("privesc", "privilege escalation", "elevation")):
            return "privilege_escalation"
        if any(w in dl for w in ("bypass", "evasion", "amsi", "etw", "defender")):
            return "defense_evasion"
        if any(w in dl for w in ("lateral", "movement", "pivot", "proxy")):
            return "lateral_movement"
        if any(w in dl for w in ("exfil", "exfiltration", "data theft")):
            return "exfiltration"
        if any(w in dl for w in ("c2", "beacon", "implant", "trojan", "rat")):
            return "command_and_control"
        if any(w in dl for w in ("credential", "hash", "dump", "password", "token")):
            return "credential_access"
        if any(w in dl for w in ("persist", "backdoor", "autorun")):
            return "persistence"
        return "exploit"

    def _map_to_mitre(self, text: str, fallback_id: str) -> list[dict]:
        mappings = []
        tl = text.lower()
        mitre_map = {
            "T1059": ("command and scripting", ["shell", "command", "powershell", "bash", "cmd"]),
            "T1055": ("process injection", ["inject", "dll", "process injection"]),
            "T1078": ("valid accounts", ["credential", "password", "account", "login"]),
            "T1190": ("exploit public-facing app", ["exploit", "rce", "remote", "cve"]),
            "T1087": ("account discovery", ["enum", "enumeration", "user", "account"]),
            "T1046": ("network service scanning", ["scan", "nmap", "port"]),
            "T1053": ("scheduled task", ["cron", "scheduled", "task", "schtask"]),
            "T1003": ("credential dumping", ["dump", "hash", "lsass", "mimikatz"]),
            "T1574": ("hijack execution flow", ["hijack", "dll", "path", "search order"]),
            "T1027": ("obfuscated files", ["obfuscat", "encrypt", "pack", "crypt"]),
            "T1048": ("exfil alt protocol", ["dns", "icmp", "http", "exfil"]),
            "T1071": ("application layer protocol", ["http", "https", "dns", "c2"]),
        }
        for tid, (name, keywords) in mitre_map.items():
            if any(kw in tl for kw in keywords):
                mappings.append({"id": tid, "name": name})
                if len(mappings) >= 3:
                    break
        if not mappings:
            mappings.append({"id": "T1190", "name": "exploit_public_facing_application"})
        return mappings

    def store_technique(self, technique: dict) -> bool:
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO extracted_techniques
                       (technique_name, category, source_type, source_id, description,
                        code_snippet, commands, prerequisites, mitre_mapping,
                        confidence, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (technique["technique_name"], technique["category"],
                     technique["source_type"], technique["source_id"],
                     technique["description"], technique.get("code_snippet", ""),
                     technique.get("commands", "[]"),
                     technique.get("prerequisites", ""),
                     technique.get("mitre_mapping", "[]"),
                     technique.get("confidence", 0.3), now, now),
                )
                return conn.total_changes > 0
            except Exception as e:
                logger.warning(f"  Failed to store technique: {e}")
                return False

    def get_techniques(self, category: str = "", min_confidence: float = 0.0, limit: int = 50) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            q = "SELECT * FROM extracted_techniques WHERE 1=1"
            params = []
            if category:
                q += " AND category = ?"
                params.append(category)
            if min_confidence > 0:
                q += " AND confidence >= ?"
                params.append(min_confidence)
            q += " ORDER BY confidence DESC, last_seen DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(q, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_techniques_by_cve(self, cve_id: str) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM extracted_techniques WHERE source_id LIKE ? OR description LIKE ? ORDER BY confidence DESC",
                (f"%{cve_id}%", f"%{cve_id}%"),
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def search_techniques(self, query: str) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT * FROM extracted_techniques WHERE technique_name LIKE ? OR description LIKE ?
                   OR commands LIKE ? OR prerequisites LIKE ? ORDER BY confidence DESC LIMIT 30""",
                (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%"),
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row[0], "technique_name": row[1], "category": row[2],
            "source_type": row[3], "source_id": row[4],
            "description": row[5][:500],
            "code_snippet": row[6][:500] if row[6] else "",
            "commands": json.loads(row[7]) if row[7] else [],
            "prerequisites": row[8],
            "mitre_mapping": json.loads(row[9]) if row[9] else [],
            "confidence": row[10],
        }

    def update_confidence(self, technique_id: int, confidence: float):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE extracted_techniques SET confidence = ?, last_seen = ? WHERE id = ?",
                (confidence, time.time(), technique_id),
            )

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM extracted_techniques").fetchone()[0]
            by_category = dict(conn.execute(
                "SELECT category, COUNT(*) FROM extracted_techniques GROUP BY category ORDER BY COUNT(*) DESC"
            ).fetchall())
            by_source = dict(conn.execute(
                "SELECT source_type, COUNT(*) FROM extracted_techniques GROUP BY source_type"
            ).fetchall())
            avg_conf = conn.execute("SELECT AVG(confidence) FROM extracted_techniques").fetchone()[0] or 0
            return {
                "total": total,
                "by_category": by_category,
                "by_source": by_source,
                "avg_confidence": round(avg_conf, 3),
            }

    async def close(self):
        await self._http.aclose()
