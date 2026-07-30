"""TTP Playbook Engine — Adversary-profiled attack chain templates.

Provides structured, replayable attack chains mapped to real threat actor
behavior (Lazarus, APT28, APT29, FIN7, Conti, LockBit, etc.).
Each playbook defines phase sequencing, tool selection, opsec posture,
and infrastructure requirements.
"""
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("ttp.engine")

PLAYBOOK_DB = os.path.join(os.path.dirname(__file__), "..", "data", "ttp.db")


class AdversaryProfile(str, Enum):
    LAZARUS = "lazarus"
    APT28 = "apt28"
    APT29 = "apt29"
    FIN7 = "fin7"
    CONTI = "conti"
    LOCKBIT = "lockbit"
    BLACKCAT = "blackcat"
    CL0P = "cl0p"
    ROYAL = "royal"
    HIVE = "hive"
    CUSTOM = "custom"


class OpsecLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class InfrastructureType(str, Enum):
    DIRECT = "direct"
    TOR = "tor"
    CDN_FRONTING = "cdn_fronting"
    DOMAIN_FRONTING = "domain_fronting"
    FAST_FLUX = "fast_flux"
    COMPROMISED_HOST = "compromised_host"


@dataclass
class Phase:
    name: str
    tools: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    timeout: int = 300
    retry_on_fail: bool = True
    opsec_notes: str = ""


@dataclass
class Playbook:
    id: str
    name: str
    adversary: AdversaryProfile
    description: str
    phases: list[Phase] = field(default_factory=list)
    infrastructure: list[InfrastructureType] = field(default_factory=list)
    opsec_level: OpsecLevel = OpsecLevel.MEDIUM
    target_sectors: list[str] = field(default_factory=list)
    geographic_focus: list[str] = field(default_factory=list)
    c2_config: dict = field(default_factory=dict)
    payload_preferences: dict = field(default_factory=dict)
    created: float = field(default_factory=time.time)


@dataclass
class PlaybookExecution:
    playbook_id: str
    target: str
    current_phase: int = 0
    phase_results: dict = field(default_factory=dict)
    started: float = field(default_factory=time.time)
    status: str = "running"
    notes: str = ""


class TTPEngine:
    def __init__(self, db_path: str = PLAYBOOK_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._seed_playbooks()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS playbooks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    adversary TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    phases TEXT NOT NULL,
                    infrastructure TEXT DEFAULT '[]',
                    opsec_level TEXT DEFAULT 'medium',
                    target_sectors TEXT DEFAULT '[]',
                    geographic_focus TEXT DEFAULT '[]',
                    c2_config TEXT DEFAULT '{}',
                    payload_preferences TEXT DEFAULT '{}',
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executions (
                    id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    current_phase INTEGER DEFAULT 0,
                    phase_results TEXT DEFAULT '{}',
                    started REAL NOT NULL,
                    completed REAL DEFAULT 0,
                    status TEXT DEFAULT 'running',
                    notes TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_executions_pb ON executions(playbook_id);
            """)

    def _seed_playbooks(self):
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0]
            if existing > 0:
                return

            playbooks = self._default_playbooks()
            now = time.time()
            for pb in playbooks:
                conn.execute(
                    """INSERT INTO playbooks
                       (id, name, adversary, description, phases, infrastructure,
                        opsec_level, target_sectors, geographic_focus, c2_config,
                        payload_preferences, created)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (pb.id, pb.name, pb.adversary.value, pb.description,
                     json.dumps([self._phase_to_dict(p) for p in pb.phases]),
                     json.dumps([i.value for i in pb.infrastructure]),
                     pb.opsec_level.value,
                     json.dumps(pb.target_sectors), json.dumps(pb.geographic_focus),
                     json.dumps(pb.c2_config), json.dumps(pb.payload_preferences),
                     now),
                )

    def _phase_to_dict(self, p: Phase) -> dict:
        return {
            "name": p.name, "tools": p.tools, "techniques": p.techniques,
            "preconditions": p.preconditions, "postconditions": p.postconditions,
            "timeout": p.timeout, "retry_on_fail": p.retry_on_fail,
            "opsec_notes": p.opsec_notes,
        }

    def _dict_to_phase(self, d: dict) -> Phase:
        return Phase(
            name=d["name"], tools=d.get("tools", []), techniques=d.get("techniques", []),
            preconditions=d.get("preconditions", []), postconditions=d.get("postconditions", []),
            timeout=d.get("timeout", 300), retry_on_fail=d.get("retry_on_fail", True),
            opsec_notes=d.get("opsec_notes", ""),
        )

    def _default_playbooks(self) -> list[Playbook]:
        now = time.time()
        return [
            Playbook(
                id=str(uuid.uuid4())[:12],
                name="Lazarus Supply Chain",
                adversary=AdversaryProfile.LAZARUS,
                description="Supply chain compromise → watering hole → custom malware → crypto theft",
                phases=[
                    Phase("recon", tools=["subfinder", "nuclei", "shodan"],
                          techniques=["T1590.005", "T1596.002"],
                          postconditions=["target_supply_chain_identified"]),
                    Phase("initial_access", tools=["msf_exploit", "custom_loader"],
                          techniques=["T1195.002", "T1204.002"],
                          preconditions=["target_supply_chain_identified"],
                          postconditions=["foothold_established"]),
                    Phase("postex", tools=["custom_rat", "cred_dump"],
                          techniques=["T1003", "T1082", "T1083"],
                          postconditions=["credentials_harvested"]),
                    Phase("lateral", tools=["psexec", "wmi", "ssh_key"],
                          techniques=["T1021.002", "T1021.004"],
                          preconditions=["credentials_harvested"],
                          postconditions=["domain_access"]),
                    Phase("collection", tools=["custom_exfil", "sql_dump"],
                          techniques=["T1005", "T1213", "T1560"],
                          postconditions=["data_staged"]),
                    Phase("exfil", tools=["custom_c2", "dns_tunnel"],
                          techniques=["T1048.003", "T1567.002"],
                          preconditions=["data_staged"],
                          postconditions=["data_exfiltrated"]),
                    Phase("impact", tools=["custom_ransom", "wiper"],
                          techniques=["T1486", "T1485"],
                          preconditions=["data_exfiltrated"],
                          postconditions=["destruction_complete"]),
                ],
                infrastructure=[InfrastructureType.COMPROMISED_HOST, InfrastructureType.CDN_FRONTING],
                opsec_level=OpsecLevel.HIGH,
                target_sectors=["crypto", "fintech", "gaming", "defense"],
                geographic_focus=["global"],
                c2_config={"protocol": "custom_tls", "domains": "dga", "sleep": 3600},
                payload_preferences={"lang": "c", "arch": "x64", "signed": True},
            ),
            Playbook(
                id=str(uuid.uuid4())[:12],
                name="APT28 Credential Harvest",
                adversary=AdversaryProfile.APT28,
                description="Phishing → credential harvest → VPN access → AD reconnaissance → exfil",
                phases=[
                    Phase("recon", tools=["gophish", "linkedin_scraper", "dnsrecon"],
                          techniques=["T1598.001", "T1590.005"],
                          postconditions=["targets_identified"]),
                    Phase("initial_access", tools=["gophish", "evilginx2"],
                          techniques=["T1566.002", "T1556.002"],
                          preconditions=["targets_identified"],
                          postconditions=["credentials_captured"]),
                    Phase("postex", tools=["rubeus", "sharphound", "seatbelt"],
                          techniques=["T1003.006", "T1208", "T1087.002"],
                          preconditions=["credentials_captured"],
                          postconditions=["ad_mapped"]),
                    Phase("lateral", tools=["psexec.py", "wmiexec", "rdp"],
                          techniques=["T1021.002", "T1021.004", "T1021.001"],
                          preconditions=["ad_mapped"],
                          postconditions=["domain_admin"]),
                    Phase("collection", tools=["ntdsutil", "secretsdump", "sqlcmd"],
                          techniques=["T1003.004", "T1213", "T1560"],
                          preconditions=["domain_admin"],
                          postconditions=["data_staged"]),
                    Phase("exfil", tools=["rar", "webdav", "onedrive"],
                          techniques=["T1567.002", "T1537"],
                          preconditions=["data_staged"],
                          postconditions=["data_exfiltrated"]),
                ],
                infrastructure=[InfrastructureType.TOR, InfrastructureType.DOMAIN_FRONTING],
                opsec_level=OpsecLevel.MEDIUM,
                target_sectors=["government", "military", "ngo", "media"],
                geographic_focus=["nato", "eastern_europe"],
                c2_config={"protocol": "http_json", "sleep": 1800, "jitter": 0.3},
                payload_preferences={"lang": "powershell", "obfuscation": "amsi_bypass"},
            ),
            Playbook(
                id=str(uuid.uuid4())[:12],
                name="FIN7 POS Intrusion",
                adversary=AdversaryProfile.FIN7,
                description="SQLi → web shell → POS scraping → card data exfil",
                phases=[
                    Phase("recon", tools=["sqlmap", "dirb", "nuclei"],
                          techniques=["T1590.005", "T1595.001"],
                          postconditions=["web_vuln_found"]),
                    Phase("initial_access", tools=["sqlmap", "webshell"],
                          techniques=["T1190", "T1505.003"],
                          preconditions=["web_vuln_found"],
                          postconditions=["shell_on_web"]),
                    Phase("postex", tools=["meterpreter", "cobaltstrike"],
                          techniques=["T1003", "T1059.001", "T1082"],
                          preconditions=["shell_on_web"],
                          postconditions=["system_access"]),
                    Phase("lateral", tools=["psexec", "winrm", "schtasks"],
                          techniques=["T1021.002", "T1021.006", "T1053.005"],
                          preconditions=["system_access"],
                          postconditions=["pos_network_access"]),
                    Phase("collection", tools=["custom_pos_scraper", "memory_dump"],
                          techniques=["T1005", "T1119", "T1081"],
                          preconditions=["pos_network_access"],
                          postconditions=["track2_data_collected"]),
                    Phase("exfil", tools=["custom_encrypt", "sftp", "tor"],
                          techniques=["T1041", "T1029", "T1573"],
                          preconditions=["track2_data_collected"],
                          postconditions=["data_exfiltrated"]),
                ],
                infrastructure=[InfrastructureType.FAST_FLUX, InfrastructureType.TOR],
                opsec_level=OpsecLevel.HIGH,
                target_sectors=["hospitality", "retail", "food_service"],
                geographic_focus=["us", "eu"],
                c2_config={"protocol": "https", "cdns": ["cloudflare", "akamai"]},
                payload_preferences={"lang": "csharp", "memory_only": True},
            ),
            Playbook(
                id=str(uuid.uuid4())[:12],
                name="Conti Ransomware",
                adversary=AdversaryProfile.CONTI,
                description="VPN/ProxyShell → AD compromise → data theft → encryption → extortion",
                phases=[
                    Phase("recon", tools=["nmap", "nuclei", "shodan"],
                          techniques=["T1595.001", "T1590.005"],
                          postconditions=["vpn_vuln_found"]),
                    Phase("initial_access", tools=["proxylogon", "cve_2021_34527"],
                          techniques=["T1190", "T1133"],
                          preconditions=["vpn_vuln_found"],
                          postconditions=["initial_foothold"]),
                    Phase("postex", tools=["cobaltstrike", "sharphound", "certipy"],
                          techniques=["T1003.001", "T1069.002", "T1550.003"],
                          preconditions=["initial_foothold"],
                          postconditions=["domain_admin", "certs_abused"]),
                    Phase("collection", tools=["rar", "7zip", "megasync"],
                          techniques=["T1560", "T1005", "T1213", "T1530"],
                          preconditions=["domain_admin"],
                          postconditions=["data_staged", "shadow_copies_deleted"]),
                    Phase("exfil", tools=["megasync", "custom_c2", "curl"],
                          techniques=["T1041", "T1567.002", "T1029"],
                          preconditions=["data_staged"],
                          postconditions=["data_exfiltrated"]),
                    Phase("impact", tools=["contilocker", "vssadmin"],
                          techniques=["T1486", "T1490"],
                          preconditions=["data_exfiltrated"],
                          postconditions=["encryption_complete"]),
                ],
                infrastructure=[InfrastructureType.TOR, InfrastructureType.COMPROMISED_HOST],
                opsec_level=OpsecLevel.HIGH,
                target_sectors=["healthcare", "manufacturing", "education", "gov"],
                geographic_focus=["global"],
                c2_config={"protocol": "custom_tcp", "backup": "tor"},
                payload_preferences={"lang": "c", "packed": True},
            ),
            Playbook(
                id=str(uuid.uuid4())[:12],
                name="LockBit Affiliate",
                adversary=AdversaryProfile.LOCKBIT,
                description="RDP brute → AD recon → stealth encryption → leak site",
                phases=[
                    Phase("recon", tools=["masscan", "rdpscan"],
                          techniques=["T1595.001", "T1590.005"],
                          postconditions=["rdp_exposed"]),
                    Phase("initial_access", tools=["hydra", "rdp_brute"],
                          techniques=["T1110.001", "T1133"],
                          preconditions=["rdp_exposed"],
                          postconditions=["rdp_access"]),
                    Phase("postex", tools=["adfind", "bloodhound", "kerbrute"],
                          techniques=["T1087.002", "T1208", "T1558.003"],
                          preconditions=["rdp_access"],
                          postconditions=["ad_mapped", "kerberoastable"]),
                    Phase("lateral", tools=["psexec.py", "wmiexec", "smbexec"],
                          techniques=["T1021.002", "T1021.003"],
                          preconditions=["ad_mapped"],
                          postconditions=["domain_wide"]),
                    Phase("collection", tools=["stealbit", "rar", "robocopy"],
                          techniques=["T1005", "T1560", "T1021.002"],
                          preconditions=["domain_wide"],
                          postconditions=["data_staged"]),
                    Phase("exfil", tools=["stealbit", "mega", "custom"],
                          techniques=["T1041", "T1567.002"],
                          preconditions=["data_staged"],
                          postconditions=["data_exfiltrated"]),
                    Phase("impact", tools=["lockbit_encryptor"],
                          techniques=["T1486", "T1490"],
                          preconditions=["data_exfiltrated"],
                          postconditions=["encrypted", "note_dropped"]),
                ],
                infrastructure=[InfrastructureType.TOR, InfrastructureType.CDN_FRONTING],
                opsec_level=OpsecLevel.MEDIUM,
                target_sectors=["any"],
                geographic_focus=["global"],
                c2_config={"protocol": "https", "panel": "lockbit_panel"},
                payload_preferences={"lang": "c", "packed": "custom", "evasion": "syscall"},
            ),
            Playbook(
                id=str(uuid.uuid4())[:12],
                name="APT29 Cloud Focus",
                adversary=AdversaryProfile.APT29,
                description="Password spray → cloud admin → SAML abuse → federation trust → persistence",
                phases=[
                    Phase("recon", tools=["azurehound", "graph_api", "msol"],
                          techniques=["T1590.005", "T1069.003"],
                          postconditions=["cloud_tenant_mapped"]),
                    Phase("initial_access", tools=["msolspray", "azure_ad_password_spray"],
                          techniques=["T1110.003", "T1078.004"],
                          preconditions=["cloud_tenant_mapped"],
                          postconditions=["cloud_account_compromised"]),
                    Phase("postex", tools=["stormspotter", "roadrecon", "azureaddecrypt"],
                          techniques=["T1069.003", "T1550.004", "T1556.003"],
                          preconditions=["cloud_account_compromised"],
                          postconditions=["global_admin", "saml_keys"]),
                    Phase("persistence", tools=["cert_sync", "app_registration"],
                          techniques=["T1505.005", "T1098", "T1556.003"],
                          preconditions=["global_admin"],
                          postconditions=["backdoor_established"]),
                    Phase("collection", tools=["graph_api", "exo_powershell", "sharepoint_dump"],
                          techniques=["T1213.003", "T1530", "T1114.001"],
                          preconditions=["backdoor_established"],
                          postconditions=["data_staged"]),
                    Phase("exfil", tools=["onedrive", "sharepoint", "custom"],
                          techniques=["T1567.002", "T1041"],
                          preconditions=["data_staged"],
                          postconditions=["data_exfiltrated"]),
                ],
                infrastructure=[InfrastructureType.DOMAIN_FRONTING, InfrastructureType.COMPROMISED_HOST],
                opsec_level=OpsecLevel.PARANOID,
                target_sectors=["gov", "think_tank", "diplomatic", "tech"],
                geographic_focus=["nato", "eastern_europe", "central_asia"],
                c2_config={"protocol": "graph_api", "token_refresh": 3600},
                payload_preferences={"lang": "powershell", "memory_only": True, "living_off_land": True},
            ),
        ]

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM playbooks WHERE id = ?", (playbook_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_playbook(row)

    def get_playbook_by_name(self, name: str) -> Optional[Playbook]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM playbooks WHERE name = ?", (name,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_playbook(row)

    def list_playbooks(self, adversary: Optional[AdversaryProfile] = None,
                       sector: str = "") -> list[Playbook]:
        with sqlite3.connect(self.db_path) as conn:
            q = "SELECT * FROM playbooks WHERE 1=1"
            params = []
            if adversary:
                q += " AND adversary = ?"
                params.append(adversary.value)
            if sector:
                q += " AND target_sectors LIKE ?"
                params.append(f"%{sector}%")
            q += " ORDER BY created DESC"
            rows = conn.execute(q, params).fetchall()
            return [self._row_to_playbook(r) for r in rows]

    def _row_to_playbook(self, row: tuple) -> Playbook:
        return Playbook(
            id=row[0], name=row[1], adversary=AdversaryProfile(row[2]),
            description=row[3],
            phases=[self._dict_to_phase(p) for p in json.loads(row[4])],
            infrastructure=[InfrastructureType(i) for i in json.loads(row[5])],
            opsec_level=OpsecLevel(row[6]),
            target_sectors=json.loads(row[7]),
            geographic_focus=json.loads(row[8]),
            c2_config=json.loads(row[9]),
            payload_preferences=json.loads(row[10]),
            created=row[11],
        )

    def start_execution(self, playbook_id: str, target: str) -> PlaybookExecution:
        exec_id = str(uuid.uuid4())[:12]
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO executions (id, playbook_id, target, current_phase, phase_results, started, status)
                   VALUES (?, ?, ?, 0, '{}', ?, 'running')""",
                (exec_id, playbook_id, target, time.time()),
            )
        return PlaybookExecution(playbook_id=playbook_id, target=target)

    def advance_phase(self, exec_id: str, phase_result: dict, success: bool = True):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT current_phase, phase_results FROM executions WHERE id = ?", (exec_id,)).fetchone()
            if not row:
                return
            current, results_json = row
            results = json.loads(results_json)
            results[f"phase_{current}"] = phase_result
            next_phase = current + 1
            status = "running"
            completed = 0
            playbook = self.get_playbook(
                conn.execute("SELECT playbook_id FROM executions WHERE id = ?", (exec_id,)).fetchone()[0]
            )
            if next_phase >= len(playbook.phases):
                status = "completed"
                completed = time.time()
                next_phase = current
            conn.execute(
                "UPDATE executions SET current_phase = ?, phase_results = ?, status = ?, completed = ? WHERE id = ?",
                (next_phase, json.dumps(results), status, completed, exec_id),
            )

    def get_execution(self, exec_id: str) -> Optional[PlaybookExecution]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM executions WHERE id = ?", (exec_id,)).fetchone()
            if not row:
                return None
            return PlaybookExecution(
                playbook_id=row[1], target=row[2], current_phase=row[3],
                phase_results=json.loads(row[4]), started=row[5],
                status=row[7], notes=row[8],
            )

    def get_next_phase(self, exec_id: str) -> Optional[Phase]:
        ex = self.get_execution(exec_id)
        if not ex or ex.status != "running":
            return None
        pb = self.get_playbook(ex.playbook_id)
        if not pb or ex.current_phase >= len(pb.phases):
            return None
        return pb.phases[ex.current_phase]

    def recommend_for_target(self, target_profile: dict) -> list[Playbook]:
        """Select playbooks matching target OS, sector, geography, tech stack."""
        all_pbs = self.list_playbooks()
        scored = []
        for pb in all_pbs:
            score = 0
            sectors = target_profile.get("sectors", [])
            if any(s in pb.target_sectors for s in sectors):
                score += 3
            geo = target_profile.get("geography", [])
            if any(g in pb.geographic_focus for g in geo):
                score += 2
            os_type = target_profile.get("os", "")
            if os_type == "windows" and any(p.name in ["initial_access", "postex"] for p in pb.phases):
                score += 1
            if score > 0:
                scored.append((score, pb))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in scored[:5]]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0]
            by_adv = dict(conn.execute(
                "SELECT adversary, COUNT(*) FROM playbooks GROUP BY adversary"
            ).fetchall())
            by_sector = {}
            rows = conn.execute("SELECT target_sectors FROM playbooks").fetchall()
            for r in rows:
                for s in json.loads(r[0]):
                    by_sector[s] = by_sector.get(s, 0) + 1
            return {
                "total": total, "by_adversary": by_adv, "by_sector": by_sector,
            }


def get_ttp_engine() -> TTPEngine:
    return TTPEngine()