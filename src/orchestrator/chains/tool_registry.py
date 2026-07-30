"""Tool Registry - Async executors for pentest tools."""

import asyncio
import json
import logging
import os
import shlex
import time
import uuid
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("tool_registry")


class ToolResult:
    """Standardized tool execution result."""
    def __init__(
        self,
        success: bool,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = -1,
        duration: float = 0.0,
        artifacts: list[dict] = None,
        metadata: dict = None,
    ):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration = duration
        self.artifacts = artifacts or []
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration": self.duration,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
        }


async def _run_command(
    cmd: list[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> ToolResult:
    """Run a command asynchronously with timeout."""
    start = time.time()
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env or os.environ.copy(),
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            exit_code = proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                duration=time.time() - start,
            )
        
        return ToolResult(
            success=exit_code == 0,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=exit_code,
            duration=time.time() - start,
        )
        
    except FileNotFoundError:
        return ToolResult(
            success=False,
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            exit_code=-1,
            duration=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            success=False,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=time.time() - start,
        )


# ============================================================
# NMAP Executor
# ============================================================
async def execute_nmap(params: dict, execution_id: str) -> dict:
    """Execute nmap scan with given parameters."""
    target = params.get("target", "")
    if not target:
        return {"success": False, "stderr": "Target required", "exit_code": -1, "duration": 0}
    
    ports = params.get("ports", "1-1000")
    scan_type = params.get("scan_type", "syn")
    stealth = params.get("stealth", False)
    aggressive = params.get("aggressive", False)
    service_version = params.get("service_version", True)
    os_detection = params.get("os_detection", False)
    scripts = params.get("scripts", "default")
    
    # Build nmap command
    cmd = ["nmap"]
    
    # Scan type
    if scan_type == "syn":
        cmd.append("-sS")
    elif scan_type == "connect":
        cmd.append("-sT")
    elif scan_type == "udp":
        cmd.append("-sU")
    elif scan_type == "ack":
        cmd.append("-sA")
    
    # Ports
    cmd.extend(["-p", ports])
    
    # Service version
    if service_version:
        cmd.append("-sV")
    
    # OS detection
    if os_detection:
        cmd.append("-O")
    
    # Scripts
    if scripts and scripts != "none":
        cmd.extend(["--script", scripts])
    
    # Timing
    if stealth:
        cmd.extend(["-T2", "--scan-delay", "5s"])
    elif aggressive:
        cmd.extend(["-T4", "-A"])
    else:
        cmd.append("-T3")
    
    # Output format
    output_file = f"/tmp/nmap_{execution_id}.xml"
    cmd.extend(["-oX", output_file, "-oN", f"/tmp/nmap_{execution_id}.nmap"])
    
    # Target
    cmd.append(target)
    
    logger.info(f"Executing nmap: {' '.join(cmd)}")
    result = await _run_command(cmd, timeout=600)
    
    # Parse XML output for artifacts
    artifacts = []
    if Path(output_file).exists():
        artifacts.append({
            "type": "nmap_xml",
            "path": output_file,
            "description": "Nmap XML output",
        })
    
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "artifacts": artifacts,
        "metadata": {"target": target, "ports": ports},
    }


# ============================================================
# SQLMAP Executor
# ============================================================
async def execute_sqlmap(params: dict, execution_id: str) -> dict:
    """Execute SQLMap for SQL injection testing."""
    url = params.get("url", "")
    if not url:
        return {"success": False, "stderr": "URL required", "exit_code": -1, "duration": 0}
    
    data = params.get("data", "")
    dbms = params.get("dbms", "")
    level = params.get("level", 3)
    risk = params.get("risk", 2)
    batch = params.get("batch", True)
    threads = params.get("threads", 5)
    timeout = params.get("timeout", 30)
    
    cmd = ["sqlmap", "-u", url]
    
    if data:
        cmd.extend(["--data", data])
    if dbms:
        cmd.extend(["--dbms", dbms])
    cmd.extend(["--level", str(level), "--risk", str(risk)])
    if batch:
        cmd.append("--batch")
    cmd.extend(["--threads", str(threads), "--timeout", str(timeout)])
    
    # Output directory
    output_dir = f"/tmp/sqlmap_{execution_id}"
    cmd.extend(["--output-dir", output_dir])
    
    logger.info(f"Executing sqlmap: {' '.join(cmd)}")
    result = await _run_command(cmd, timeout=600)
    
    artifacts = []
    if Path(output_dir).exists():
        artifacts.append({
            "type": "sqlmap_output",
            "path": output_dir,
            "description": "SQLMap output directory",
        })
    
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "artifacts": artifacts,
        "metadata": {"url": url, "dbms": dbms},
    }


# ============================================================
# BLOODHOUND Executor
# ============================================================
async def execute_bloodhound(params: dict, execution_id: str) -> dict:
    """Execute BloodHound Python collector."""
    domain = params.get("domain", "")
    dc = params.get("dc", "")
    username = params.get("username", "")
    password = params.get("password", "")
    collection_method = params.get("collection_method", "all")
    output_dir = params.get("output_dir", f"/tmp/bloodhound_{execution_id}")
    stealth = params.get("stealth", False)
    
    if not domain or not dc or not username or not password:
        return {"success": False, "stderr": "domain, dc, username, password required", "exit_code": -1, "duration": 0}
    
    cmd = [
        "bloodhound-python",
        "-d", domain,
        "-dc", dc,
        "-u", username,
        "-p", password,
        "-c", collection_method,
        "-o", output_dir,
    ]
    
    if stealth:
        cmd.append("--stealth")
    
    logger.info(f"Executing bloodhound: {' '.join(cmd[:8])} [redacted]")
    result = await _run_command(cmd, timeout=600)
    
    artifacts = []
    if Path(output_dir).exists():
        artifacts.append({
            "type": "bloodhound_json",
            "path": output_dir,
            "description": "BloodHound JSON output",
        })
    
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "artifacts": artifacts,
        "metadata": {"domain": domain, "dc": dc, "collection_method": collection_method},
    }


# ============================================================
# METASPLOIT Executor
# ============================================================
async def execute_metasploit(params: dict, execution_id: str) -> dict:
    """Execute Metasploit module via msfconsole."""
    module = params.get("module", "")
    rhost = params.get("rhost", "")
    rport = params.get("rport", 0)
    payload = params.get("payload", "")
    lhost = params.get("lhost", "")
    lport = params.get("lport", 4444)
    options = params.get("options", {})
    
    if not module or not rhost:
        return {"success": False, "stderr": "module and rhost required", "exit_code": -1, "duration": 0}
    
    # Build msfconsole resource script
    rc_content = f"use {module}\n"
    rc_content += f"set RHOSTS {rhost}\n"
    if rport:
        rc_content += f"set RPORT {rport}\n"
    if payload:
        rc_content += f"set PAYLOAD {payload}\n"
    if lhost:
        rc_content += f"set LHOST {lhost}\n"
    if lport:
        rc_content += f"set LPORT {lport}\n"
    
    for key, value in options.items():
        rc_content += f"set {key} {value}\n"
    
    rc_content += "exploit -j\n"
    rc_content += "exit\n"
    
    rc_file = f"/tmp/msf_{execution_id}.rc"
    Path(rc_file).write_text(rc_content)
    
    cmd = ["msfconsole", "-q", "-r", rc_file]
    
    logger.info(f"Executing metasploit: {module} against {rhost}")
    result = await _run_command(cmd, timeout=300)
    
    artifacts = [{"type": "msf_resource", "path": rc_file, "description": "Metasploit resource script"}]
    
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "artifacts": artifacts,
        "metadata": {"module": module, "rhost": rhost, "payload": payload},
    }


# ============================================================
# CRACKMAPEXEC Executor
# ============================================================
async def execute_crackmapexec(params: dict, execution_id: str) -> dict:
    """Execute CrackMapExec for network enumeration."""
    target = params.get("target", "")
    protocol = params.get("protocol", "smb")
    username = params.get("username", "")
    password = params.get("password", "")
    hash_val = params.get("hash", "")
    command = params.get("command", "")
    module = params.get("module", "")
    options = params.get("options", {})
    
    if not target:
        return {"success": False, "stderr": "target required", "exit_code": -1, "duration": 0}
    
    cmd = ["crackmapexec", protocol, target]
    
    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if hash_val:
        cmd.extend(["-H", hash_val])
    if command:
        cmd.extend(["-x", command])
    if module:
        cmd.extend(["-M", module])
        for key, value in options.items():
            cmd.extend(["-o", f"{key}={value}"])
    
    # Output
    output_file = f"/tmp/cme_{execution_id}.json"
    cmd.extend(["--json", output_file])
    
    logger.info(f"Executing crackmapexec: {protocol} {target}")
    result = await _run_command(cmd, timeout=300)
    
    artifacts = []
    if Path(output_file).exists():
        artifacts.append({
            "type": "cme_json",
            "path": output_file,
            "description": "CrackMapExec JSON output",
        })
    
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "artifacts": artifacts,
        "metadata": {"target": target, "protocol": protocol},
    }


# ============================================================
# CHISEL Executor
# ============================================================
async def execute_chisel(params: dict, execution_id: str) -> dict:
    """Execute Chisel for tunneling."""
    mode = params.get("mode", "client")
    target = params.get("target", "")
    port = params.get("port", 8080)
    socks5 = params.get("socks5", True)
    reverse = params.get("reverse", False)
    auth = params.get("auth", "")
    fingerprint = params.get("fingerprint", "")
    
    if mode == "client" and not target:
        return {"success": False, "stderr": "target required for client mode", "exit_code": -1, "duration": 0}
    
    if mode == "server":
        cmd = ["chisel", "server", "-p", str(port)]
        if socks5:
            cmd.append("--socks5")
        if auth:
            cmd.extend(["--auth", auth])
        if fingerprint:
            cmd.extend(["--fingerprint", fingerprint])
    else:
        # Client mode
        cmd = ["chisel", "client", target]
        if socks5:
            cmd.extend(["--socks5", "1080"])
        if reverse:
            cmd.append("--reverse")
        if auth:
            cmd.extend(["--auth", auth])
        if fingerprint:
            cmd.extend(["--fingerprint", fingerprint])
    
    logger.info(f"Executing chisel: {' '.join(cmd)}")
    
    # Chisel runs in background, we'll just test connection
    # For actual tunnel, we'd need to run as daemon
    result = await _run_command(cmd + ["--help"], timeout=10)  # Test if binary exists
    
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "artifacts": [],
        "metadata": {"mode": mode, "target": target, "port": port},
    }


# ============================================================
# Tool Registry Class
# ============================================================
class ToolRegistry:
    """Registry of available tools with execution capabilities."""
    
    def __init__(self):
        self._tools = {
            "nmap": {
                "executor": execute_nmap,
                "description": "Network port scanning and service enumeration",
                "category": "recon",
            },
            "sqlmap": {
                "executor": execute_sqlmap,
                "description": "Automated SQL injection detection and exploitation",
                "category": "exploit",
            },
            "bloodhound": {
                "executor": execute_bloodhound,
                "description": "Active Directory attack path analysis",
                "category": "postex",
            },
            "metasploit": {
                "executor": execute_metasploit,
                "description": "Metasploit Framework module execution",
                "category": "exploit",
            },
            "crackmapexec": {
                "executor": execute_crackmapexec,
                "description": "Network enumeration and credential testing",
                "category": "postex",
            },
            "chisel": {
                "executor": execute_chisel,
                "description": "Fast TCP/UDP tunneling over HTTP/SOCKS5",
                "category": "c2",
            },
        }
    
    def get_tool(self, name: str) -> Optional[dict]:
        return self._tools.get(name)
    
    def list_tools(self) -> list[dict]:
        return [
            {"name": name, **info}
            for name, info in self._tools.items()
        ]
    
    def get_categories(self) -> list[str]:
        return list(set(info["category"] for info in self._tools.values()))
    
    async def execute(self, name: str, params: dict, execution_id: str = None) -> dict:
        tool = self.get_tool(name)
        if not tool:
            return {"success": False, "stderr": f"Tool '{name}' not found", "exit_code": -1, "duration": 0}
        
        if execution_id is None:
            execution_id = str(uuid.uuid4())
        
        return await tool["executor"](params, execution_id)


# Global registry instance
registry = ToolRegistry()


async def execute_tool(name: str, params: dict, execution_id: str = None) -> dict:
    """Execute a tool by name."""
    return await registry.execute(name, params, execution_id)