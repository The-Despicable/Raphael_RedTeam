import subprocess
import re
from ...schemas.tools import NmapParams, NmapResult
from ...core.registry import BaseTool


class Nmap(BaseTool):
    name = "nmap"
    description = "Port scan a target using nmap. Discovers open ports, running services, and OS detection."

    async def execute(self, params: dict) -> dict:
        p = NmapParams(**params)
        cmd = ["nmap", "-sV", "-T4"]
        if p.aggressive:
            cmd.append("-A")
        if p.ports:
            cmd.extend(["-p", p.ports])
        if p.scripts:
            cmd.extend(["--script", p.scripts])
        cmd.append(p.target)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout or result.stderr

        open_ports = []
        for line in output.split("\n"):
            m = re.search(r"(\d+)/tcp\s+open", line)
            if m:
                open_ports.append(int(m.group(1)))

        services = []
        for line in output.split("\n"):
            m = re.search(r"(\d+)/tcp\s+open\s+(\S+)\s+(.+)", line)
            if m:
                services.append({"port": int(m.group(1)), "protocol": m.group(2), "service": m.group(3).strip()})

        return NmapResult(output=output, open_ports=open_ports, services=services).model_dump()
