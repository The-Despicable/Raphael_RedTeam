import subprocess
from ...schemas.tools import SubfinderParams, SubfinderResult
from ...core.registry import BaseTool


class Subfinder(BaseTool):
    name = "subfinder"
    description = "Passive subdomain enumeration using subfinder. Discovers subdomains from public sources."

    async def execute(self, params: dict) -> dict:
        p = SubfinderParams(**params)
        cmd = ["subfinder", "-d", p.domain, "-oJ"]
        if p.recursive:
            cmd.append("-recursive")
        if p.sources:
            cmd.extend(["-sources", p.sources])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout or result.stderr

        subdomains = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line:
                subdomains.append(line)

        return SubfinderResult(subdomains=subdomains, raw_output=output).model_dump()
