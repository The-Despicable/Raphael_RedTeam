import subprocess
import json
from ...schemas.tools import GobusterParams, GobusterResult
from ...core.registry import BaseTool


class Gobuster(BaseTool):
    name = "gobuster"
    description = "Directory/file enumeration using gobuster. Brute-forces directories and files on web servers."

    async def execute(self, params: dict) -> dict:
        p = GobusterParams(**params)
        cmd = ["gobuster", p.mode, "-u", p.url, "-w", p.wordlist, "-q", "-o", "/dev/stdout"]
        if p.extensions:
            cmd.extend(["-x", p.extensions])
        cmd.extend(["-t", str(p.threads)])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout or result.stderr

        entries = []
        for line in output.split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                entries.append({"path": parts[0], "status": parts[1] if len(parts) > 1 else ""})

        return GobusterResult(entries=entries, raw_output=output).model_dump()
