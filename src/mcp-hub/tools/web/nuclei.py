import subprocess
import json
from ...schemas.tools import NucleiParams, NucleiResult
from ...core.registry import BaseTool


class Nuclei(BaseTool):
    name = "nuclei"
    description = "Vulnerability scanner using nuclei templates. Scans targets with 4000+ vulnerability templates."

    async def execute(self, params: dict) -> dict:
        p = NucleiParams(**params)
        cmd = ["nuclei", "-u", p.target, "-json"]
        if p.severity:
            cmd.extend(["-severity", p.severity])
        if p.tags:
            cmd.extend(["-tags", p.tags])
        if p.template:
            cmd.extend(["-t", p.template])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout or result.stderr

        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line.startswith("{"):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        return NucleiResult(findings=findings, raw_output=output).model_dump()
