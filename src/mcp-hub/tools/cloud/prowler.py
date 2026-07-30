import subprocess
from ...core.registry import BaseTool


class Prowler(BaseTool):
    name = "prowler"
    description = "Cloud security assessment using Prowler. Audits AWS/Azure/GCP configurations against CIS benchmarks."

    async def execute(self, params: dict) -> dict:
        provider = params.get("provider", "aws")
        profile = params.get("profile", "default")
        checks = params.get("checks", "")
        output_format = params.get("output_format", "json")
        output_dir = params.get("output_dir", "/tmp/prowler_output")

        cmd = ["prowler", provider, "--profile", profile, "-M", output_format, "-o", output_dir]
        if checks:
            cmd.extend(["--checks", checks])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout or result.stderr

        return {"provider": provider, "profile": profile, "raw_output": output}


class Trivy(BaseTool):
    name = "trivy"
    description = "Container and filesystem vulnerability scanner using Trivy."

    async def execute(self, params: dict) -> dict:
        target = params.get("target", "")
        scan_type = params.get("scan_type", "image")
        severity = params.get("severity", "CRITICAL,HIGH")
        output_format = params.get("format", "json")

        cmd = ["trivy", scan_type, "--severity", severity, "--format", output_format, "--output", "/tmp/trivy_output.json", target]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        import json
        try:
            with open("/tmp/trivy_output.json") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            data = {}

        return {"target": target, "scan_type": scan_type, "findings": data, "raw_output": result.stdout or result.stderr}
