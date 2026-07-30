import json, os, re

KALI_TOOLS_URL = os.getenv("KALI_TOOLS_URL", "http://localhost:3800")


def _escape_header_value(val: str) -> str:
    """Remove characters that would break args parsing in the kali-tools API."""
    return re.sub(r"[^\w:/.\-@ ]", "", val).strip()


class NucleiScanner:
    def __init__(self, default_templates: list = None):
        self.default_templates = default_templates or ["/root/nuclei-templates/http/technologies/"]

    @property
    def available(self) -> bool:
        return True

    async def scan(self, target: str, templates: list = None,
                   severity: str = None, rate_limit: int = 50,
                   headers: dict = None) -> dict:
        template_args = " ".join(f"-t {t}" for t in (templates or self.default_templates))
        args = f"-u {target} -j -silent -rate-limit {rate_limit} {template_args}"

        if headers:
            for key, val in headers.items():
                safe_val = _escape_header_value(val)
                args += f" -H {key}:{safe_val}"

        if severity:
            args += f" -severity {severity}"

        try:
            import httpx
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{KALI_TOOLS_URL}/run",
                    params={"tool": "nuclei", "args": args, "timeout": 100},
                )
            result = resp.json()
            if result.get("returncode") != 0:
                stderr = result.get("stderr", "")
                if "no results" in stderr.lower() or len(result.get("stdout", "")) > 0:
                    pass
                else:
                    return {"error": stderr[:500], "target": target}

            findings = []
            for line in result["stdout"].strip().split("\n"):
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return {
                "target": target,
                "findings": findings,
                "findings_count": len(findings),
            }
        except Exception as e:
            return {"error": str(e), "target": target}
