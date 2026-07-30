import re

from orchestrator.kali_tools_client import kali


class MasscanWrapper:
    def __init__(self, rate: int = 10000):
        self._rate = rate

    async def scan(self, target: str, ports: str = "1-10000", timeout: int = 120) -> dict:
        ip = target.split(":")[0]
        args = f"{ip} -p{ports} --rate={self._rate} -oJ - 2>/dev/null"
        result = await kali.run("masscan", args, timeout=timeout)
        stdout = (result.get("stdout") or "")
        ports_found = []
        try:
            import json
            lines = stdout.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line.endswith(","):
                    line = line[:-1]
                try:
                    entry = json.loads(line)
                    ports_found.append({
                        "port": entry.get("ports", [{}])[0].get("port", 0),
                        "protocol": entry.get("ports", [{}])[0].get("proto", "tcp"),
                        "state": "open",
                    })
                except json.JSONDecodeError:
                    m = re.search(r'port (\d+)/(\w+)', line)
                    if m:
                        ports_found.append({"port": int(m.group(1)), "protocol": m.group(2), "state": "open"})
        except Exception:
            pass
        return {
            "success": True,
            "ports": ports_found,
            "port_count": len(ports_found),
            "raw": stdout[:3000],
        }
