import subprocess
import json
from ...schemas.tools import SQLMapParams, SQLMapResult
from ...core.registry import BaseTool


class Sqlmap(BaseTool):
    name = "sqlmap"
    description = "SQL injection detection and exploitation using sqlmap. Automates detection and exploitation of SQLi flaws."

    async def execute(self, params: dict) -> dict:
        p = SQLMapParams(**params)
        cmd = ["sqlmap", "-u", p.url, "--batch", "--random-agent", "--output-dir=/tmp/sqlmap_out"]
        if p.level:
            cmd.extend(["--level", str(p.level)])
        if p.risk:
            cmd.extend(["--risk", str(p.risk)])
        if p.dbms:
            cmd.extend(["--dbms", p.dbms])
        if p.crawl:
            cmd.extend(["--crawl", str(p.crawl)])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout or result.stderr

        return SQLMapResult(vulnerabilities=[], raw_output=output).model_dump()
