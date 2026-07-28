import subprocess
from ...core.registry import BaseTool


class Volatility(BaseTool):
    name = "volatility"
    description = "Memory forensics using Volatility 3. Analyze memory dumps for processes, network connections, and artifacts."

    async def execute(self, params: dict) -> dict:
        dump_path = params.get("dump_path", "")
        plugin = params.get("plugin", "windows.pslist")
        output_format = params.get("format", "json")

        if not dump_path:
            return {"error": "dump_path parameter required"}

        cmd = ["vol", "-f", dump_path, plugin]
        if output_format:
            cmd.extend(["--output", output_format])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout or result.stderr

        return {"dump": dump_path, "plugin": plugin, "raw_output": output}


class ExifTool(BaseTool):
    name = "exiftool"
    description = "Extract metadata from files using ExifTool."

    async def execute(self, params: dict) -> dict:
        file_path = params.get("file_path", "")
        if not file_path:
            return {"error": "file_path parameter required"}

        cmd = ["exiftool", "-json", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout or result.stderr

        import json
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"raw": output}

        return {"file": file_path, "metadata": data}
