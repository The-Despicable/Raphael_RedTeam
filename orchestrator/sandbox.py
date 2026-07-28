import subprocess
import tempfile
import logging
from pathlib import Path

logger = logging.getLogger("sandbox")


class PatchSandbox:
    def __init__(self) -> None:
        self.running = False

    async def validate_syntax(self, code: str) -> tuple[bool, str]:
        try:
            compile(code, "<sandbox>", "exec")
            return True, ""
        except SyntaxError as e:
            return False, str(e)

    async def run_code(self, code: str, timeout: int = 30) -> dict:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            tmppath = f.name
        try:
            r = subprocess.run(
                ["python3", tmppath],
                capture_output=True, timeout=timeout, text=True,
            )
            return {
                "stdout": r.stdout,
                "stderr": r.stderr,
                "exit_code": r.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "timeout", "exit_code": -1}
        except FileNotFoundError:
            return {"stdout": "", "stderr": "python3 not found", "exit_code": -1}
        finally:
            Path(tmppath).unlink(missing_ok=True)


sandbox = PatchSandbox()
