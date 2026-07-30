import subprocess, asyncio

class Executor:
    @staticmethod
    async def run(command: str, timeout: int = 30) -> dict:
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.PIPE,
                stderr=asyncio.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
                "code": proc.returncode,
            }
        except asyncio.TimeoutError:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)}
