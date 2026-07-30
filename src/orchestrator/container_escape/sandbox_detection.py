"""
Sandbox Detection Module (P3 — Container/Sandbox Escape)

Detects and analyzes container sandbox environments:
  - gVisor (runsc) detection via procfs, device, and behavioral checks
  - runc / crun container runtime detection
  - AppArmor profile detection and analysis
  - SELinux status and policy detection
  - Seccomp filter detection and analysis
  - Capability bounding set analysis
  - User namespace isolation detection
  - Container runtime fingerprinting (Docker, containerd, CRI-O, Podman)
  - Unshare / namespace creation capability

FORGE Rule 3 (import map): stdlib only.
FORGE Rule 4 (subprocess): all binary calls guarded by shutil.which().
"""

from __future__ import annotations

import os
import re
import json
import stat
import shutil
import logging
import subprocess
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SandboxType(Enum):
    GVISOR = "gvisor"
    RUNSC = "runsc"
    KATA = "kata_containers"
    FIREJAIL = "firejail"
    BUBBLEWRAP = "bubblewrap"
    DOCKER = "docker"
    PODMAN = "podman"
    NONE = "none_detected"
    UNKNOWN = "unknown"


class LSMType(Enum):
    APPARMOR = "apparmor"
    SELINUX = "selinux"
    NONE = "none"
    UNKNOWN = "unknown"


class SeccompMode(Enum):
    STRICT = "strict"
    FILTER = "filter"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


@dataclass
class SandboxInfo:
    """Information about detected sandbox environment."""
    sandbox_type: SandboxType = SandboxType.UNKNOWN
    runtime_binary: str = ""
    runtime_version: str = ""
    confidence: float = 0.0  # 0.0 - 1.0

    def to_dict(self) -> dict:
        return {
            "sandbox_type": self.sandbox_type.value,
            "runtime_binary": self.runtime_binary,
            "runtime_version": self.runtime_version,
            "confidence": self.confidence,
        }


@dataclass
class LSMAnalysis:
    """Linux Security Module analysis result."""
    lsm_type: LSMType = LSMType.UNKNOWN
    enabled: bool = False
    profile: str = ""
    profile_mode: str = ""  # enforcing / permissive / complain
    loaded_policies: list[str] = field(default_factory=list)
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "lsm_type": self.lsm_type.value,
            "enabled": self.enabled,
            "profile": self.profile,
            "profile_mode": self.profile_mode,
            "loaded_policies": self.loaded_policies[:10],
        }


@dataclass
class SeccompAnalysis:
    """Seccomp filter analysis result."""
    mode: SeccompMode = SeccompMode.UNKNOWN
    enabled: bool = False
    filter_count: int = 0
    default_action: str = ""  # ALLOW / KILL / TRAP / ERRNO / TRACE / LOG
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "enabled": self.enabled,
            "filter_count": self.filter_count,
            "default_action": self.default_action,
        }


@dataclass
class NamespaceInfo:
    """Namespace isolation analysis."""
    pid_ns: str = ""
    mnt_ns: str = ""
    net_ns: str = ""
    user_ns: str = ""
    uts_ns: str = ""
    ipc_ns: str = ""
    cgroup_ns: str = ""
    time_ns: str = ""
    shared: list[str] = field(default_factory=list)  # Namespaces shared with host
    isolated: list[str] = field(default_factory=list)  # Namespaces properly isolated

    def to_dict(self) -> dict:
        return {
            "shared_with_host": self.shared,
            "isolated": self.isolated,
            "total_isolated": len(self.isolated),
            "total_shared": len(self.shared),
        }


@dataclass
class SandboxDetectionResult:
    """Result of sandbox detection analysis."""
    sandbox: SandboxInfo = field(default_factory=SandboxInfo)
    lsm: LSMAnalysis = field(default_factory=LSMAnalysis)
    seccomp: SeccompAnalysis = field(default_factory=SeccompAnalysis)
    namespaces: NamespaceInfo = field(default_factory=NamespaceInfo)
    escape_potential: bool = False
    escape_paths: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "sandbox": self.sandbox.to_dict(),
            "lsm": self.lsm.to_dict(),
            "seccomp": self.seccomp.to_dict(),
            "namespaces": self.namespaces.to_dict(),
            "escape_potential": self.escape_potential,
            "escape_paths": self.escape_paths[:10],
            "summary": self.summary,
        }


class SandboxDetector:
    """Detects and analyzes container sandbox environments.

    Uses multiple techniques to fingerprint the sandbox/container runtime:
    - Device file inspection (/dev)
    - /proc filesystem introspection
    - Binary detection in $PATH
    - Kernel module checks
    - Capability and LSM analysis
    """

    # Known gVisor indicators in /proc
    GVISOR_PROC_INDICATORS = {
        "/proc/sys/kernel/hostname": "gVisor",  # gVisor returns empty hostname
        "/proc/version": "gVisor",  # gVisor has synthetic /proc/version
        "/proc/self/maps": "",  # gVisor has no /proc/self/maps
    }

    # Sandbox runtime binaries to check
    SANDBOX_BINARIES: dict[str, SandboxType] = {
        "runsc": SandboxType.RUNSC,
        "kata-runtime": SandboxType.KATA,
        "firejail": SandboxType.FIREJAIL,
        "bwrap": SandboxType.BUBBLEWRAP,
    }

    # Container runtime binaries
    CONTAINER_RUNTIME_BINARIES: dict[str, SandboxType] = {
        "docker": SandboxType.DOCKER,
        "podman": SandboxType.PODMAN,
        "containerd": SandboxType.DOCKER,
        "crio": SandboxType.DOCKER,
    }

    def __init__(self):
        self._proc_version: str = ""
        self._proc_self_maps: str = ""

    def detect(self) -> SandboxDetectionResult:
        """Full sandbox detection and analysis."""
        result = SandboxDetectionResult()

        # Step 1: Detect sandbox type
        result.sandbox = self._detect_sandbox_type()

        # Step 2: Analyze LSM (AppArmor / SELinux)
        result.lsm = self._analyze_lsm()

        # Step 3: Analyze seccomp
        result.seccomp = self._analyze_seccomp()

        # Step 4: Analyze namespace isolation
        result.namespaces = self._analyze_namespaces()

        # Step 5: Assess escape potential
        result.escape_potential, result.escape_paths = self._assess_escape_potential(
            result.sandbox, result.lsm, result.seccomp, result.namespaces
        )

        # Build summary
        summary_parts = []
        summary_parts.append(f"Sandbox: {result.sandbox.sandbox_type.value} (conf: {result.sandbox.confidence:.0%})")
        if result.lsm.enabled:
            summary_parts.append(f"{result.lsm.lsm_type.value}: {result.lsm.profile_mode}")
        if result.seccomp.enabled:
            summary_parts.append(f"seccomp: {result.seccomp.mode.value}")
        ns_shared = len(result.namespaces.shared)
        if ns_shared > 0:
            summary_parts.append(f"{ns_shared} ns shared with host")
        if result.escape_potential:
            summary_parts.append("Escape possible!")
        else:
            summary_parts.append("No escape detected")

        result.summary = f"Sandbox detection: {' | '.join(summary_parts)}"
        return result

    def _detect_sandbox_type(self) -> SandboxInfo:
        """Detect sandbox/container runtime type using multiple techniques."""
        info = SandboxInfo()

        # Technique 1: Check for sandbox runtime binaries in $PATH
        for binary, sandbox_type in self.SANDBOX_BINARIES.items():
            bin_path = shutil.which(binary)
            if bin_path:
                info.sandbox_type = sandbox_type
                info.runtime_binary = bin_path
                info.confidence = max(info.confidence, 0.9)
                info.runtime_version = self._get_binary_version(binary)
                return info  # High confidence match

        # Technique 2: Check for container runtime binaries
        for binary, container_type in self.CONTAINER_RUNTIME_BINARIES.items():
            bin_path = shutil.which(binary)
            if bin_path:
                info.sandbox_type = container_type
                info.runtime_binary = bin_path
                info.confidence = 0.8
                info.runtime_version = self._get_binary_version(binary)
                break

        # Technique 3: Check /proc/version for gVisor indicators
        proc_version = self._read_file("/proc/version")
        if proc_version:
            gvisor_patterns = [
                r"gVisor",
                r"runsc",
                r"GNU/Linux.*gVisor",
            ]
            for pattern in gvisor_patterns:
                if re.search(pattern, proc_version, re.IGNORECASE):
                    info.sandbox_type = SandboxType.GVISOR
                    info.confidence = 0.95
                    return info

        # Technique 4: Check for gVisor sentry process
        proc_self_status = self._read_file("/proc/self/status")
        if proc_self_status and "gVisor" in proc_self_status:
            info.sandbox_type = SandboxType.GVISOR
            info.confidence = 0.9
            return info

        # Technique 5: Check /dev for gVisor indicators
        dev_entries = self._list_dir("/dev")
        if dev_entries:
            # gVisor has limited /dev (usually just null, zero, random, urandom)
            gvisor_dev = {"null", "zero", "random", "urandom", "fd", "stdin", "stdout", "stderr"}
            actual_dev = set(dev_entries)
            # If /dev has very few entries and matches gVisor pattern
            if len(actual_dev - gvisor_dev) <= 2 and len(actual_dev) <= 12:
                # Could be gVisor, but low confidence without other indicators
                if info.confidence == 0.0:
                    info.sandbox_type = SandboxType.GVISOR
                    info.confidence = 0.5

        # Technique 6: Check /proc/1/cmdline for runtime
        cmdline = self._read_file("/proc/1/cmdline")
        if cmdline:
            runtime_patterns = {
                "docker": SandboxType.DOCKER,
                "containerd": SandboxType.DOCKER,
                "podman": SandboxType.PODMAN,
                "runsc": SandboxType.RUNSC,
                "kata": SandboxType.KATA,
                "lxc": SandboxType.DOCKER,
                "crio": SandboxType.DOCKER,
            }
            for pattern, stype in runtime_patterns.items():
                if pattern in cmdline.lower():
                    if info.confidence < 0.8:
                        info.sandbox_type = stype
                        info.confidence = 0.7
                    break

        # Technique 7: Check cgroup for runtime hints
        cgroup = self._read_file("/proc/1/cgroup")
        if cgroup:
            if "gvisor" in cgroup.lower() or "runsc" in cgroup.lower():
                info.sandbox_type = SandboxType.GVISOR
                info.confidence = 0.85

        # Technique 8: Check for kata-containers
        if os.path.exists("/dev/vport1p1") or os.path.exists("/dev/port"):
            info.sandbox_type = SandboxType.KATA
            info.confidence = 0.7

        if info.confidence == 0.0:
            info.sandbox_type = SandboxType.NONE
            info.confidence = 1.0

        return info

    def _get_binary_version(self, binary: str) -> str:
        """Get version string from a binary."""
        try:
            result = subprocess.run(
                [binary, "--version"],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0:
                return result.stdout.strip()[:100]
        except Exception:
            pass
        return ""

    def _analyze_lsm(self) -> LSMAnalysis:
        """Analyze Linux Security Module (AppArmor/SELinux) status."""
        analysis = LSMAnalysis()

        # Check AppArmor
        apparmor_path = "/sys/kernel/security/apparmor"
        if os.path.exists(apparmor_path):
            analysis.lsm_type = LSMType.APPARMOR
            analysis.enabled = True

            # Read current profile
            current = self._read_file("/proc/self/attr/current")
            if current:
                analysis.profile = current.strip()
                if "complain" in current.lower():
                    analysis.profile_mode = "complain"
                elif "enforce" in current.lower():
                    analysis.profile_mode = "enforcing"
                elif "unconfined" in current.lower():
                    analysis.profile_mode = "unconfined"
                else:
                    analysis.profile_mode = "unknown"

            # List loaded policies
            profiles_path = os.path.join(apparmor_path, "profiles")
            if os.path.exists(profiles_path):
                profiles_content = self._read_file(profiles_path)
                if profiles_content:
                    for line in profiles_content.split("\n"):
                        line = line.strip()
                        if line and not line.startswith("("):
                            analysis.loaded_policies.append(line.split()[0] if " " in line else line)

            analysis.details = f"AppArmor {'enabled' if analysis.enabled else 'disabled'}, profile: {analysis.profile}"

        # Check SELinux
        selinux_path = "/sys/fs/selinux"
        if os.path.exists(selinux_path) or os.path.exists("/etc/selinux/config"):
            analysis.lsm_type = LSMType.SELINUX
            analysis.enabled = True

            # Read current context
            current = self._read_file("/proc/self/attr/current")
            if current:
                analysis.profile = current.strip()

            # Check enforcing mode
            enforce_path = os.path.join(selinux_path, "enforce")
            if os.path.exists(enforce_path):
                enforce_val = self._read_file(enforce_path).strip()
                analysis.profile_mode = "enforcing" if enforce_val == "1" else "permissive"

            analysis.details = f"SELinux {'enabled' if analysis.enabled else 'disabled'}, context: {analysis.profile}"

        # Check if LSM is disabled
        if not analysis.enabled:
            # Check /proc/self/attr/current for "unconfined"
            current = self._read_file("/proc/self/attr/current")
            if current and "unconfined" in current.lower():
                analysis.lsm_type = LSMType.NONE
                analysis.profile = "unconfined"
                analysis.profile_mode = "disabled"

        return analysis

    def _analyze_seccomp(self) -> SeccompAnalysis:
        """Analyze seccomp filter status."""
        analysis = SeccompAnalysis()

        # Check /proc/self/seccomp
        seccomp_data = self._read_file("/proc/self/seccomp")
        if seccomp_data and seccomp_data.strip():
            analysis.enabled = True
            mode_num = seccomp_data.strip()
            if mode_num == "0":
                analysis.mode = SeccompMode.DISABLED
                analysis.enabled = False
            elif mode_num == "1":
                analysis.mode = SeccompMode.STRICT
            elif mode_num == "2":
                analysis.mode = SeccompMode.FILTER
            else:
                analysis.mode = SeccompMode.UNKNOWN

        # Check /proc/self/status for Seccomp line
        status = self._read_file("/proc/self/status")
        if status:
            for line in status.split("\n"):
                if line.startswith("Seccomp:"):
                    try:
                        val = int(line.split(":")[1].strip())
                        analysis.enabled = val > 0
                        if val == 1:
                            analysis.mode = SeccompMode.STRICT
                        elif val == 2:
                            analysis.mode = SeccompMode.FILTER
                    except (ValueError, IndexError):
                        pass
                if line.startswith("Seccomp_filters:"):
                    try:
                        analysis.filter_count = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass

        # Try to determine default action via seccomp sysfs
        seccomp_actions = self._read_file("/proc/sys/kernel/seccomp/actions_avail")
        if seccomp_actions:
            analysis.details = f"Available seccomp actions: {seccomp_actions.strip()}"

        return analysis

    def _analyze_namespaces(self) -> NamespaceInfo:
        """Analyze namespace isolation."""
        ns_info = NamespaceInfo()

        # Read namespace IDs
        ns_types = {
            "pid": "pid_ns",
            "mnt": "mnt_ns",
            "net": "net_ns",
            "user": "user_ns",
            "uts": "uts_ns",
            "ipc": "ipc_ns",
            "cgroup": "cgroup_ns",
            "time": "time_ns",
        }

        # Check /proc/self/ns for each namespace type
        for ns_type, attr_name in ns_types.items():
            ns_path = f"/proc/self/ns/{ns_type}"
            ns_val = self._read_link(ns_path)
            if ns_val:
                setattr(ns_info, attr_name, ns_val)

        # Determine which namespaces are shared with host
        # by checking /proc/1/ns and comparing to /proc/self/ns
        for ns_type, attr_name in ns_types.items():
            self_ns = self._read_link(f"/proc/self/ns/{ns_type}")
            host_ns = self._read_link(f"/proc/1/ns/{ns_type}")
            if self_ns and host_ns:
                if self_ns == host_ns:
                    ns_info.shared.append(ns_type)
                else:
                    ns_info.isolated.append(ns_type)

        # Check user namespace (unshared user ns = likely sandboxed)
        if ns_info.user_ns:
            try:
                uid_map = self._read_file("/proc/self/uid_map")
                gid_map = self._read_file("/proc/self/gid_map")
                if uid_map and "0 0 1" in uid_map:
                    ns_info.isolated.append("user_mapped")
            except Exception:
                pass

        return ns_info

    def _assess_escape_potential(self, sandbox: SandboxInfo, lsm: LSMAnalysis,
                                   seccomp: SeccompAnalysis, ns: NamespaceInfo) -> tuple[bool, list[str]]:
        """Assess potential for sandbox escape."""
        escape_paths = []

        # gVisor escape potential
        if sandbox.sandbox_type == SandboxType.GVISOR:
            # gVisor escapes are rare but known CVEs exist
            if not seccomp.enabled or seccomp.mode == SeccompMode.DISABLED:
                escape_paths.append("gVisor without seccomp — CVE-2019-5736 variant possible")

        # Shared PID namespace
        if "pid" in ns.shared:
            escape_paths.append("Shared PID namespace — can see host processes")

        # Shared mount namespace with writable /proc/1/root
        if "mnt" in ns.shared:
            if os.access("/proc/1/root", os.R_OK | os.X_OK):
                escape_paths.append("Shared mount namespace + /proc/1/root accessible — host filesystem access")

        # User namespace escape
        if "user" in ns.isolated and "mnt" not in ns.isolated:
            escape_paths.append("User namespace present but mount namespace shared — potential root on host")

        # No AppArmor/SELinux
        if not lsm.enabled:
            escape_paths.append("No MAC/LSM enforcement — reduced escape difficulty")

        # Seccomp disabled
        if not seccomp.enabled:
            escape_paths.append("Seccomp disabled — all syscalls available")

        # Seccomp strict mode (ironically, strict seccomp can be bypassed)
        if seccomp.mode == SeccompMode.STRICT:
            escape_paths.append("Strict seccomp — limited syscalls but known bypass techniques exist")

        return len(escape_paths) > 0, escape_paths

    def _read_file(self, path: str) -> str:
        """Read a file, returning '' on any error."""
        try:
            with open(path, "r", errors="replace") as f:
                return f.read(4096).strip()
        except (FileNotFoundError, PermissionError, OSError):
            return ""

    def _read_link(self, path: str) -> str:
        """Read a symlink target, returning '' on any error."""
        try:
            return os.readlink(path)
        except (FileNotFoundError, PermissionError, OSError):
            return ""

    def _list_dir(self, path: str) -> list[str]:
        """List directory contents, returning [] on any error."""
        try:
            return os.listdir(path)
        except (FileNotFoundError, PermissionError, OSError):
            return []


def detect_sandbox() -> dict:
    """Convenience function to detect sandbox environment."""
    detector = SandboxDetector()
    result = detector.detect()
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    result = detect_sandbox()
    print(json.dumps(result, indent=2, default=str))
