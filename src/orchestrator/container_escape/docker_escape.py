"""
Docker Container Escape Module (P3 — Container/Sandbox Escape)

Detects and exploits Docker container escape vectors:
  - Docker socket detection and abuse
  - Privileged container detection
  - Capability analysis (CAP_SYS_ADMIN, CAP_NET_RAW, etc.)
  - cgroup escape via release_agent / notify_on_release
  - /proc/1/root namespace escape
  - Mount namespace breakout
  - Container runtime fingerprinting
  - Docker API access via mounted socket

FORGE Rule 3 (import map): stdlib only — no 3rd party deps.
FORGE Rule 4 (subprocess): all binary calls guarded by shutil.which().
"""

from __future__ import annotations

import os
import re
import stat
import json
import time
import socket
import shutil
import struct
import logging
import subprocess
import urllib.request
import urllib.error
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class EscapeTechnique(Enum):
    DOCKER_SOCKET = "docker_socket_abuse"
    PRIVILEGED_MODE = "privileged_mode"
    CAP_SYS_ADMIN = "cap_sys_admin"
    CAP_NET_RAW = "cap_net_raw"
    CGROUP_RELEASE_AGENT = "cgroup_release_agent"
    PROC_1_ROOT = "proc_1_root_ns"
    MOUNT_BREAKOUT = "mount_breakout"
    SYS_PTRACE = "sys_ptrace"
    CAP_DAC_OVERRIDE = "cap_dac_override"
    CAP_SYS_PTRACE = "cap_sys_ptrace"
    NAMESPACE_REMOVAL = "namespace_removal"
    UNKNOWN = "unknown"


class ContainerRuntime(Enum):
    DOCKER = "docker"
    CONTAINERD = "containerd"
    CRIO = "cri-o"
    PODMAN = "podman"
    LXC = "lxc"
    GVISOR = "gvisor"
    UNKNOWN = "unknown"


@dataclass
class EscapeVector:
    """A detected container escape vector."""
    technique: EscapeTechnique
    description: str
    severity: str  # CRITICAL / HIGH / MEDIUM
    evidence: str = ""
    exploitable: bool = False
    command: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "technique": self.technique.value,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence[:200],
            "exploitable": self.exploitable,
            "command": self.command,
            "details": self.details,
        }


@dataclass
class ContainerInfo:
    """Information about the current container environment."""
    inside_container: bool = False
    runtime: ContainerRuntime = ContainerRuntime.UNKNOWN
    container_id: str = ""
    image: str = ""
    privileged: bool = False
    capabilities: list[str] = field(default_factory=list)
    apparmor_profile: str = ""
    seccomp_enabled: bool = False
    seccomp_mode: str = ""
    cgroup_version: int = 1
    cgroup_path: str = ""
    pid_namespace: str = ""
    mount_namespace: str = ""
    user_namespace: str = ""
    uts_namespace: str = ""

    def to_dict(self) -> dict:
        return {
            "inside_container": self.inside_container,
            "runtime": self.runtime.value,
            "container_id": self.container_id,
            "image": self.image,
            "privileged": self.privileged,
            "capabilities": self.capabilities[:20],
            "apparmor_profile": self.apparmor_profile,
            "seccomp_enabled": self.seccomp_enabled,
            "seccomp_mode": self.seccomp_mode,
            "cgroup_version": self.cgroup_version,
            "pid_namespace": self.pid_namespace[:30] if self.pid_namespace else "",
            "mount_namespace": self.mount_namespace[:30] if self.mount_namespace else "",
        }


@dataclass
class EscapeResult:
    """Result of container escape analysis."""
    container_info: ContainerInfo = field(default_factory=ContainerInfo)
    vectors: list[EscapeVector] = field(default_factory=list)
    docker_socket_present: bool = False
    docker_api_accessible: bool = False
    docker_containers: list[dict] = field(default_factory=list)
    host_files_accesssible: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "container_info": self.container_info.to_dict(),
            "vectors_found": len(self.vectors),
            "vectors": [v.to_dict() for v in self.vectors],
            "docker_socket_present": self.docker_socket_present,
            "docker_api_accessible": self.docker_api_accessible,
            "docker_containers": self.docker_containers[:10],
            "host_files_accessible": self.host_files_accesssible[:10],
            "summary": self.summary,
        }


class DockerEscapeScanner:
    """Scans for Docker container escape vectors.

    All scanning is done via stdlib file I/O, socket connections,
    and /proc filesystem introspection. No Docker SDK required.
    Subprocess calls are guarded by shutil.which().
    """

    # Well-known dangerous capabilities in containers
    DANGEROUS_CAPS = {
        "CAP_SYS_ADMIN": "Mount namespaces, access devices, perform admin operations",
        "CAP_NET_ADMIN": "Modify network interfaces, firewall rules",
        "CAP_NET_RAW": "Raw sockets, packet crafting",
        "CAP_SYS_PTRACE": "Ptrace any process, memory manipulation",
        "CAP_SYS_MODULE": "Insert/remove kernel modules",
        "CAP_DAC_OVERRIDE": "Bypass file permission checks",
        "CAP_DAC_READ_SEARCH": "Bypass file read/dir search checks",
        "CAP_SYS_RAWIO": "Raw I/O, port access, memory access",
        "CAP_SYS_BOOT": "Reboot the system",
        "CAP_SYS_CHROOT": "Call chroot()",
        "CAP_KILL": "Send signals to any process",
        "CAP_SETUID": "Manipulate UIDs",
        "CAP_SETGID": "Manipulate GIDs",
        "CAP_SETFCAP": "Set file capabilities",
        "CAP_FOWNER": "Bypass ownership checks on files",
        "CAP_FSETID": "Don't clear setuid/setgid bits on file modification",
        "CAP_SYS_NICE": "Raise/lower process priority",
        "CAP_SYS_RESOURCE": "Override resource limits",
        "CAP_SYS_TIME": "Set system clock",
        "CAP_SYS_TTY_CONFIG": "Configure TTY devices",
        "CAP_LINUX_IMMUTABLE": "Set FS_APPEND_FL/FS_IMMUTABLE_FL on files",
        "CAP_NET_BROADCAST": "Socket broadcast, listen to multicasts",
        "CAP_NET_ADMIN": "Administration of network",
        "CAP_IPC_LOCK": "Lock memory",
        "CAP_IPC_OWNER": "Override IPC ownership checks",
        "CAP_SYS_ADMIN": "Catch-all administrative capability",
    }

    # Docker socket paths to check
    DOCKER_SOCKET_PATHS = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/docker-ce.sock",
        "/run/docker-ce.sock",
        "/var/run/docker/socket",
    ]

    def __init__(self):
        self._cap_cache: Optional[list[str]] = None

    def scan(self) -> EscapeResult:
        """Full container escape scan."""
        result = EscapeResult()

        # Step 1: Detect container environment
        result.container_info = self._detect_container_env()

        # Step 2: Check for Docker socket
        result.docker_socket_present, result.docker_api_accessible, result.docker_containers = self._check_docker_socket()

        # Step 3: Check for privileged mode
        priv_vectors = self._check_privileged(result.container_info)
        result.vectors.extend(priv_vectors)

        # Step 4: Check capabilities
        cap_vectors = self._check_capabilities(result.container_info)
        result.vectors.extend(cap_vectors)

        # Step 5: Check cgroup escape
        cgroup_vectors = self._check_cgroup_escape()
        result.vectors.extend(cgroup_vectors)

        # Step 6: Check /proc/1/root escape
        proc_vectors = self._check_proc_1_root()
        result.vectors.extend(proc_vectors)

        # Step 7: Check mount namespace breakout
        mount_vectors = self._check_mount_breakout()
        result.vectors.extend(mount_vectors)

        # Step 8: Check host file access
        result.host_files_accesssible = self._check_host_files()

        # Build summary
        critical = [v for v in result.vectors if v.severity == "CRITICAL"]
        high = [v for v in result.vectors if v.severity == "HIGH"]

        summary_parts = []
        if critical:
            summary_parts.append(f"{len(critical)} critical vectors")
        if high:
            summary_parts.append(f"{len(high)} high vectors")
        if not critical and not high:
            summary_parts.append("No immediate escape vectors")
        if result.docker_socket_present:
            summary_parts.append("Docker socket accessible")
        if result.host_files_accesssible:
            summary_parts.append(f"{len(result.host_files_accesssible)} host files")

        result.summary = f"Container escape scan: {' | '.join(summary_parts)}"
        return result

    def _detect_container_env(self) -> ContainerInfo:
        """Detect if running inside a container and gather environment info."""
        info = ContainerInfo()

        # Check for .dockerenv file
        if os.path.exists("/.dockerenv"):
            info.inside_container = True
            info.runtime = ContainerRuntime.DOCKER
            info.evidence = "/.dockerenv exists"

        # Check /proc/1/cgroup for container indicators
        cgroup_hints = self._read_file("/proc/1/cgroup")
        if cgroup_hints:
            if "docker" in cgroup_hints.lower():
                info.inside_container = True
                info.runtime = ContainerRuntime.DOCKER
                # Extract container ID
                for line in cgroup_hints.split("\n"):
                    match = re.search(r"docker[=/](\w{64})", line)
                    if match:
                        info.container_id = match.group(1)
                        break
                    match = re.search(r"/(\w{64})\s*$", line)
                    if match:
                        info.container_id = match.group(1)
            elif "kubepods" in cgroup_hints.lower() or "kubepods" in cgroup_hints:
                info.inside_container = True
                info.runtime = ContainerRuntime.CONTAINERD
                # Check for CRI-O
                if "crio" in cgroup_hints.lower() or "crio" in cgroup_hints:
                    info.runtime = ContainerRuntime.CRIO
            elif "lxc" in cgroup_hints.lower():
                info.inside_container = True
                info.runtime = ContainerRuntime.LXC
            elif "gvisor" in cgroup_hints.lower() or ".gvisor" in cgroup_hints:
                info.inside_container = True
                info.runtime = ContainerRuntime.GVISOR

        # Check /proc/1/environ for container hints
        env_data = self._read_file("/proc/1/environ")
        if env_data:
            for env_var in env_data.split("\0"):
                if env_var.startswith("DOCKER_HOST="):
                    info.inside_container = True
                elif env_var.startswith("KUBERNETES_SERVICE_HOST="):
                    info.inside_container = True
                    if info.runtime == ContainerRuntime.UNKNOWN:
                        info.runtime = ContainerRuntime.CONTAINERD

        # Check hostname length (Docker containers often have short hostnames = container ID)
        hostname = self._read_file("/etc/hostname").strip() or socket.gethostname()
        if len(hostname) == 12 and hostname.isalnum():
            info.container_id = hostname
            if not info.inside_container:
                info.inside_container = True
                info.runtime = ContainerRuntime.DOCKER

        # Check cgroup version
        cgroup2_path = "/sys/fs/cgroup/cgroup.controllers"
        if os.path.exists(cgroup2_path):
            info.cgroup_version = 2
            cgroup_self = self._read_file("/proc/self/cgroup")
            if cgroup_self:
                info.cgroup_path = cgroup_self.strip()
        else:
            info.cgroup_version = 1
            cgroup_self = self._read_file("/proc/self/cgroup")
            if cgroup_self:
                for line in cgroup_self.split("\n"):
                    parts = line.split(":")
                    if len(parts) == 3:
                        info.cgroup_path = parts[2]
                        break

        # Check namespaces
        info.pid_namespace = self._read_file("/proc/self/ns/pid")[:40]
        info.mount_namespace = self._read_file("/proc/self/ns/mnt")[:40]
        info.user_namespace = self._read_file("/proc/self/ns/user")[:40]
        info.uts_namespace = self._read_file("/proc/self/ns/uts")[:40]

        # Check privileged mode
        info.privileged = self._check_privileged_mode()

        # Check capabilities
        info.capabilities = self._get_capabilities()

        # Check AppArmor
        apparmor = self._read_file("/proc/self/attr/current")
        if apparmor:
            info.apparmor_profile = apparmor.strip()

        # Check seccomp
        seccomp = self._read_file("/proc/self/seccomp")
        if seccomp:
            info.seccomp_enabled = True
            info.seccomp_mode = seccomp.strip()

        # Check image name if available
        hostname_file = self._read_file("/etc/hostname")
        if hostname_file.strip():
            info.image = hostname_file.strip()

        return info

    def _check_privileged_mode(self) -> bool:
        """Check if container is running in privileged mode."""
        # Check /proc/1/status for CapEff/ CapPrm
        status = self._read_file("/proc/1/status")
        if not status:
            return False

        for line in status.split("\n"):
            # In privileged mode, CapEff has all capabilities set
            if line.startswith("CapEff:"):
                try:
                    cap_eff = int(line.split(":")[1].strip(), 16)
                    # Full capability mask on x86_64 is typically 0x000001FFFFFFFFFF or higher
                    # A fully privileged container will have all bits set
                    full_mask = (1 << 40) - 1  # 40 capabilities as of recent kernels
                    if cap_eff >= full_mask:
                        return True
                except (ValueError, IndexError):
                    pass
            # NoNewPrivs should be 0 for privileged
            if line.startswith("NoNewPrivs:"):
                try:
                    if line.split(":")[1].strip() == "1":
                        return False  # Can't escalate if NoNewPrivs is set
                except IndexError:
                    pass

        return False

    def _get_capabilities(self) -> list[str]:
        """Extract capability set from /proc/self/status."""
        if self._cap_cache:
            return self._cap_cache

        caps = []
        status = self._read_file("/proc/self/status")
        if status:
            for line in status.split("\n"):
                if line.startswith("CapEff:"):
                    try:
                        cap_eff = int(line.split(":")[1].strip(), 16)
                        # Decode capabilities
                        for i in range(40):
                            if cap_eff & (1 << i):
                                cap_name = self._cap_num_to_name(i)
                                if cap_name:
                                    caps.append(cap_name)
                    except (ValueError, IndexError):
                        pass
                    break

        self._cap_cache = caps
        return caps

    def _cap_num_to_name(self, num: int) -> str:
        """Convert capability number to human-readable name."""
        cap_map = {
            0: "CAP_CHOWN",
            1: "CAP_DAC_OVERRIDE",
            2: "CAP_DAC_READ_SEARCH",
            3: "CAP_FOWNER",
            4: "CAP_FSETID",
            5: "CAP_KILL",
            6: "CAP_SETGID",
            7: "CAP_SETUID",
            8: "CAP_SETPCAP",
            9: "CAP_LINUX_IMMUTABLE",
            10: "CAP_NET_BIND_SERVICE",
            11: "CAP_NET_BROADCAST",
            12: "CAP_NET_ADMIN",
            13: "CAP_NET_RAW",
            14: "CAP_IPC_LOCK",
            15: "CAP_IPC_OWNER",
            16: "CAP_SYS_MODULE",
            17: "CAP_SYS_RAWIO",
            18: "CAP_SYS_CHROOT",
            19: "CAP_SYS_PTRACE",
            20: "CAP_SYS_PACCT",
            21: "CAP_SYS_ADMIN",
            22: "CAP_SYS_BOOT",
            23: "CAP_SYS_NICE",
            24: "CAP_SYS_RESOURCE",
            25: "CAP_SYS_TIME",
            26: "CAP_SYS_TTY_CONFIG",
            27: "CAP_MKNOD",
            28: "CAP_LEASE",
            29: "CAP_AUDIT_WRITE",
            30: "CAP_AUDIT_CONTROL",
            31: "CAP_SETFCAP",
            32: "CAP_MAC_OVERRIDE",
            33: "CAP_MAC_ADMIN",
            34: "CAP_SYSLOG",
            35: "CAP_WAKE_ALARM",
            36: "CAP_BLOCK_SUSPEND",
            37: "CAP_AUDIT_READ",
            38: "CAP_PERFMON",
            39: "CAP_BPF",
            40: "CAP_CHECKPOINT_RESTORE",
        }
        return cap_map.get(num, f"CAP_UNKNOWN_{num}")

    def _check_docker_socket(self) -> tuple[bool, bool, list[dict]]:
        """Check for Docker socket and API access."""
        socket_path = None
        for path in self.DOCKER_SOCKET_PATHS:
            if os.path.exists(path):
                try:
                    mode = os.stat(path).st_mode
                    if stat.S_ISSOCK(mode):
                        socket_path = path
                        break
                except OSError:
                    continue

        if not socket_path:
            # Check via environment
            docker_host = os.environ.get("DOCKER_HOST", "")
            if docker_host:
                return True, self._check_docker_api_url(docker_host), []

        # Test Docker API via socket
        accessible = False
        containers = []
        if socket_path:
            accessible, containers = self._query_docker_api_via_socket(socket_path)

        return socket_path is not None, accessible, containers

    def _check_docker_api_url(self, url: str) -> bool:
        """Check Docker API via TCP URL."""
        try:
            req = urllib.request.Request(
                f"{url}/containers/json?all=true",
                headers={"User-Agent": "Raphael/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _query_docker_api_via_socket(self, socket_path: str) -> tuple[bool, list[dict]]:
        """Query Docker API via Unix socket."""
        containers = []
        try:
            # Use urllib with unix socket via HTTP
            import http.client
            # We need to connect via Unix socket
            conn = http.client.HTTPConnection("localhost", timeout=5)
            conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.sock.connect(socket_path)

            conn.request("GET", "/containers/json?all=true",
                         headers={"Host": "localhost", "User-Agent": "Raphael/1.0"})
            resp = conn.getresponse()
            if resp.status == 200:
                data = resp.read()
                containers = json.loads(data)
                return True, containers
            conn.close()
        except Exception as e:
            logger.debug(f"Docker socket query failed: {e}")

        return False, containers

    def _check_privileged(self, info: ContainerInfo) -> list[EscapeVector]:
        """Check for privileged mode related escapes."""
        vectors = []
        if info.privileged:
            vectors.append(EscapeVector(
                technique=EscapeTechnique.PRIVILEGED_MODE,
                description="Container running in privileged mode — full host access",
                severity="CRITICAL",
                evidence="CapEff shows all capabilities or /proc/1/status indicates privileged",
                exploitable=True,
                command="mount -t proc none /proc && cat /proc/1/cmdline",
                details={"privileged": True},
            ))
        return vectors

    def _check_capabilities(self, info: ContainerInfo) -> list[EscapeVector]:
        """Check for dangerous capabilities."""
        vectors = []

        # Check for CAP_SYS_ADMIN
        if "CAP_SYS_ADMIN" in info.capabilities:
            vectors.append(EscapeVector(
                technique=EscapeTechnique.CAP_SYS_ADMIN,
                description="CAP_SYS_ADMIN: can mount cgroup, access namespaces, escape container",
                severity="CRITICAL",
                evidence="CAP_SYS_ADMIN present in CapEff",
                exploitable=True,
                command="mkdir /tmp/cgroup && mount -t cgroup -o memory cgroup /tmp/cgroup && echo 1 > /tmp/cgroup/notify_on_release",
                details={"capability": "CAP_SYS_ADMIN"},
            ))

        # Check for CAP_SYS_PTRACE
        if "CAP_SYS_PTRACE" in info.capabilities:
            vectors.append(EscapeVector(
                technique=EscapeTechnique.SYS_PTRACE,
                description="CAP_SYS_PTRACE: can ptrace any process including host processes",
                severity="HIGH",
                evidence="CAP_SYS_PTRACE present in CapEff",
                exploitable=True,
                command="ptrace to inject into init process",
                details={"capability": "CAP_SYS_PTRACE"},
            ))

        # Check for CAP_DAC_OVERRIDE
        if "CAP_DAC_OVERRIDE" in info.capabilities:
            vectors.append(EscapeVector(
                technique=EscapeTechnique.CAP_DAC_OVERRIDE,
                description="CAP_DAC_OVERRIDE: can bypass file permission checks on host",
                severity="HIGH",
                evidence="CAP_DAC_OVERRIDE present in CapEff",
                exploitable=True,
                command="Access any host file via /proc/1/root",
                details={"capability": "CAP_DAC_OVERRIDE"},
            ))

        # Check for CAP_NET_RAW
        if "CAP_NET_RAW" in info.capabilities:
            vectors.append(EscapeVector(
                technique=EscapeTechnique.CAP_NET_RAW,
                description="CAP_NET_RAW: can craft raw packets for network-based escapes",
                severity="MEDIUM",
                evidence="CAP_NET_RAW present in CapEff",
                exploitable=True,
                command="Raw socket packet crafting for ARP spoofing / network attacks",
                details={"capability": "CAP_NET_RAW"},
            ))

        return vectors

    def _check_cgroup_escape(self) -> list[EscapeVector]:
        """Check for cgroup-based container escape (release_agent)."""
        vectors = []

        if not os.path.exists("/sys/fs/cgroup"):
            return vectors

        # Check if we can write to cgroup release_agent
        try:
            # Try to find writable cgroup directories
            for root, dirs, files in os.walk("/sys/fs/cgroup"):
                for d in dirs[:10]:  # Limit search depth
                    dir_path = os.path.join(root, d)
                    try:
                        if os.access(dir_path, os.W_OK):
                            release_agent = os.path.join(dir_path, "release_agent")
                            if os.path.exists(release_agent) or d == "memory":
                                vectors.append(EscapeVector(
                                    technique=EscapeTechnique.CGROUP_RELEASE_AGENT,
                                    description=f"Cgroup escape via writable cgroup: {dir_path}",
                                    severity="CRITICAL",
                                    evidence=f"Write access to {dir_path}/release_agent",
                                    exploitable=True,
                                    command=f"echo '/path/to/payload' > {dir_path}/release_agent",
                                    details={"cgroup_path": dir_path},
                                ))
                                break
                    except (PermissionError, OSError):
                        continue
                if vectors:
                    break
        except Exception as e:
            logger.debug(f"Cgroup escape check failed: {e}")

        return vectors

    def _check_proc_1_root(self) -> list[EscapeVector]:
        """Check for /proc/1/root based escape."""
        vectors = []

        proc_root = "/proc/1/root"
        try:
            if os.path.exists(proc_root):
                # Check if we can read host files
                test_path = os.path.join(proc_root, "etc", "passwd")
                if os.access(test_path, os.R_OK):
                    vectors.append(EscapeVector(
                        technique=EscapeTechnique.PROC_1_ROOT,
                        description="/proc/1/root accessible — host filesystem visible",
                        severity="CRITICAL",
                        evidence=f"Can read host /etc/passwd via {proc_root}/etc/passwd",
                        exploitable=True,
                        command="ls -la /proc/1/root/",
                        details={"proc_root_path": proc_root},
                    ))
        except Exception as e:
            logger.debug(f"/proc/1/root check failed: {e}")

        return vectors

    def _check_mount_breakout(self) -> list[EscapeVector]:
        """Check for mount-based container escape."""
        vectors = []

        mounts = self._read_file("/proc/1/mountinfo")
        if not mounts:
            return vectors

        # Check for suspicious mounts
        suspicious_patterns = [
            r"/dev/sd[a-z]",
            r"/dev/nvme\d+n\d+",
            r"/dev/xvd[a-z]",
            r"/var/lib/docker",
            r"/var/lib/kubelet",
            r"/var/lib/containerd",
            r"/host",
            r"/data",
        ]

        for line in mounts.split("\n"):
            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vectors.append(EscapeVector(
                        technique=EscapeTechnique.MOUNT_BREAKOUT,
                        description=f"Host mount detected: {line[:120]}",
                        severity="HIGH",
                        evidence=f"Mount info: {line[:200]}",
                        exploitable=True,
                        command=f"cd {line.split()[-1] if line.split() else '/mnt'} && ls -la",
                        details={"mount_line": line[:200]},
                    ))
                    break

        return vectors

    def _check_host_files(self) -> list[str]:
        """Check for accessible host files via /proc/1/root."""
        accessible = []
        host_paths = [
            "/proc/1/root/etc/shadow",
            "/proc/1/root/root/.ssh/id_rsa",
            "/proc/1/root/root/.ssh/authorized_keys",
            "/proc/1/root/etc/kubernetes/pki/ca.crt",
            "/proc/1/root/etc/kubernetes/pki/apiserver.crt",
            "/proc/1/root/etc/environment",
            "/proc/1/root/var/run/secrets/kubernetes.io/serviceaccount/token",
        ]

        for path in host_paths:
            try:
                if os.access(path, os.R_OK):
                    accessible.append(path)
            except OSError:
                continue

        return accessible

    def _read_file(self, path: str) -> str:
        """Read a file, returning '' on any error."""
        try:
            with open(path, "r", errors="replace") as f:
                return f.read(4096)
        except (FileNotFoundError, PermissionError, OSError):
            return ""


def scan_container_escape() -> dict:
    """Convenience function to scan for Docker container escapes."""
    scanner = DockerEscapeScanner()
    result = scanner.scan()
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    result = scan_container_escape()
    print(json.dumps(result, indent=2, default=str))
