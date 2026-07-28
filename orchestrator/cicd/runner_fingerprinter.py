"""
CI/CD Runner Fingerprinter (P0 - FORGE Phase 0)

Detects and fingerprints CI/CD runners:
- GitHub-hosted vs self-hosted runners
- Runner OS, architecture, and version
- Runner labels and capabilities
- Network posture (public vs private subnet)
"""

from __future__ import annotations

import re
import os
import json
import socket
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class RunnerPlatform(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"


class RunnerArchitecture(Enum):
    X86_64 = "x86_64"
    ARM64 = "arm64"
    X86 = "x86"
    UNKNOWN = "unknown"


class RunnerHealth(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass
class RunnerInfo:
    """Fingerprinted information about a CI/CD runner."""
    hostname: str
    platform: RunnerPlatform = RunnerPlatform.UNKNOWN
    architecture: RunnerArchitecture = RunnerArchitecture.UNKNOWN
    os_version: str = ""
    kernel_version: str = ""
    cpu_count: int = 0
    total_memory_mb: int = 0
    is_container: bool = False
    is_vm: bool = False
    docker_version: str = ""
    has_nvidia_gpu: bool = False
    has_docker: bool = False
    has_kubectl: bool = False
    has_aws_cli: bool = False
    has_gcloud_cli: bool = False
    has_azure_cli: bool = False
    public_ip: str = ""
    private_ips: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    ci_provider: str = ""
    runner_version: str = ""
    health: RunnerHealth = RunnerHealth.UNKNOWN
    raw_info: dict = field(default_factory=dict)

    def is_self_hosted(self) -> bool:
        """Self-hosted runners typically lack 'Hosted' in provider and may have custom labels."""
        return "self-hosted" in self.labels or not self.ci_provider

    def has_network_isolation(self) -> bool:
        """Check if runner appears to be in a private network."""
        if not self.private_ips:
            return True  # No private IP detected — likely sandboxed
        for ip in self.private_ips:
            parts = ip.split(".")
            if len(parts) == 4:
                if parts[0] in ("10", "172", "192"):
                    return True
        return False

    def can_egress(self) -> bool:
        """Check if runner appears to have outbound network access."""
        return bool(self.public_ip)

    def to_dict(self) -> dict:
        d = {
            "hostname": self.hostname,
            "platform": self.platform.value,
            "architecture": self.architecture.value,
            "os_version": self.os_version,
            "kernel_version": self.kernel_version,
            "cpu_count": self.cpu_count,
            "total_memory_mb": self.total_memory_mb,
            "is_container": self.is_container,
            "is_vm": self.is_vm,
            "docker_version": self.docker_version,
            "has_nvidia_gpu": self.has_nvidia_gpu,
            "has_docker": self.has_docker,
            "has_kubectl": self.has_kubectl,
            "has_aws_cli": self.has_aws_cli,
            "has_gcloud_cli": self.has_gcloud_cli,
            "has_azure_cli": self.has_azure_cli,
            "public_ip": self.public_ip,
            "private_ips": self.private_ips,
            "labels": self.labels,
            "ci_provider": self.ci_provider,
            "runner_version": self.runner_version,
            "health": self.health.value,
        }
        return d


@dataclass
class RunnerFingerprintResult:
    """Aggregated fingerprinting result."""
    runner_info: RunnerInfo
    detected_env_vars: dict = field(default_factory=dict)
    detected_services: list[str] = field(default_factory=list)
    detected_credentials: list[str] = field(default_factory=list)
    attack_surface: dict = field(default_factory=dict)
    risk_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "runner_info": self.runner_info.to_dict(),
            "detected_env_vars": self.detected_env_vars,
            "detected_services": self.detected_services,
            "detected_credentials": self.detected_credentials,
            "attack_surface": self.attack_surface,
            "risk_score": self.risk_score,
        }


class RunnerFingerprinter:
    """Fingerprints CI/CD runners via environment inspection, API queries, and network probes."""

    # CI environment variable signatures
    CI_ENV_SIGNATURES = {
        "github_actions": {
            "GITHUB_ACTIONS": "true",
            "GITHUB_RUNNER_NAME": None,
            "RUNNER_NAME": None,
            "GITHUB_REPOSITORY": None,
        },
        "gitlab_ci": {
            "GITLAB_CI": "true",
            "CI_RUNNER_ID": None,
            "CI_RUNNER_DESCRIPTION": None,
        },
        "azure_pipelines": {
            "AZURE_HTTP_USER_AGENT": None,
            "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": None,
            "AGENT_NAME": None,
        },
        "jenkins": {
            "JENKINS_HOME": None,
            "BUILD_NUMBER": None,
            "JENKINS_URL": None,
        },
        "circleci": {
            "CIRCLECI": "true",
            "CIRCLE_BUILD_NUM": None,
        },
        "travis_ci": {
            "TRAVIS": "true",
            "TRAVIS_BUILD_ID": None,
        },
    }

    # CI provider API endpoints for runner info
    PROVIDER_APIS = {
        "github_actions": {
            "token": "ACTIONS_RUNTIME_TOKEN",
            "url": "ACTIONS_ID_TOKEN_REQUEST_URL",
        },
        "gitlab_ci": {
            "token": "CI_JOB_JWT",
            "url": "CI_API_V4_URL",
        },
    }

    SENSITIVE_ENV_PATTERNS = [
        re.compile(r".*(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|API_KEY|API_TOKEN|ACCESS_KEY).*", re.IGNORECASE),
        re.compile(r".*_PAT$", re.IGNORECASE),
        re.compile(r".*_SECRET$", re.IGNORECASE),
        re.compile(r".*_PASSWORD$", re.IGNORECASE),
    ]

    def __init__(self, target_host: Optional[str] = None, timeout: int = 10):
        self.target_host = target_host
        self.timeout = timeout
        self.env_cache: dict = {}

    def fingerprint_local(self) -> RunnerFingerprintResult:
        """Fingerprint the current environment (running inside a CI/CD runner)."""
        info = RunnerInfo(hostname=socket.gethostname())
        result = RunnerFingerprintResult(runner_info=info)

        self._detect_platform(info)
        self._detect_hardware(info)
        self._detect_container_vm(info)
        self._detect_tools(info)
        self._detect_network(info)
        self._detect_ci_provider(info)
        self._detect_labels_from_env(info)
        self._detect_env_vars(result)
        self._detect_services(result)
        self._detect_credentials(result)
        self._assess_attack_surface(result)
        self._calculate_risk(result)

        return result

    def fingerprint_remote(self, host: str, port: int = 22) -> RunnerFingerprintResult:
        """Remote runner fingerprinting via SSH or API."""
        result = RunnerFingerprintResult(
            runner_info=RunnerInfo(hostname=host)
        )

        try:
            ssh_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                f"{host}",
                "uname -a; cat /etc/os-release 2>/dev/null; env | sort 2>/dev/null; "
                "cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1; "
                "free -m 2>/dev/null | grep Mem; "
                "ls -la /var/run/docker.sock 2>/dev/null; "
                "which docker kubectl aws gcloud az 2>/dev/null; "
                "curl -s ifconfig.me 2>/dev/null; hostname -I 2>/dev/null"
            ]
            output = subprocess.check_output(" ".join(ssh_cmd), shell=True, timeout=self.timeout, stderr=subprocess.PIPE)
            result.runner_info.health = RunnerHealth.HEALTHY
            self._parse_remote_output(result, output.decode("utf-8"))
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"Remote fingerprinting failed for {host}: {e}")
            result.runner_info.health = RunnerHealth.UNREACHABLE

        return result

    def fingerprint_from_labels(self, labels: list[str]) -> RunnerFingerprintResult:
        """Fingerprint based on runner label metadata (from workflow parsing)."""
        info = RunnerInfo(hostname="unknown", labels=labels)
        result = RunnerFingerprintResult(runner_info=info)

        # Parse labels for platform hints
        for label in labels:
            label_lower = label.lower()
            if "ubuntu" in label_lower:
                info.platform = RunnerPlatform.LINUX
            elif "windows" in label_lower:
                info.platform = RunnerPlatform.WINDOWS
            elif "macos" in label_lower or "mac" in label_lower:
                info.platform = RunnerPlatform.MACOS
            if "arm" in label_lower or "aarch" in label_lower:
                info.architecture = RunnerArchitecture.ARM64
            elif "x64" in label_lower or "amd" in label_lower:
                info.architecture = RunnerArchitecture.X86_64
            if "gpu" in label_lower or "nvidia" in label_lower:
                info.has_nvidia_gpu = True

        info.is_self_hosted()
        self._assess_attack_surface(result)
        self._calculate_risk(result)
        return result

    def _detect_platform(self, info: RunnerInfo):
        try:
            uname = os.uname()
            sysname = uname.sysname.lower()
            if "linux" in sysname:
                info.platform = RunnerPlatform.LINUX
            elif "windows" in sysname or "nt" in sysname:
                info.platform = RunnerPlatform.WINDOWS
            elif "darwin" in sysname:
                info.platform = RunnerPlatform.MACOS

            info.kernel_version = uname.release

            # OS version
            if info.platform == RunnerPlatform.LINUX:
                try:
                    with open("/etc/os-release") as f:
                        for line in f:
                            if line.startswith("PRETTY_NAME="):
                                info.os_version = line.split("=")[1].strip().strip('"')
                                break
                except FileNotFoundError:
                    pass
            elif info.platform == RunnerPlatform.WINDOWS:
                info.os_version = os.environ.get("OS", "")
            elif info.platform == RunnerPlatform.MACOS:
                try:
                    output = subprocess.check_output(["sw_vers", "-productVersion"], timeout=5)
                    info.os_version = output.decode().strip()
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass
        except Exception as e:
            logger.warning(f"Platform detection failed: {e}")

    def _detect_hardware(self, info: RunnerInfo):
        try:
            # Architecture
            machine = os.uname().machine.lower()
            if "x86_64" in machine or "amd64" in machine:
                info.architecture = RunnerArchitecture.X86_64
            elif "aarch64" in machine or "arm64" in machine:
                info.architecture = RunnerArchitecture.ARM64
            elif "x86" in machine or "i386" in machine or "i686" in machine:
                info.architecture = RunnerArchitecture.X86

            # CPU count
            info.cpu_count = os.cpu_count() or 0

            # Memory (Linux)
            if info.platform == RunnerPlatform.LINUX:
                try:
                    with open("/proc/meminfo") as f:
                        for line in f:
                            if line.startswith("MemTotal:"):
                                kb = int(line.split()[1])
                                info.total_memory_mb = kb // 1024
                                break
                except FileNotFoundError:
                    pass
        except Exception as e:
            logger.warning(f"Hardware detection failed: {e}")

    def _detect_container_vm(self, info: RunnerInfo):
        # Check for container indicators
        try:
            if os.path.exists("/.dockerenv"):
                info.is_container = True
            if os.path.exists("/run/.containerenv"):
                info.is_container = True
        except Exception:
            pass

        # Check for Docker
        try:
            output = subprocess.check_output(["docker", "--version"], timeout=5, stderr=subprocess.DEVNULL)
            info.has_docker = True
            info.docker_version = output.decode().strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Check for VM indicators
        try:
            with open("/proc/cpuinfo") as f:
                content = f.read()
                if "hypervisor" in content.lower():
                    info.is_vm = True
        except FileNotFoundError:
            pass

    def _detect_tools(self, info: RunnerInfo):
        for tool_attr, check_cmd in [
            ("has_kubectl", "kubectl version --client --short"),
            ("has_aws_cli", "aws --version"),
            ("has_gcloud_cli", "gcloud --version"),
            ("has_azure_cli", "az version"),
        ]:
            try:
                subprocess.check_output(check_cmd.split(), timeout=5, stderr=subprocess.DEVNULL)
                setattr(info, tool_attr, True)
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

        # NVIDIA GPU
        try:
            output = subprocess.check_output(["nvidia-smi", "-L"], timeout=10, stderr=subprocess.DEVNULL)
            if output.strip():
                info.has_nvidia_gpu = True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    def _detect_network(self, info: RunnerInfo):
        # Private IPs
        try:
            hostname = socket.gethostname()
            info.private_ips = list(set(
                addr[4][0] for addr in socket.getaddrinfo(hostname, None)
                if addr[0] in (socket.AF_INET, socket.AF_INET6) and addr[4][0]
            ))
        except Exception:
            pass

        # Public IP
        try:
            output = subprocess.check_output(
                ["curl", "-s", "--max-time", "5", "https://ifconfig.me"],
                timeout=10, stderr=subprocess.DEVNULL
            )
            info.public_ip = output.decode().strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    def _detect_ci_provider(self, info: RunnerInfo):
        for provider, signatures in self.CI_ENV_SIGNATURES.items():
            matched = False
            for var, expected in signatures.items():
                val = os.environ.get(var)
                if val:
                    if expected is None or val == expected:
                        matched = True
                        break
            if matched:
                info.ci_provider = provider
                info.runner_version = os.environ.get(
                    f"{var.upper()}_VERSION" if not var.startswith("CI_") else "CI_RUNNER_VERSION",
                    ""
                )
                break

    def _detect_labels_from_env(self, info: RunnerInfo):
        # GitHub Actions labels from env
        runner_name = os.environ.get("RUNNER_NAME") or os.environ.get("GITHUB_RUNNER_NAME")
        if runner_name:
            info.labels.append(runner_name)
        runner_os = os.environ.get("RUNNER_OS")
        if runner_os:
            info.labels.append(runner_os)
        runner_arch = os.environ.get("RUNNER_ARCH")
        if runner_arch:
            info.labels.append(runner_arch)
        # GitLab CI labels
        runner_desc = os.environ.get("CI_RUNNER_DESCRIPTION")
        if runner_desc:
            info.labels.append(runner_desc)
        runner_tags = os.environ.get("CI_RUNNER_TAGS")
        if runner_tags:
            info.labels.extend(runner_tags.split(","))

    def _detect_env_vars(self, result: RunnerFingerprintResult):
        """Extract all environment variables with CI/CD context."""
        env_vars = {}
        for key, value in os.environ.items():
            if any(pattern.match(key) for pattern in self.SENSITIVE_ENV_PATTERNS):
                masked_value = value[:4] + "..." if len(value) > 8 else "***"
                env_vars[key] = masked_value
            elif key.startswith(("CI_", "GITHUB_", "SYSTEM_", "AGENT_", "BUILD_", "TF_", "AZURE_")):
                env_vars[key] = value[:80] if len(value) > 80 else value
        result.detected_env_vars = env_vars

    def _detect_services(self, result: RunnerFingerprintResult):
        """Detect running services accessible from the runner."""
        services = []
        # Check for metadata services
        metadata_checks = [
            ("AWS_EC2", "http://169.254.169.254/latest/meta-data/"),
            ("GCP_GCE", "http://metadata.google.internal/computeMetadata/v1/"),
            ("Azure_IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            ("Docker_Socket", "/var/run/docker.sock"),
        ]
        for service_name, check_path in metadata_checks:
            if check_path.startswith("http"):
                try:
                    r = subprocess.check_output(
                        ["curl", "-s", "--max-time", "2", check_path],
                        timeout=5, stderr=subprocess.DEVNULL
                    )
                    if r.strip():
                        services.append(service_name)
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass
            else:
                if os.path.exists(check_path):
                    services.append(service_name)
        result.detected_services = services

    def _detect_credentials(self, result: RunnerFingerprintResult):
        """Detect potential credential exposure in env and files."""
        creds = []

        # Check for well-known credential files
        cred_paths = [
            ("AWS_CREDS", os.path.expanduser("~/.aws/credentials")),
            ("GCP_SA_KEY", os.path.expanduser("~/.config/gcloud/application_default_credentials.json")),
            ("AZURE_CREDS", os.path.expanduser("~/.azure/azureProfile.json")),
            ("KUBE_CONFIG", os.path.expanduser("~/.kube/config")),
            ("DOCKER_CONFIG", os.path.expanduser("~/.docker/config.json")),
            ("NETRC", os.path.expanduser("~/.netrc")),
            ("SSH_KEY", os.path.expanduser("~/.ssh/id_rsa")),
        ]
        for cred_name, cred_path in cred_paths:
            if os.path.exists(cred_path):
                creds.append(cred_name)

        result.detected_credentials = creds

    def _assess_attack_surface(self, result: RunnerFingerprintResult):
        """Assess the runner's attack surface based on detected features."""
        surface = {
            "has_cloud_creds": len(result.detected_credentials) > 0,
            "has_sensitive_env": len(result.detected_env_vars) > 0,
            "has_metadata_service": any("IMDS" in s or "EC2" in s or "GCE" in s for s in result.detected_services),
            "has_docker_socket": "Docker_Socket" in result.detected_services,
            "has_network_egress": result.runner_info.can_egress(),
            "is_container": result.runner_info.is_container,
            "has_orchestration": any(result.runner_info.__dict__.get(a) for a in
                                      ["has_kubectl", "has_aws_cli", "has_gcloud_cli", "has_azure_cli"]),
        }
        result.attack_surface = surface

    def _calculate_risk(self, result: RunnerFingerprintResult):
        """Calculate a risk score (0.0 - 10.0) for the runner."""
        score = 0.0
        info = result.runner_info

        # Self-hosted runners are higher value targets
        if info.is_self_hosted():
            score += 3.0

        # Containers have more isolation but also more escape surface
        if info.is_container:
            score += 1.0

        # Network egress enables data exfiltration
        if info.can_egress():
            score += 1.5

        # Cloud credentials = high value
        cloud_creds_count = len([c for c in result.detected_credentials if "CLOUD" in c.upper() or "AWS" in c or "GCP" in c or "AZURE" in c])
        score += min(cloud_creds_count * 1.0, 3.0)

        # Metadata service availability
        if result.attack_surface.get("has_metadata_service"):
            score += 2.0

        # Docker socket
        if result.attack_surface.get("has_docker_socket"):
            score += 1.5

        # Sensitive env vars
        if len(result.detected_env_vars) > 5:
            score += 1.0

        # GPU = higher compute value
        if info.has_nvidia_gpu:
            score += 0.5

        result.risk_score = min(round(score, 2), 10.0)

    def _parse_remote_output(self, result: RunnerFingerprintResult, output: str):
        info = result.runner_info
        # Parse uname -a
        uname_match = re.search(r"Linux\s+\S+\s+(\S+)\s+(\S+)", output)
        if uname_match:
            info.kernel_version = uname_match.group(2)

        # Parse OS release
        os_match = re.search(r'PRETTY_NAME="([^"]+)"', output)
        if os_match:
            info.os_version = os_match.group(1)

        # Parse CPU
        cpu_match = re.search(r"model name\s*:\s*(.+)", output)
        if cpu_match:
            info.cpu_count = 1  # rough

        # Parse memory
        mem_match = re.search(r"Mem:\s+(\d+)", output)
        if mem_match:
            info.total_memory_mb = int(mem_match.group(1))

        # Parse tools
        if "docker" in output:
            info.has_docker = True
        if "kubectl" in output:
            info.has_kubectl = True
        if "aws" in output:
            info.has_aws_cli = True
        if "gcloud" in output:
            info.has_gcloud_cli = True
        if "az" in output:
            info.has_azure_cli = True

        # Parse public IP
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", output.split("curl")[-1] if "curl" in output else "")
        if ip_match:
            info.public_ip = ip_match.group(0)

        # Docker socket
        if "/var/run/docker.sock" in output:
            result.detected_services.append("Docker_Socket")

    def summary(self) -> dict:
        return {
            "fingerprinter": "RunnerFingerprinter",
            "version": "0.1.0",
            "ci_providers_supported": list(self.CI_ENV_SIGNATURES.keys()),
            "detection_capabilities": [
                "platform", "hardware", "container_vm", "tools",
                "network", "ci_provider", "env_vars", "services",
                "credentials", "attack_surface", "risk_score",
            ],
        }


def fingerprint_runner(host: Optional[str] = None) -> dict:
    """Convenience function to fingerprint a runner."""
    fingerprinter = RunnerFingerprinter(target_host=host)
    if host:
        result = fingerprinter.fingerprint_remote(host)
    else:
        result = fingerprinter.fingerprint_local()
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    target = sys.argv[1] if len(sys.argv) > 1 else None
    result = fingerprint_runner(target)
    print(json.dumps(result, indent=2, default=str))
