"""
Runtime Dependency Validation for Agent Modules

Validates that all required tools and libraries are available
before the agent begins its engagement. Fails fast with clear
error messages instead of silent failures mid-operation.
"""

import importlib
import logging
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class DependencySeverity(Enum):
    """How critical a missing dependency is."""
    BLOCKER = auto()    # Agent cannot function at all
    CRITICAL = auto()   # Core module will fail
    HIGH = auto()       # Important feature unavailable
    MEDIUM = auto()     # Niche feature unavailable
    LOW = auto()        # Optional enhancement


class DependencyType(Enum):
    """Type of dependency."""
    PYTHON_PACKAGE = auto()    # pip-installable
    SYSTEM_TOOL = auto()       # apt/yum/brew installable
    SYSTEM_LIBRARY = auto()    # .so/.dll shared library
    FILE = auto()              # Specific file path
    CAPABILITY = auto()        # OS capability (e.g., root)


@dataclass
class Dependency:
    """Definition of a single dependency."""
    name: str
    type: DependencyType
    severity: DependencySeverity
    module: str = ""                       # Python module name (if PYTHON_PACKAGE)
    binary: str = ""                       # Binary name (if SYSTEM_TOOL)
    library: str = ""                      # Library name (if SYSTEM_LIBRARY)
    path: str = ""                         # File path (if FILE)
    min_version: str = ""                  # Minimum version requirement
    import_name: str = ""                  # Import name if different from module
    description: str = ""                  # Human-readable description
    platforms: list[str] = field(default_factory=lambda: ["linux", "darwin", "windows"])
    check_command: str = ""                # Custom verification command
    install_hint: str = ""                 # How to install


# ═══════════════════════════════════════════════════════════════════════════════
# FULL DEPENDENCY REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM = platform.system().lower()

ALL_DEPENDENCIES: list[Dependency] = [

    # ── Python Packages (BLOCKER) ──────────────────────────────────────────
    Dependency(
        name="cryptography",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.BLOCKER,
        module="cryptography",
        min_version="41.0.0",
        description="Cryptographic operations (AES-GCM, HKDF, key exchange)",
        install_hint="pip install cryptography>=41.0.0",
    ),
    Dependency(
        name="httpx",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.BLOCKER,
        module="httpx",
        min_version="0.27.0",
        description="Async HTTP client for C2 communication",
        install_hint="pip install httpx>=0.27.0",
    ),

    # ── Python Packages (CRITICAL) ────────────────────────────────────────
    Dependency(
        name="aiohttp",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.CRITICAL,
        module="aiohttp",
        min_version="3.9.0",
        description="Async HTTP server for beacon listener",
        install_hint="pip install aiohttp>=3.9.0",
    ),
    Dependency(
        name="requests",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.CRITICAL,
        module="requests",
        min_version="2.31.0",
        description="Sync HTTP client for C2 communication (fallback)",
        install_hint="pip install requests>=2.31.0",
    ),

    # ── Python Packages (HIGH) ────────────────────────────────────────────
    Dependency(
        name="pydantic",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.HIGH,
        module="pydantic",
        min_version="2.0.0",
        description="Data validation and settings management",
        install_hint="pip install pydantic>=2.0.0",
    ),
    Dependency(
        name="pyyaml",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.HIGH,
        module="yaml",
        import_name="yaml",
        min_version="6.0",
        description="YAML parsing for configuration",
        install_hint="pip install pyyaml>=6.0",
    ),

    # ── Python Packages (MEDIUM) ──────────────────────────────────────────
    Dependency(
        name="pyjwt",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.MEDIUM,
        module="jwt",
        import_name="jwt",
        min_version="2.8.0",
        description="JWT token handling for C2 auth",
        install_hint="pip install pyjwt>=2.8.0",
    ),
    Dependency(
        name="colorama",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.MEDIUM,
        module="colorama",
        description="Terminal color output",
        install_hint="pip install colorama",
    ),

    # ── Python Packages (LOW) ─────────────────────────────────────────────
    Dependency(
        name="boto3",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.LOW,
        module="boto3",
        description="AWS SDK for cloud exfiltration",
        install_hint="pip install boto3",
    ),
    Dependency(
        name="azure-storage-blob",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.LOW,
        module="azure.storage.blob",
        description="Azure Blob SDK for cloud exfiltration",
        install_hint="pip install azure-storage-blob",
    ),
    Dependency(
        name="google-cloud-storage",
        type=DependencyType.PYTHON_PACKAGE,
        severity=DependencySeverity.LOW,
        module="google.cloud.storage",
        description="GCP Storage SDK for cloud exfiltration",
        install_hint="pip install google-cloud-storage",
    ),

    # ── System Tools (CRITICAL) ──────────────────────────────────────────
    Dependency(
        name="nmap",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.CRITICAL,
        binary="nmap",
        description="Network discovery and port scanning",
        platforms=["linux", "darwin"],
        check_command="nmap --version",
        install_hint="apt install nmap  |  brew install nmap",
    ),
    Dependency(
        name="impacket",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.CRITICAL,
        binary="impacket-wmiexec",
        description="Windows protocol implementations (WMI, SMB, Kerberos)",
        platforms=["linux"],
        check_command="impacket-wmiexec -h",
        install_hint="apt install impacket-scripts python3-impacket",
    ),
    Dependency(
        name="netexec",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.CRITICAL,
        binary="netexec",
        description="Swiss army knife for network service exploitation",
        platforms=["linux"],
        check_command="netexec --version",
        install_hint="pip install netexec  |  apt install netexec",
    ),
    Dependency(
        name="evil-winrm",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.CRITICAL,
        binary="evil-winrm",
        description="WinRM shell for Windows targets",
        platforms=["linux"],
        check_command="evil-winrm --version",
        install_hint="gem install evil-winrm  |  apt install evil-winrm",
    ),
    Dependency(
        name="sshpass",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.CRITICAL,
        binary="sshpass",
        description="Non-interactive SSH authentication",
        platforms=["linux", "darwin"],
        check_command="sshpass -V",
        install_hint="apt install sshpass  |  brew install hudochenkov/sshpass/sshpass",
    ),

    # ── System Tools (HIGH) ──────────────────────────────────────────────
    Dependency(
        name="gcc",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.HIGH,
        binary="gcc",
        description="C compiler for LD_PRELOAD persistence",
        platforms=["linux"],
        check_command="gcc --version",
        install_hint="apt install gcc build-essential",
    ),
    Dependency(
        name="curl",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.HIGH,
        binary="curl",
        description="HTTP transfers (fallback transport)",
        platforms=["linux", "darwin", "windows"],
        check_command="curl --version",
        install_hint="apt install curl  |  brew install curl",
    ),
    Dependency(
        name="powershell",
        type=DependencyType.SYSTEM_TOOL,
        severity=DependencySeverity.HIGH,
        binary="powershell",
        description="PowerShell for Windows lateral movement and persistence",
        platforms=["windows"],
        check_command="powershell -Command 'echo $PSVersionTable.PSVersion'",
        install_hint="Pre-installed on Windows 10+",
    ),

    # ── System Libraries (MEDIUM) ─────────────────────────────────────────
    Dependency(
        name="OpenSSL",
        type=DependencyType.SYSTEM_LIBRARY,
        severity=DependencySeverity.MEDIUM,
        library="libssl.so",
        description="TLS/SSL for mTLS and HTTPS transport",
        platforms=["linux"],
        check_command="openssl version",
        install_hint="apt install libssl-dev openssl",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECK FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def check_python_package(dep: Dependency) -> tuple[bool, str]:
    """Check if a Python package is installed and meets version requirements."""
    try:
        module = importlib.import_module(dep.import_name or dep.module)
    except ImportError as e:
        return False, f"Not installed ({e})"

    # Check version if required
    if dep.min_version:
        try:
            installed = getattr(module, "__version__", "")
            if installed:
                try:
                    from packaging.version import Version
                except ImportError:
                    return False, "packaging library not installed (required for version check)"
                if Version(installed) < Version(dep.min_version):
                    return False, (
                        f"Version {installed} < required {dep.min_version}"
                    )
        except Exception:
            pass

    return True, "OK"


def check_system_tool(dep: Dependency) -> tuple[bool, str]:
    """Check if a system binary is available on PATH."""
    binary = shutil.which(dep.binary)
    if not binary:
        return False, f"Not in PATH"

    # Run version check if provided
    if dep.check_command:
        try:
            result = subprocess.run(
                dep.check_command.split(),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return False, f"Command failed: {result.stderr[:100]}"
        except Exception as e:
            return False, f"Check failed: {e}"

    return True, "OK"


def check_system_library(dep: Dependency) -> tuple[bool, str]:
    """Check if a shared library is available."""
    import ctypes

    # Try ctypes.util.find_library first
    import ctypes.util
    lib_path = ctypes.util.find_library(dep.library.replace("lib", "").replace(".so", ""))
    if lib_path:
        return True, f"Found at {lib_path}"

    # Try common paths
    common_paths = [
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/lib",
        "/lib64",
    ]
    for path in common_paths:
        full = os.path.join(path, dep.library)
        if os.path.exists(full):
            return True, f"Found at {full}"

    return False, "Not found in library paths"


def check_file(dep: Dependency) -> tuple[bool, str]:
    """Check if a specific file exists and is readable."""
    path = Path(dep.path)
    if not path.exists():
        return False, "File does not exist"
    if not os.access(path, os.R_OK):
        return False, "File not readable"
    return True, "OK"


def check_capability(dep: Dependency) -> tuple[bool, str]:
    """Check OS capability (e.g., root)."""
    if dep.name == "root":
        if os.geteuid() == 0:
            return True, "Running as root"
        return False, "Not running as root"
    return True, "Unknown capability"


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN CHECKER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CheckResult:
    """Result of a single dependency check."""
    dependency: Dependency
    passed: bool
    message: str
    severity: DependencySeverity


class DependencyChecker:
    """
    Validates all runtime dependencies for the Raphael agent.

    Usage:
        checker = DependencyChecker()
        results = checker.check_all()
        if not checker.all_blockers_passed():
            sys.exit(1)
    """

    def __init__(
        self,
        dependencies: list[Dependency] = None,
        target_platform: str = None,
    ):
        self._dependencies = dependencies or ALL_DEPENDENCIES
        self._target_platform = target_platform or SYSTEM
        self._results: list[CheckResult] = []

    def _filter_by_platform(self, deps: list[Dependency]) -> list[Dependency]:
        """Filter dependencies by target platform."""
        return [
            d for d in deps
            if self._target_platform in d.platforms
        ]

    def check_all(self) -> list[CheckResult]:
        """Run all dependency checks."""
        self._results = []
        filtered = self._filter_by_platform(self._dependencies)

        logger.info(
            "Checking %d dependencies for platform %s",
            len(filtered), self._target_platform,
        )

        for dep in filtered:
            passed, message = self._check_single(dep)
            self._results.append(CheckResult(
                dependency=dep,
                passed=passed,
                message=message,
                severity=dep.severity,
            ))

            status = "✓" if passed else "✗"
            logger.info(
                "%s %s [%s]: %s",
                status, dep.name, dep.severity.name, message,
            )

        return self._results

    def _check_single(self, dep: Dependency) -> tuple[bool, str]:
        """Check a single dependency based on its type."""
        try:
            if dep.type == DependencyType.PYTHON_PACKAGE:
                return check_python_package(dep)
            elif dep.type == DependencyType.SYSTEM_TOOL:
                return check_system_tool(dep)
            elif dep.type == DependencyType.SYSTEM_LIBRARY:
                return check_system_library(dep)
            elif dep.type == DependencyType.FILE:
                return check_file(dep)
            elif dep.type == DependencyType.CAPABILITY:
                return check_capability(dep)
            else:
                return False, f"Unknown dependency type: {dep.type}"
        except Exception as e:
            logger.error("Check failed for %s: %s", dep.name, e)
            return False, f"Check error: {e}"

    def all_blockers_passed(self) -> bool:
        """Check if all BLOCKER/CRITICAL dependencies passed."""
        for result in self._results:
            if result.severity in (DependencySeverity.BLOCKER, DependencySeverity.CRITICAL):
                if not result.passed:
                    return False
        return True

    def get_failed(self) -> list[CheckResult]:
        """Get all failed dependency checks."""
        return [r for r in self._results if not r.passed]

    def get_failed_by_severity(self, severity: DependencySeverity) -> list[CheckResult]:
        """Get failed checks of a specific severity."""
        return [
            r for r in self._results
            if r.severity == severity and not r.passed
        ]

    def print_summary(self) -> str:
        """Generate a human-readable summary."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.passed)
        failed = total - passed

        blockers = self.get_failed_by_severity(DependencySeverity.BLOCKER)
        critical = self.get_failed_by_severity(DependencySeverity.CRITICAL)
        high = self.get_failed_by_severity(DependencySeverity.HIGH)
        medium = self.get_failed_by_severity(DependencySeverity.MEDIUM)
        low = self.get_failed_by_severity(DependencySeverity.LOW)

        lines = [
            "═══════════════════════════════════════════════════════════",
            "       DEPENDENCY VALIDATION SUMMARY",
            "═══════════════════════════════════════════════════════════",
            f"Platform: {SYSTEM} ({platform.platform()})",
            f"Python: {sys.version.split()[0]}",
            f"Total: {total}  |  Passed: {passed}  |  Failed: {failed}",
            "",
            "FAILURES BY SEVERITY:",
        ]

        for severity, results in [
            (DependencySeverity.BLOCKER, blockers),
            (DependencySeverity.CRITICAL, critical),
            (DependencySeverity.HIGH, high),
            (DependencySeverity.MEDIUM, medium),
            (DependencySeverity.LOW, low),
        ]:
            failed_results = [r for r in results if not r.passed]
            if failed_results:
                lines.append(f"  {severity.name}: {len(failed_results)}")
                for r in failed_results:
                    lines.append(f"    ✗ {r.dependency.name}: {r.message}")

        lines.append("")
        if blockers:
            lines.append("❌ BLOCKER dependencies missing — agent CANNOT START")
        elif critical:
            lines.append("❌ CRITICAL dependencies missing — core features DISABLED")
        elif high:
            lines.append("⚠️  HIGH severity missing — important features DISABLED")
        else:
            lines.append("✅ All critical dependencies satisfied")

        lines.append("═══════════════════════════════════════════════════════════")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT INTEGRATION
# ════════════════════════════════════════════════════════════════════════════════

def validate_agent_dependencies() -> bool:
    """
    Validate all agent dependencies at startup.

    Raises SystemExit if BLOCKER or CRITICAL dependencies are missing.
    Logs warnings for HIGH/MEDIUM/LOW missing dependencies.
    """
    checker = DependencyChecker()
    results = checker.check_all()

    # Print summary
    print(checker.print_summary())

    # Exit on blockers/critical
    blockers = checker.get_failed_by_severity(DependencySeverity.BLOCKER)
    critical = checker.get_failed_by_severity(DependencySeverity.CRITICAL)

    if blockers:
        logger.error("BLOCKER dependencies missing — aborting agent startup")
        for r in blockers:
            logger.error("  Missing: %s — %s", r.dependency.name, r.dependency.install_hint)
        sys.exit(1)

    if critical:
        logger.error("CRITICAL dependencies missing — core features will fail")
        for r in critical:
            logger.error("  Missing: %s — %s", r.dependency.name, r.dependency.install_hint)
        sys.exit(1)

    # Log warnings for other missing
    for result in checker.get_failed():
        if result.severity == DependencySeverity.HIGH:
            logger.warning(
                "HIGH: %s missing — %s",
                result.dependency.name,
                result.dependency.install_hint,
            )
        elif result.severity == DependencySeverity.MEDIUM:
            logger.info(
                "MEDIUM: %s missing — %s",
                result.dependency.name,
                result.dependency.install_hint,
            )
        elif result.severity == DependencySeverity.LOW:
            logger.debug(
                "LOW: %s missing — %s",
                result.dependency.name,
                result.dependency.install_hint,
            )

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# EXTENSION POINTS
# ════════════════════════════════════════════════════════════════════════════════

def add_custom_dependency(
    name: str,
    dep_type: DependencyType,
    severity: DependencySeverity,
    **kwargs,
) -> None:
    """Add a custom dependency to the registry."""
    dep = Dependency(
        name=name,
        type=dep_type,
        severity=severity,
        **kwargs,
    )
    ALL_DEPENDENCIES.append(dep)
    logger.info("Added custom dependency: %s (%s)", name, dep_type.name)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════

def main():
    """Command-line interface for dependency checking."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Raphael Agent Dependency Validator",
    )
    parser.add_argument(
        "--severity",
        choices=[s.name for s in DependencySeverity],
        default="BLOCKER",
        help="Minimum severity to check (default: BLOCKER)",
    )
    parser.add_argument(
        "--platform",
        choices=["linux", "darwin", "windows"],
        default=SYSTEM,
        help=f"Target platform (default: {SYSTEM})",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.name for s in DependencySeverity],
        default="CRITICAL",
        help="Exit with error code if this severity fails",
    )

    args = parser.parse_args()

    checker = DependencyChecker(target_platform=args.platform)
    results = checker.check_all()

    if args.format == "json":
        import json
        output = {
            "platform": SYSTEM,
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
            "results": [
                {
                    "name": r.dependency.name,
                    "type": r.dependency.type.name,
                    "severity": r.severity.name,
                    "passed": r.passed,
                    "message": r.message,
                    "install_hint": r.dependency.install_hint,
                }
                for r in results
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print(checker.print_summary())

    # Exit code based on --fail-on
    fail_severity = DependencySeverity[args.fail_on]
    failed_at_level = [
        r for r in results
        if not r.passed and r.severity.value <= fail_severity.value
    ]

    if failed_at_level:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()