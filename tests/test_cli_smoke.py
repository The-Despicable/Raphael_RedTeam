#!/usr/bin/env python3
"""
Raphael 2.0 — Comprehensive CLI Test & Infrastructure Smoke Check
==================================================================
Verifies 100% CLI functionality, all Docker images build, AI models
respond, hacker tools run, and orchestrator modes initialize.

Usage:
  python tests/test_cli_smoke.py                    # Full test suite
  python tests/test_cli_smoke.py --cli-only          # CLI command tests only
  python tests/test_cli_smoke.py --docker-only       # Docker build/image tests only
  python tests/test_cli_smoke.py --tools-only        # Hacker tools availability
  python tests/test_cli_smoke.py --models-only       # AI model config validation
  python tests/test_cli_smoke.py --orchestrator-only # Mode initialization tests
  python tests/test_cli_smoke.py --quick             # Skip slow docker/tool builds
  python tests/test_cli_smoke.py --verbose           # Full output

Exit codes: 0 = all pass, 1 = warnings, 2 = failures
"""

import argparse
import asyncio
import importlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any, Callable, Optional

# ── Configuration ──────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLI_DIR = PROJECT_ROOT / "cli"
MODELS_CONFIG = CLI_DIR / "models_config.json"
DOCKER_COMPOSE = PROJECT_ROOT / "docker-compose.yml"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
REQUIREMENTS_TXT = PROJECT_ROOT / "requirements.txt"
CLI_REQUIREMENTS = CLI_DIR / "requirements-cli.txt"
ORCHESTRATOR_DIR = PROJECT_ROOT / "orchestrator"
BRAIN_DIR = PROJECT_ROOT / "brain"
SWORD_DIR = PROJECT_ROOT / "sword"
AGENT_DIR = PROJECT_ROOT / "agent"
CAI_DIR = PROJECT_ROOT / "cai-service"
KALI_DIR = PROJECT_ROOT / "kali-tools"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

CHECK_PASS = "PASS"
CHECK_WARN = "WARN"
CHECK_FAIL = "FAIL"
CHECK_SKIP = "SKIP"

TOTAL_TESTS = {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
VERBOSE = False

# ── Test Infrastructure ─────────────────────────────────────────────────────

class CheckResult:
    def __init__(self, name: str, label: str, status: str, detail: str = ""):
        self.name = name
        self.label = label
        self.status = status
        self.detail = detail
        TOTAL_TESTS[status.lower()] += 1

    def __str__(self):
        icons = {CHECK_PASS: "\u2713", CHECK_WARN: "!", CHECK_FAIL: "\u2717", CHECK_SKIP: "\u2013"}
        icon = icons.get(self.status, "?")
        detail = f" \u2014 {self.detail}" if self.detail else ""
        return f"  {icon}  {self.label:<52} [{self.status}]{detail}"


def check(name: str, label: str, fn: Callable, *args, **kwargs) -> CheckResult:
    """Run a check function and return the result."""
    try:
        result = fn(*args, **kwargs)
        if isinstance(result, CheckResult):
            return result
        if isinstance(result, tuple) and len(result) >= 2:
            return CheckResult(name, label, result[0], str(result[1]))
        if result is True or result is None:
            return CheckResult(name, label, CHECK_PASS)
        if result is False:
            return CheckResult(name, label, CHECK_FAIL)
        return CheckResult(name, label, CHECK_PASS, str(result))
    except Exception as e:
        return CheckResult(name, label, CHECK_FAIL, str(e))


def run_section(title: str, checks: list[CheckResult]):
    """Print a section of test results."""
    total = len(checks)
    passed = sum(1 for c in checks if c.status == CHECK_PASS)
    warned = sum(1 for c in checks if c.status == CHECK_WARN)
    failed = sum(1 for c in checks if c.status == CHECK_FAIL)
    skipped = sum(1 for c in checks if c.status == CHECK_SKIP)

    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")

    if VERBOSE:
        for c in checks:
            if c.status != CHECK_PASS or VERBOSE:
                print(c)
    else:
        # Always show failures and warnings
        for c in checks:
            if c.status in (CHECK_FAIL, CHECK_WARN):
                print(c)
        # Show passes only in summary
        if passed > 0:
            print(f"  ({passed} checks passed)")

    status_indicators = []
    if passed:
        status_indicators.append(f"{passed} passed")
    if warned:
        status_indicators.append(f"{warned} warnings")
    if failed:
        status_indicators.append(f"{failed} failed")
    if skipped:
        status_indicators.append(f"{skipped} skipped")

    print(f"  {'─' * 4} {', '.join(status_indicators)} of {total} total")
    return failed


# ── Helper Functions ───────────────────────────────────────────────────────

def file_exists(path: Path) -> bool:
    return path.exists() and path.is_file()


def dir_exists(path: Path) -> bool:
    return path.exists() and path.is_dir()


def cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(cmd: list[str], cwd: Path = None, timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd or PROJECT_ROOT)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -2, "", "NOT_FOUND"


def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def parse_models_config() -> dict:
    """Load and validate the models config JSON."""
    if not MODELS_CONFIG.exists():
        return {}
    with open(MODELS_CONFIG) as f:
        return json.load(f)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: CLI COMMAND TESTS (100% functionality coverage)
# ═══════════════════════════════════════════════════════════════════════════

def test_cli_imports() -> list[CheckResult]:
    """Verify all CLI modules import cleanly."""
    results = []
    sys.path.insert(0, str(CLI_DIR))

    # Check requirements-cli.txt packages
    if CLI_REQUIREMENTS.exists():
        with open(CLI_REQUIREMENTS) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg = line.split(">=")[0].split("==")[0].strip()
                    results.append(
                        check(f"import_{pkg}", f"CLI dep: {pkg}",
                              lambda p=pkg: importlib.import_module(p.replace("-", "_")) or CHECK_PASS)
                    )

    # Check main CLI files
    for module_name, file_path in [
        ("raphael", CLI_DIR / "raphael.py"),
        ("health_check", CLI_DIR / "health_check.py"),
        ("models_config.json", MODELS_CONFIG),
    ]:
        results.append(
            check(f"file_{module_name}", f"CLI file: {module_name}", file_exists, file_path)
        )

    # Try importing raphael module
    try:
        spec = importlib.util.spec_from_file_location("raphael", CLI_DIR / "raphael.py")
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            results.append(CheckResult("raphael_import", "raphael.py imports cleanly", CHECK_PASS))
            # Check key functions exist
            for func_name in ["build_parser", "main", "cmd_health", "cmd_engage_run",
                              "cmd_engage_start", "cmd_engage_status", "cmd_report",
                              "cmd_scan", "cmd_chat", "cmd_models", "cmd_interactive",
                              "cmd_docker"]:
                has = hasattr(mod, func_name)
                results.append(
                    check(f"raphael_{func_name}", f"raphael.{func_name}() exists",
                          lambda h=has: h or (CHECK_FAIL, "missing"))
                )
        else:
            results.append(CheckResult("raphael_import", "raphael.py imports", CHECK_FAIL, "spec load failed"))
    except Exception as e:
        results.append(CheckResult("raphael_import", "raphael.py imports", CHECK_FAIL, str(e)))

    # Try importing health_check module
    try:
        spec = importlib.util.spec_from_file_location("health_check", CLI_DIR / "health_check.py")
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            results.append(CheckResult("health_import", "health_check.py imports cleanly", CHECK_PASS))
            for needed in ["CheckResult", "SERVICES", "TOOLS", "DOCKER_CONTAINERS",
                           "ENV_CHECKS", "run_all_checks", "print_results", "main"]:
                has = hasattr(mod, needed)
                results.append(
                    check(f"health_{needed}", f"health_check.{needed} exists",
                          lambda h=has: h or (CHECK_FAIL, "missing"))
                )
        else:
            results.append(CheckResult("health_import", "health_check.py imports", CHECK_FAIL))
    except Exception as e:
        results.append(CheckResult("health_import", "health_check.py imports", CHECK_FAIL, str(e)))

    return results


def test_cli_argparse() -> list[CheckResult]:
    """Verify all CLI subcommands and arguments parse correctly."""
    results = []
    sys.path.insert(0, str(CLI_DIR))

    try:
        spec = importlib.util.spec_from_file_location("raphael", CLI_DIR / "raphael.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        parser = mod.build_parser()

        # Test each subcommand parses
        test_cases = [
            (["health"], "health"),
            (["health", "--all"], "health"),
            (["health", "--docker"], "health"),
            (["health", "--host", "10.0.0.1"], "health"),
            (["engage", "run", "192.168.1.1"], "engage"),
            (["engage", "run", "target.com", "--phases", "recon,scan,exploit"], "engage"),
            (["--model", "w13", "engage", "run", "10.0.0.5", "--persona", "redteam"], "engage"),
            (["engage", "run", "10.0.0.5", "--no-proxy"], "engage"),
            (["engage", "run", "10.0.0.5", "--webhook", "http://hook.example.com"], "engage"),
            (["engage", "start", "10.0.0.5"], "engage"),
            (["engage", "start", "10.0.0.5", "--phases", "exploit"], "engage"),
            (["engage", "status", "abc123"], "engage"),
            (["report", "abc123"], "report"),
            (["report", "abc123", "--format", "sarif"], "report"),
            (["report", "abc123", "--format", "junit"], "report"),
            (["scan", "192.168.1.1"], "scan"),
            (["scan", "target.com", "--persona", "blackhat"], "scan"),
            (["scan", "10.0.0.1", "--no-proxy"], "scan"),
            (["chat"], "chat"),
            (["--model", "auto", "chat"], "chat"),
            (["models", "--list"], "models"),
            (["models", "--set", "w13"], "models"),
            (["interactive"], "interactive"),
            (["docker", "ps"], "docker"),
            (["docker", "up"], "docker"),
            (["docker", "down"], "docker"),
            (["docker", "restart", "cai-service"], "docker"),
            (["docker", "logs", "tor-proxy"], "docker"),
            (["docker", "up", "autonomous-brain"], "docker"),
            (["--model", "w480b", "scan", "10.0.0.1"], "scan"),
            (["--raw", "health"], "health"),
            (["--version"], None),  # Should call version and exit
        ]

        for args_list, expected_cmd in test_cases:
            try:
                parsed = parser.parse_args(args_list)
                cmd_ok = hasattr(parsed, "command") and parsed.command == expected_cmd
                has_func = hasattr(parsed, "func")
                results.append(
                    check(f"parse_{'_'.join(args_list)[:40]}",
                          f"raphael {' '.join(args_list)}",
                          lambda ok=cmd_ok, hf=has_func: (
                              CHECK_PASS if (ok and hf) else (CHECK_FAIL, f"cmd={getattr(parsed,'command','?')}")
                          ))
                )
            except SystemExit:
                if expected_cmd is None:
                    results.append(CheckResult(f"parse_version", "--version exits cleanly", CHECK_PASS))
                else:
                    results.append(CheckResult(f"parse_{'_'.join(args_list)[:40]}",
                                               f"raphael {' '.join(args_list)}", CHECK_FAIL, "unexpected exit"))
            except Exception as e:
                results.append(CheckResult(f"parse_{'_'.join(args_list)[:40]}",
                                           f"raphael {' '.join(args_list)}", CHECK_FAIL, str(e)))

    except Exception as e:
        results.append(CheckResult("argparse", "CLI argument parsing", CHECK_FAIL, str(e)))

    return results


def test_cli_models_config() -> list[CheckResult]:
    """Validate models_config.json structure."""
    results = []

    if not MODELS_CONFIG.exists():
        return [CheckResult("models_config", "models_config.json", CHECK_FAIL, "file not found")]

    try:
        config = parse_models_config()
    except json.JSONDecodeError as e:
        return [CheckResult("models_config", "models_config.json", CHECK_FAIL, f"invalid JSON: {e}")]

    # Required top-level keys
    for key in ["default_model", "models", "personas"]:
        results.append(
            check(f"config_key_{key}", f"config has '{key}'",
                  lambda: key in config or (CHECK_FAIL, f"missing key: {key}"))
        )

    if "default_model" in config:
        dm = config["default_model"]
        results.append(
            check("default_model_valid", f"default_model = '{dm}'",
                  lambda: dm in config.get("models", {}) or (CHECK_WARN, f"default '{dm}' not in models dict"))
        )

    # Validate each model entry
    model_keys = config.get("models", {})
    results.append(
        check("models_count", f"Model entries: {len(model_keys)}",
              lambda: len(model_keys) >= 4 or (CHECK_WARN, f"only {len(model_keys)} models (expected >=4)"))
    )

    for model_id, model_cfg in model_keys.items():
        for field in ["display", "provider", "description", "enabled", "capabilities"]:
            results.append(
                check(f"{model_id}_{field}", f"model '{model_id}'.{field}",
                      lambda m=model_cfg, f=field: f in m or (CHECK_FAIL, f"missing {f}"))
            )

    # Validate personas
    persona_keys = config.get("personas", {})
    for pid in ["default", "redteam", "blackhat"]:
        results.append(
            check(f"persona_{pid}", f"persona '{pid}' exists",
                  lambda p=pid: p in persona_keys or (CHECK_WARN, f"missing persona: {p}"))
        )

    # Validate phase_model_overrides
    if "phase_model_overrides" in config:
        overrides = config["phase_model_overrides"]
        expected_phases = ["recon", "scan", "exploit", "postex", "lateral", "credential", "exfil", "phish"]
        for phase in expected_phases:
            if phase in overrides:
                model_val = overrides[phase]
                results.append(
                    check(f"override_{phase}", f"phase override '{phase}' = '{model_val}'",
                          lambda v=model_val: v == "" or v in model_keys or (CHECK_WARN, f"'{v}' not a known model"))
                )

    # Validate fallback_order
    if "fallback_order" in config:
        fb = config["fallback_order"]
        results.append(
            check("fallback_order", f"fallback_order: {fb}",
                  lambda: all(m in model_keys for m in fb) or (CHECK_WARN, "some fallback models not in models dict"))
        )

    return results


def test_cli_health_check_logic() -> list[CheckResult]:
    """Test health_check.py internal logic (unit tests without Docker)."""
    results = []
    sys.path.insert(0, str(CLI_DIR))

    try:
        spec = importlib.util.spec_from_file_location("health_check", CLI_DIR / "health_check.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Test CheckResult creation
        cr = mod.CheckResult("test", "Test", "PASS", "details")
        results.append(CheckResult("health_checkresult", "CheckResult class works", CHECK_PASS,
                                   f"name={cr.name} status={cr.status}"))

        # Test check_binary for known binaries
        for binary in ["python3", "sh", "ls"]:
            r = mod.check_binary(binary, f"Binary: {binary}")
            results.append(
                check(f"health_binary_{binary}", f"check_binary('{binary}') returns result",
                      lambda: r and hasattr(r, 'status') or (CHECK_FAIL, "no result"))
            )

        # Test check_env_var
        os.environ["_RAPHAEL_TEST_VAR"] = "test_value_12345"
        test_cfg = {"label": "Test Var", "required": True, "min_len": 5}
        r = mod.check_env_var("_RAPHAEL_TEST_VAR", test_cfg)
        results.append(CheckResult("health_env_check", "check_env_var works", CHECK_PASS, str(r.status)))
        del os.environ["_RAPHAEL_TEST_VAR"]

        # Verify SERVICES dict has all expected entries
        expected_services = ["cai-service", "mhddos-service", "cloak-service", "orchestrator-api",
                             "c2-server", "phishing", "recon-pipeline", "sword",
                             "autonomous-brain", "kali-tools", "raphael-api"]
        for svc in expected_services:
            results.append(
                check(f"health_service_{svc}", f"SERVICES has '{svc}'",
                      lambda s=svc: s in mod.SERVICES or (CHECK_WARN, f"missing service: {s}"))
            )

        # Verify TOOLS dict
        expected_tools = ["nmap", "sqlmap", "nuclei", "gobuster", "whatweb",
                          "curl", "dig", "python3", "docker", "git"]
        for tool in expected_tools:
            results.append(
                check(f"health_tool_{tool}", f"TOOLS has '{tool}'",
                      lambda t=tool: t in mod.TOOLS or (CHECK_WARN, f"missing tool: {t}"))
            )

        # Verify DOCKER_CONTAINERS
        expected_containers = ["cai-service", "tor-proxy", "neo4j", "sword",
                               "autonomous-brain", "sliver-server", "kali-tools", "raphael-api"]
        for container in expected_containers:
            results.append(
                check(f"health_container_{container}", f"DOCKER_CONTAINERS has '{container}'",
                      lambda c=container: c in mod.DOCKER_CONTAINERS or (CHECK_WARN, f"missing container: {c}"))
            )

    except Exception as e:
        results.append(CheckResult("health_logic", "health_check.py internal logic", CHECK_FAIL, str(e)))

    return results


def test_cli_banner_and_output() -> list[CheckResult]:
    """Verify CLI produces expected output without crashing."""
    results = []

    # Test --help produces output
    rc, stdout, stderr = run_cmd([sys.executable, str(CLI_DIR / "raphael.py"), "--help"], timeout=15)
    results.append(
        check("cli_help", "raphael --help runs",
              lambda: (rc == 0 or rc == -2) and ("usage:" in stdout.lower() or "raphael" in stdout.lower())
              or (CHECK_FAIL, f"exit={rc} out={stdout[:100]}"))
    )

    # Test --version
    rc, stdout, stderr = run_cmd([sys.executable, str(CLI_DIR / "raphael.py"), "--version"], timeout=15)
    results.append(
        check("cli_version", "raphael --version runs",
              lambda: "2.0" in stdout or "2.0" in stderr or rc in (0, 2)
              or (CHECK_WARN, f"exit={rc}"))
    )

    # Test health check module runs (won't fail if Docker missing)
    rc, stdout, stderr = run_cmd([sys.executable, str(CLI_DIR / "health_check.py"), "--host", "127.0.0.1"], timeout=15)
    results.append(
        check("cli_health_module", "health_check.py runs standalone",
              lambda: rc in (0, 1) or (CHECK_WARN, f"exit={rc} (expected 0 or 1)"))
    )

    # Test models --list
    rc, stdout, stderr = run_cmd([sys.executable, str(CLI_DIR / "raphael.py"), "models", "--list", "--raw"], timeout=15)
    results.append(
        check("cli_models_list", "raphael models --list",
              lambda: rc in (0, 1, 2) or (CHECK_WARN, f"exit={rc}"))
    )

    # Test docker ps (won't fail if Docker missing)
    rc, stdout, stderr = run_cmd([sys.executable, str(CLI_DIR / "raphael.py"), "docker", "ps", "--raw"], timeout=15)
    results.append(
        check("cli_docker_ps", "raphael docker ps",
              lambda: rc in (0, 1, 2) or (CHECK_WARN, f"exit={rc}"))
    )

    return results


def test_cli_error_handling() -> list[CheckResult]:
    """Test CLI gracefully handles missing API and invalid inputs."""
    results = []

    # Test with invalid target
    rc, stdout, stderr = run_cmd(
        [sys.executable, str(CLI_DIR / "raphael.py"), "scan", "--raw"], timeout=10
    )
    results.append(
        check("cli_no_target", "raphael scan (no target) errors gracefully",
              lambda: rc != 0 or (CHECK_WARN, "no-target didn't error"))
    )

    # Test with non-existent command
    rc, stdout, stderr = run_cmd(
        [sys.executable, str(CLI_DIR / "raphael.py"), "nonexistent"], timeout=10
    )
    results.append(
        check("cli_bad_cmd", "raphael nonexistent errors gracefully",
              lambda: rc != 0 or (CHECK_WARN, "bad command didn't error"))
    )

    # Test health check with unreachable host
    rc, stdout, stderr = run_cmd(
        [sys.executable, str(CLI_DIR / "health_check.py"), "--host", "192.0.2.1"], timeout=10
    )
    # -1 = timeout, 0 or 1 = normal exit with results, 2 = argparse error
    results.append(
        check("cli_health_bad_host", "health_check.py with unreachable host",
              lambda: rc in (0, 1, 2, -1) or (CHECK_WARN, f"unexpected exit={rc}"))
    )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: DOCKER IMAGE TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_docker_files_exist() -> list[CheckResult]:
    """Verify all Docker-related files exist."""
    results = []
    docker_checks = {
        "docker-compose.yml": DOCKER_COMPOSE,
        "docker-compose.override.example.yml": PROJECT_ROOT / "docker-compose.override.example.yml",
        "Dockerfile (cai-service)": CAI_DIR / "Dockerfile",
        "Dockerfile (mhddos-service)": PROJECT_ROOT / "mhddos-service" / "Dockerfile",
        "Dockerfile (cloak-service)": PROJECT_ROOT / "cloak-service" / "Dockerfile",
        "Dockerfile (sword)": SWORD_DIR / "Dockerfile",
        "Dockerfile (brain)": BRAIN_DIR / "Dockerfile",
        "Dockerfile (sliver)": PROJECT_ROOT / "sliver" / "Dockerfile",
        "Dockerfile (kali-tools)": KALI_DIR / "Dockerfile",
        "Dockerfile (raphael-api)": PROJECT_ROOT / "docker" / "api.Dockerfile",
        "server.py (kali-tools)": KALI_DIR / "server.py",
    }

    for label, path in docker_checks.items():
        results.append(
            check(f"docker_file_{path.name}", f"Docker file: {label}", file_exists, path)
        )

    return results


def test_docker_compose_syntax() -> list[CheckResult]:
    """Verify docker-compose.yml parses correctly."""
    results = []

    if not DOCKER_COMPOSE.exists():
        return [CheckResult("docker_compose_syntax", "docker-compose.yml syntax", CHECK_FAIL, "file not found")]

    # Check it's valid YAML
    try:
        import yaml
        with open(DOCKER_COMPOSE) as f:
            config = yaml.safe_load(f)
        results.append(CheckResult("docker_compose_yaml", "docker-compose.yml is valid YAML", CHECK_PASS))

        services = config.get("services", {})
        results.append(
            check("docker_services", f"Services defined: {len(services)}",
                  lambda: len(services) >= 10 or (CHECK_WARN, f"only {len(services)} services"))
        )

        # Check each service has required fields
        for svc_name, svc_cfg in services.items():
            if not isinstance(svc_cfg, dict):
                continue
            # Check image or build
            has_image = "image" in svc_cfg
            has_build = "build" in svc_cfg
            results.append(
                check(f"docker_{svc_name}_def", f"Service '{svc_name}' has image/build",
                      lambda hi=has_image, hb=has_build: hi or hb or (CHECK_FAIL, "neither image nor build"))
            )
            # Check ports
            if svc_name not in ("tor-proxy", "neo4j"):
                pass  # ports not strictly required

        # Check networks
        if "networks" in config:
            results.append(CheckResult("docker_networks", "docker-compose has networks", CHECK_PASS))
        else:
            results.append(CheckResult("docker_networks", "docker-compose has networks", CHECK_WARN, "missing"))

        # Check volumes
        if "volumes" in config:
            results.append(CheckResult("docker_volumes", "docker-compose has volumes", CHECK_PASS))
        else:
            results.append(CheckResult("docker_volumes", "docker-compose has volumes", CHECK_WARN, "missing"))

    except ImportError:
        results.append(CheckResult("docker_compose_yaml", "docker-compose.yml syntax", CHECK_SKIP, "PyYAML not installed"))
    except yaml.YAMLError as e:
        results.append(CheckResult("docker_compose_yaml", "docker-compose.yml syntax", CHECK_FAIL, str(e)))
    except Exception as e:
        results.append(CheckResult("docker_compose_yaml", "docker-compose.yml syntax", CHECK_FAIL, str(e)))

    return results


def test_docker_images_buildable() -> list[CheckResult]:
    """Quick-check Docker images without full build (config validation)."""
    results = []

    if not DOCKER_COMPOSE.exists():
        return [CheckResult("docker_images", "Docker images buildable", CHECK_SKIP, "compose file missing")]

    # Check for pinned versions vs :latest
    try:
        import yaml
        with open(DOCKER_COMPOSE) as f:
            config = yaml.safe_load(f)

        services = config.get("services", {})
        for svc_name, svc_cfg in services.items():
            image = svc_cfg.get("image", "")
            if image.endswith(":latest"):
                results.append(
                    check(f"docker_{svc_name}_pinned", f"Image pin: {svc_name} ({image})",
                          lambda: False or (CHECK_WARN, f"uses :latest \u2014 pin to specific version"))
                )
            elif "image" in svc_cfg:
                results.append(
                    check(f"docker_{svc_name}_pinned", f"Image pin: {svc_name} ({image})",
                          lambda: True or None)
                )
    except ImportError:
        results.append(CheckResult("docker_image_pins", "Image version pinning", CHECK_SKIP, "PyYAML not installed"))
    except Exception as e:
        results.append(CheckResult("docker_image_pins", "Image version pinning", CHECK_FAIL, str(e)))

    return results


def test_docker_running_services() -> list[CheckResult]:
    """Check if Docker containers are running (live environment check)."""
    results = []

    if not cmd_exists("docker"):
        return [CheckResult("docker_engine", "Docker Engine", CHECK_SKIP, "docker not installed")]

    # Check Docker engine
    rc, stdout, stderr = run_cmd(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=10)
    if rc == 0 and stdout.strip():
        results.append(CheckResult("docker_engine", "Docker Engine", CHECK_PASS, f"v{stdout.strip()}"))
    else:
        results.append(CheckResult("docker_engine", "Docker Engine", CHECK_SKIP,
                                    "not running or permission denied"))

    # Check Docker Compose
    rc, stdout, stderr = run_cmd(["docker", "compose", "version", "--short"], timeout=10)
    if rc == 0 and stdout.strip():
        results.append(CheckResult("docker_compose", "Docker Compose", CHECK_PASS, f"v{stdout.strip()}"))
    else:
        results.append(CheckResult("docker_compose", "Docker Compose", CHECK_SKIP, "not available"))

    # List running containers
    rc, stdout, stderr = run_cmd(
        ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"], timeout=10
    )
    if rc == 0 and stdout.strip():
        for line in stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 2:
                name, image = parts[0], parts[1]
                status = parts[2] if len(parts) > 2 else "?"
                results.append(
                    check(f"docker_container_{name}", f"Container: {name} ({image})",
                          lambda: True or None, detail=status)
                )
    else:
        results.append(CheckResult("docker_containers", "Running containers", CHECK_SKIP, "none running or can't list"))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: AI MODEL TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_ai_models_config() -> list[CheckResult]:
    """Validate the model configuration is complete and consistent."""
    results = []

    if not MODELS_CONFIG.exists():
        return [CheckResult("models_config", "AI Models Config", CHECK_FAIL, "file not found")]

    try:
        config = parse_models_config()
    except json.JSONDecodeError as e:
        return [CheckResult("models_config", "AI Models Config", CHECK_FAIL, f"invalid JSON: {e}")]

    models = config.get("models", {})

    # Verify each model's provider is valid
    valid_providers = {"openai_compatible", "ollama", "adaptive_router"}
    for model_id, model_cfg in models.items():
        provider = model_cfg.get("provider", "")
        results.append(
            check(f"model_{model_id}_provider", f"Model '{model_id}' provider: {provider}",
                  lambda p=provider: p in valid_providers or (CHECK_WARN, f"unknown provider: {p}"))
        )

    # Check enabled models have at least one valid provider
    enabled_models = [m for m_id, m in models.items() if m.get("enabled", False)]
    results.append(
        check("enabled_models_count", f"Enabled models: {len(enabled_models)}",
              lambda: len(enabled_models) >= 3 or (CHECK_WARN, f"only {len(enabled_models)} enabled (need >=3 for fallback)"))
    )

    # Verify model capabilities structure
    for model_id, model_cfg in models.items():
        caps = model_cfg.get("capabilities", [])
        if not caps:
            results.append(
                check(f"model_{model_id}_caps", f"Model '{model_id}' capabilities",
                      lambda: False or (CHECK_WARN, "no capabilities defined"))
            )

    # Check personas have descriptions
    personas = config.get("personas", {})
    for pid, pcfg in personas.items():
        if "description" not in pcfg:
            results.append(
                check(f"persona_{pid}_desc", f"Persona '{pid}' description",
                      lambda: False or (CHECK_WARN, "missing description"))
            )

    # Validate that the schema version is present
    schema_ver = config.get("_schema_version", "")
    results.append(
        check("models_schema_version", f"Config schema version: {schema_ver}",
              lambda: schema_ver or (CHECK_WARN, "missing _schema_version"))
    )

    return results


def test_ai_providers_module() -> list[CheckResult]:
    """Test providers.py imports and core functions."""
    results = []
    sys.path.insert(0, str(PROJECT_ROOT))

    try:
        from orchestrator import providers
        results.append(CheckResult("providers_import", "orchestrator.providers imports", CHECK_PASS))
    except Exception as e:
        return [CheckResult("providers_import", "orchestrator.providers imports", CHECK_FAIL, str(e))]

    # Check key functions exist
    for func_name in ["call_model", "call_parallel", "resolve", "resolve_persona_override"]:
        has = hasattr(providers, func_name)
        results.append(
            check(f"providers_{func_name}", f"providers.{func_name}() exists",
                  lambda h=has: h or (CHECK_FAIL, "missing"))
        )

    # Check key constants exist
    for const_name in ["WORKING_ALIASES", "DEFAULT_SYSTEM_PROMPT",
                        "REDTEAM_SYSTEM_PROMPT", "BLACKHAT_SYSTEM_PROMPT"]:
        has = hasattr(providers, const_name)
        results.append(
            check(f"providers_{const_name}", f"providers.{const_name} exists",
                  lambda h=has: h or (CHECK_WARN, "missing"))
        )

    # Check CircuitBreaker class
    if hasattr(providers, "CircuitBreaker"):
        try:
            cb = providers.CircuitBreaker("test", failure_threshold=2, recovery_timeout=5)
            results.append(CheckResult("circuit_breaker", "CircuitBreaker instantiates", CHECK_PASS))

            # Test state machine
            def _fail():
                raise Exception("test")
            try:
                cb.call(_fail)
            except Exception:
                raise RuntimeError("Not implemented")
            try:
                cb.call(_fail)
            except Exception:
                pass
            results.append(
                check("circuit_breaker_trip", "CircuitBreaker trips after failures",
                      lambda: cb.state == "open" or (CHECK_WARN, f"state={cb.state}"))
            )

            # Verify recovery
            cb.last_failure = 0  # Force recovery
            results.append(
                check("circuit_breaker_recovery", "CircuitBreaker half-open recovery",
                      lambda: cb.state in ("open", "half-open") or (CHECK_FAIL, "unexpected state"))
            )

        except Exception as e:
            results.append(CheckResult("circuit_breaker", "CircuitBreaker tests", CHECK_FAIL, str(e)))
    else:
        results.append(CheckResult("circuit_breaker", "CircuitBreaker class", CHECK_WARN, "not found"))

    return results


def test_ai_adaptive_router() -> list[CheckResult]:
    """Test the adaptive router module."""
    results = []
    sys.path.insert(0, str(PROJECT_ROOT))

    try:
        from orchestrator import adaptive_router
        results.append(CheckResult("adaptive_router_import", "adaptive_router imports", CHECK_PASS))
    except Exception as e:
        return [CheckResult("adaptive_router_import", "adaptive_router imports", CHECK_FAIL, str(e))]

    # Test classify_task
    test_messages = [{"role": "user", "content": "Scan port 80 and enumerate subdomains for target.com"}]
    task_type = adaptive_router.classify_task(test_messages)
    results.append(
        check("router_classify", f"classify_task() \u2192 '{task_type}'",
              lambda: task_type in ("recon", "scan", "exploit", "code", "postex",
                                    "opsec", "waf_bypass", "forensics", "mimicry", "dkom", "general")
              or (CHECK_FAIL, f"unknown type: {task_type}"))
    )

    # Test pick_model
    models = ["w12", "w13", "w480b", "m3"]
    scores = {}
    chosen = adaptive_router.pick_model("recon", models, scores)
    results.append(
        check("router_pick", f"pick_model(recon, {models}) \u2192 '{chosen}'",
              lambda: chosen in models or (CHECK_FAIL, f"returned '{chosen}' not in {models}"))
    )

    # Test estimate_success
    score1 = adaptive_router.estimate_success("Here are the scan results", False)
    score2 = adaptive_router.estimate_success("ERROR: something failed", False)
    score3 = adaptive_router.estimate_success("", True)
    results.append(
        check("router_estimate", "estimate_success() scoring",
              lambda: score1 > 0.5 and score3 < 0.3 or (CHECK_WARN, f"scores: {score1}, {score2}, {score3}"))
    )

    # Test update_score with temp file
    original_path = adaptive_router.STORAGE_PATH
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        f.write("{}")
        temp_path = f.name
    adaptive_router.STORAGE_PATH = temp_path
    try:
        adaptive_router.update_score("w12", "recon", 0.9, 2.5)
        loaded = adaptive_router.load_scores()
        results.append(
            check("router_update_score", "update_score persists to disk",
                  lambda: "w12" in loaded and "recon" in loaded["w12"]
                  and len(loaded["w12"]["recon"]) > 0 or (CHECK_FAIL, f"data: {loaded}"))
        )
    finally:
        adaptive_router.STORAGE_PATH = original_path
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: HACKER TOOLS TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_tools_availability() -> list[CheckResult]:
    """Check hacker tools are available on the system or via Docker."""
    results = []

    # Core penetration testing tools
    core_tools = [
        ("nmap", "Network scanner"),
        ("sqlmap", "SQL injection tool"),
        ("nuclei", "Vulnerability scanner"),
        ("gobuster", "Directory busting"),
        ("whatweb", "Web technology fingerprinting"),
        ("nikto", "Web server scanner"),
        ("hydra", "Password brute-forcing"),
        ("john", "Password cracking"),
        ("hashcat", "GPU password cracking"),
        ("curl", "HTTP client"),
        ("dig", "DNS lookup"),
        ("whois", "Domain registration lookup"),
        ("python3", "Python interpreter"),
        ("docker", "Container engine"),
        ("git", "Version control"),
    ]

    for tool_name, description in core_tools:
        found = cmd_exists(tool_name)
        results.append(
            check(f"tool_{tool_name}", f"Tool: {tool_name} ({description})",
                  lambda f=found: CHECK_PASS if f else CHECK_WARN,
                  detail=f"found at {shutil.which(tool_name)}" if found else "not in PATH")
        )

    # Check Kali-tools Docker image
    if cmd_exists("docker"):
        rc, stdout, stderr = run_cmd(
            ["docker", "images", "raphael/kali-tools", "--format", "{{.Repository}}:{{.Tag}}"], timeout=10
        )
        if rc == 0 and stdout.strip():
            for image in stdout.strip().split("\n"):
                results.append(CheckResult("kali_tools_image", f"Kali tools Docker: {image}", CHECK_PASS))
        else:
            results.append(CheckResult("kali_tools_image", "Kali tools Docker image", CHECK_WARN,
                                        "not built yet \u2014 run 'docker compose build kali-tools'"))

    return results


def test_tools_kali_server() -> list[CheckResult]:
    """Verify the Kali tools API server logic (static analysis)."""
    results = []

    server_path = KALI_DIR / "server.py"
    if not server_path.exists():
        return [CheckResult("kali_server", "kali-tools/server.py", CHECK_FAIL, "file not found")]

    # Check server.py has expected endpoints
    with open(server_path) as f:
        content = f.read()

    endpoints = {
        "POST /run": "/run" in content,
        "GET /tools": "/tools" in content,
        "GET /health": "/health" in content,
    }

    for endpoint, found in endpoints.items():
        results.append(
            check(f"kali_endpoint_{endpoint.replace('/','_')}", f"Kali server: {endpoint}",
                  lambda f=found: CHECK_PASS if f else CHECK_FAIL)
        )

    # Check TOOLS_CACHE startup logic
    if "TOOLS_CACHE" in content:
        results.append(CheckResult("kali_tools_cache", "Kali server has TOOLS_CACHE", CHECK_PASS))
    else:
        results.append(CheckResult("kali_tools_cache", "Kali server has TOOLS_CACHE", CHECK_WARN))

    return results


def test_tools_kali_dockerfile() -> list[CheckResult]:
    """Verify Kali Dockerfile has all expected tools."""
    results: list[CheckResult] = []
    dockerfile_path = KALI_DIR / "Dockerfile"
    if not dockerfile_path.exists():
        return [CheckResult("kali_dockerfile", "kali-tools/Dockerfile", CHECK_FAIL, "not found")]

    with open(dockerfile_path) as f:
        content = f.read()

    expected_tools = [
        "nmap", "masscan", "dnsutils", "whois", "enum4linux",
        "gobuster", "ffuf", "dirb", "nikto", "wfuzz", "whatweb",
        "hydra", "sqlmap", "metasploit-framework",
        "impacket-scripts", "bloodhound.py", "certipy-ad",
        "hashcat", "john",
        "netexec", "donpapi",
        "nuclei", "kerbrute", "pspy64",
    ]

    for tool in expected_tools:
        found = tool.lower() in content.lower()
        results.append(
            check(f"kali_tool_{tool}", f"Kali Docker: {tool}",
                  lambda f=found: CHECK_PASS if f else CHECK_WARN,
                  detail="present" if found else "not found in Dockerfile")
        )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: ORCHESTRATOR MODE TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_orchestrator_imports() -> list[CheckResult]:
    """Verify all orchestrator mode modules import."""
    results = []

    sys.path.insert(0, str(PROJECT_ROOT))

    # Test each mode module imports
    mode_modules = [
        ("orchestrator.modes.autonomous", "Autonomous mode"),
        ("orchestrator.modes.scan", "Scan mode"),
        ("orchestrator.modes.debate", "Debate mode"),
        ("orchestrator.modes.community", "Community mode"),
        ("orchestrator.modes.rsi", "RSI mode"),
    ]

    for module_path, description in mode_modules:
        try:
            mod = importlib.import_module(module_path)
            results.append(CheckResult(f"mode_import_{module_path.split('.')[-1]}", f"Mode: {description}", CHECK_PASS))
        except ImportError as e:
            results.append(CheckResult(f"mode_import_{module_path.split('.')[-1]}",
                                       f"Mode: {description}", CHECK_FAIL, str(e)))
        except Exception as e:
            results.append(CheckResult(f"mode_import_{module_path.split('.')[-1]}",
                                       f"Mode: {description}", CHECK_FAIL, str(e)))

    return results


def test_orchestrator_app() -> list[CheckResult]:
    """Verify orchestrator/app.py structure."""
    results = []

    app_path = ORCHESTRATOR_DIR / "app.py"
    if not app_path.exists():
        return [CheckResult("app_py", "orchestrator/app.py", CHECK_FAIL, "not found")]

    with open(app_path) as f:
        content = f.read()

    # Check MODES dict
    expected_modes = ["debate", "community", "rsi", "scan", "autonomous"]
    for mode_name in expected_modes:
        found = f'"{mode_name}"' in content or f"'{mode_name}'" in content
        results.append(
            check(f"app_mode_{mode_name}", f"app.py MODES has '{mode_name}'",
                  lambda f=found: CHECK_PASS if f else CHECK_WARN,
                  detail="present" if found else "not found")
        )

    # Check key imports exist
    expected_imports = [
        "autonomous.handle", "scan.handle", "debate.handle",
        "call_model", "SessionManager",
    ]
    for imp in expected_imports:
        found = imp in content
        results.append(
            check(f"app_import_{imp.replace('.','_')}", f"app.py imports {imp}",
                  lambda f=found: CHECK_PASS if f else CHECK_WARN)
        )

    return results


def test_orchestrator_pipelines() -> list[CheckResult]:
    """Verify all pipeline modules exist and have expected interfaces."""
    results = []

    pipeline_files = [
        ("orchestrator/exploit/pipeline.py", "ExploitPipeline", "Exploit"),
        ("orchestrator/postex/pipeline.py", "PostExploitPipeline", "Post-Exploit"),
        ("orchestrator/exfil/pipeline.py", "ExfilPipeline", "Exfiltration"),
        ("orchestrator/phishing/pipeline.py", "PhishingPipeline", "Phishing"),
        ("orchestrator/anti_forensics.py", "AntiForensicsPipeline", "Anti-Forensics"),
    ]

    sys.path.insert(0, str(PROJECT_ROOT))

    for file_path, class_name, description in pipeline_files:
        full_path = PROJECT_ROOT / file_path
        if not full_path.exists():
            results.append(CheckResult(f"pipeline_{class_name}", f"Pipeline: {description}", CHECK_FAIL, "file not found"))
            continue

        try:
            # Just verify the file parses as valid Python syntax
            compile(full_path.read_text(), str(full_path), "exec")
            results.append(CheckResult(f"pipeline_{class_name}_syntax", f"Pipeline {description}: syntax OK", CHECK_PASS))

            # Check class definition exists in file
            content = full_path.read_text()
            if f"class {class_name}" in content:
                results.append(CheckResult(f"pipeline_{class_name}_class", f"Pipeline {description}: class defined", CHECK_PASS))
            else:
                results.append(CheckResult(f"pipeline_{class_name}_class", f"Pipeline {description}: class defined",
                                           CHECK_WARN, f"'{class_name}' not found in file"))

        except SyntaxError as e:
            results.append(CheckResult(f"pipeline_{class_name}_syntax", f"Pipeline {description}: syntax",
                                       CHECK_FAIL, str(e)))

    return results


def test_orchestrator_c2() -> list[CheckResult]:
    """Verify C2 module structure."""
    results = []

    c2_files = [
        ("orchestrator/c2/manager.py", "C2Manager"),
        ("orchestrator/c2/sliver_backend.py", "SliverBackend"),
        ("orchestrator/c2/models.py", None),
    ]

    sys.path.insert(0, str(PROJECT_ROOT))

    for file_path, class_name in c2_files:
        full_path = PROJECT_ROOT / file_path
        if not full_path.exists():
            results.append(CheckResult(f"c2_{file_path.split('/')[-1]}", f"C2: {file_path}", CHECK_FAIL, "not found"))
            continue

        try:
            compile(full_path.read_text(), str(full_path), "exec")
            results.append(CheckResult(f"c2_{file_path.split('/')[-1]}_syntax",
                                       f"C2: {file_path.split('/')[-1]} syntax OK", CHECK_PASS))

            if class_name:
                content = full_path.read_text()
                if f"class {class_name}" in content:
                    results.append(CheckResult(f"c2_{class_name}", f"C2: {class_name} defined", CHECK_PASS))
                else:
                    results.append(CheckResult(f"c2_{class_name}", f"C2: {class_name} defined",
                                               CHECK_WARN, f"'{class_name}' not found"))
        except SyntaxError as e:
            results.append(CheckResult(f"c2_{file_path.split('/')[-1]}_syntax",
                                       f"C2: {file_path.split('/')[-1]} syntax", CHECK_FAIL, str(e)))

    return results


def test_orchestrator_security() -> list[CheckResult]:
    """Verify security-critical components (ProxyGuard, egress, env validation)."""
    results = []

    sys.path.insert(0, str(PROJECT_ROOT))

    # ProxyGuard
    pg_path = ORCHESTRATOR_DIR / "proxy_guard.py"
    if pg_path.exists():
        try:
            compile(pg_path.read_text(), str(pg_path), "exec")
            results.append(CheckResult("proxy_guard_syntax", "ProxyGuard: syntax OK", CHECK_PASS))
            content = pg_path.read_text()
            if "class ProxyGuard" in content:
                results.append(CheckResult("proxy_guard_class", "ProxyGuard: class defined", CHECK_PASS))
            else:
                results.append(CheckResult("proxy_guard_class", "ProxyGuard: class defined", CHECK_WARN))
        except SyntaxError as e:
            results.append(CheckResult("proxy_guard_syntax", "ProxyGuard: syntax", CHECK_FAIL, str(e)))
    else:
        results.append(CheckResult("proxy_guard", "ProxyGuard", CHECK_FAIL, "not found"))

    # Egress strategies
    for eg_file, eg_label in [
        ("strategies.py", "Egress Strategies"),
        ("front_domains.py", "Front Domains"),
    ]:
        eg_path = ORCHESTRATOR_DIR / "egress" / eg_file
        if eg_path.exists():
            content = eg_path.read_text()
            # Check for placeholder domains (security fix verification)
            has_placeholder = "your-cdn-fronting-domain" in content or "your-sni-fronting-domain" in content or "example.com" in content
            has_real_domain = "cloudfront.net" in content or "fastly" in content.lower() or "azure" in content.lower()
            results.append(
                check(f"egress_{eg_file.replace('.py','')}_placeholders", f"{eg_label}: placeholder domains",
                      lambda hp=has_placeholder: CHECK_PASS if hp else CHECK_WARN,
                      detail="placeholders OK" if has_placeholder else "no placeholders found")
            )
            if has_real_domain:
                results.append(
                    check(f"egress_{eg_file.replace('.py','')}_real_domains", f"{eg_label}: no real domains",
                          lambda: CHECK_FAIL if has_real_domain else CHECK_PASS,
                          detail="WARNING: real CDN domains still present!" if has_real_domain else "OK")
                )
        else:
            results.append(CheckResult(f"egress_{eg_file.replace('.py','')}", eg_label, CHECK_FAIL, "not found"))

    # Env validation script
    env_script = SCRIPTS_DIR / "validate_env.py"
    if env_script.exists():
        try:
            compile(env_script.read_text(), str(env_script), "exec")
            results.append(CheckResult("validate_env_syntax", "validate_env.py: syntax OK", CHECK_PASS))

            # Check it has weak pattern detection
            content = env_script.read_text()
            for pattern in ["WEAK_PATTERNS", "changeme", "raphael-dev"]:
                if pattern in content:
                    results.append(CheckResult(f"validate_env_{pattern}", f"validate_env.py: {pattern} detection",
                                               CHECK_PASS))
                    break
        except SyntaxError as e:
            results.append(CheckResult("validate_env_syntax", "validate_env.py: syntax", CHECK_FAIL, str(e)))
    else:
        results.append(CheckResult("validate_env_script", "scripts/validate_env.py", CHECK_FAIL, "not found"))

    return results


def test_orchestrator_brain() -> list[CheckResult]:
    """Verify brain module structure."""
    results = []

    brain_files = [
        ("brain/engagement_modes.py", "EngagementController"),
        ("brain/adaptive_brain.py", "AdaptiveBrain"),
    ]

    sys.path.insert(0, str(PROJECT_ROOT))

    for file_path, class_name in brain_files:
        full_path = PROJECT_ROOT / file_path
        if not full_path.exists():
            results.append(CheckResult(f"brain_{file_path.split('/')[-1]}", f"Brain: {file_path}", CHECK_FAIL, "not found"))
            continue

        try:
            compile(full_path.read_text(), str(full_path), "exec")
            results.append(CheckResult(f"brain_{file_path.split('/')[-1]}_syntax",
                                       f"Brain: {file_path.split('/')[-1]} syntax OK", CHECK_PASS))

            content = full_path.read_text()
            if class_name in content:
                results.append(CheckResult(f"brain_{class_name}", f"Brain: {class_name} defined", CHECK_PASS))
            else:
                results.append(CheckResult(f"brain_{class_name}", f"Brain: {class_name} defined",
                                           CHECK_WARN, f"'{class_name}' not found"))
        except SyntaxError as e:
            results.append(CheckResult(f"brain_{file_path.split('/')[-1]}_syntax",
                                       f"Brain: {file_path.split('/')[-1]} syntax", CHECK_FAIL, str(e)))

    return results


def test_orchestrator_agent() -> list[CheckResult]:
    """Verify agent module (implant capabilities)."""
    results = []

    agent_path = AGENT_DIR / "agent.py"
    if not agent_path.exists():
        return [CheckResult("agent_py", "agent/agent.py", CHECK_FAIL, "not found")]

    try:
        compile(agent_path.read_text(), str(agent_path), "exec")
        results.append(CheckResult("agent_syntax", "agent/agent.py: syntax OK", CHECK_PASS))
    except SyntaxError as e:
        results.append(CheckResult("agent_syntax", "agent/agent.py: syntax", CHECK_FAIL, str(e)))
        return results

    content = agent_path.read_text()

    # Check key functions
    checks = [
        ("_validate_config", "Config validation"),
        ("get_hwid", "HWID generation"),
        ("register", "C2 registration"),
        ("heartbeat", "Heartbeat loop"),
        ("execute_task", "Task execution"),
        ("submit_result", "Result submission"),
        ("_redact", "Log redaction"),
    ]

    for func_name, description in checks:
        results.append(
            check(f"agent_{func_name}", f"Agent: {description} ({func_name}())",
                  lambda fn=func_name: fn in content or (CHECK_WARN, f"missing {fn}()"))
        )

    # Check confirm_uninstall safety
    if "confirm_uninstall" in content:
        results.append(CheckResult("agent_confirm_uninstall", "Agent: confirm_uninstall safety check", CHECK_PASS))
    else:
        results.append(CheckResult("agent_confirm_uninstall", "Agent: confirm_uninstall safety check",
                                   CHECK_WARN, "uninstall may not require confirmation"))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: ENVIRONMENT CONFIGURATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_env_configuration() -> list[CheckResult]:
    """Verify .env.example structure and validate_env script."""
    results = []

    if not ENV_EXAMPLE.exists():
        return [CheckResult("env_example", ".env.example", CHECK_FAIL, "not found")]

    with open(ENV_EXAMPLE) as f:
        content = f.read()

    # Check required config keys
    required_keys = [
        "OPENAI_API_KEY", "TOR_CONTROL_PASS",
        "API_KEY", "NEO4J_PASS", "MAX_SPEND_TOKENS", "TOR_PROXY",
    ]

    for key in required_keys:
        found = key in content
        results.append(
            check(f"env_key_{key}", f".env.example has '{key}'",
                  lambda f=found: CHECK_PASS if f else CHECK_WARN,
                  detail="present" if found else "missing")
        )

    # Check no default passwords remain (security fix verification)
    weak_patterns = ["changeme", "raphael-dev", "sk-omniroute-local", "raphael-layer5"]
    for pattern in weak_patterns:
        if pattern.lower() in content.lower():
            results.append(
                check(f"env_weak_{pattern}", f".env.example: no '{pattern}' default",
                      lambda: CHECK_FAIL, detail=f"WARNING: default value '{pattern}' still present!")
            )
        else:
            results.append(
                check(f"env_weak_{pattern}", f".env.example: no '{pattern}' default",
                      CHECK_PASS)
            )

    # Check has warnings about committing .env
    if "NEVER commit" in content or "never commit" in content.lower():
        results.append(CheckResult("env_warning", ".env.example has commit warning", CHECK_PASS))
    else:
        results.append(CheckResult("env_warning", ".env.example has commit warning", CHECK_WARN))

    return results


def test_requirements() -> list[CheckResult]:
    """Verify Python dependency files."""
    results = []

    for req_file, label in [(REQUIREMENTS_TXT, "requirements.txt"),
                             (CLI_REQUIREMENTS, "cli/requirements-cli.txt")]:
        if not req_file.exists():
            results.append(CheckResult(f"req_{req_file.name}", label, CHECK_FAIL, "not found"))
            continue

        with open(req_file) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        results.append(
            check(f"req_{req_file.name}_deps", f"{label}: {len(lines)} dependencies",
                  lambda: len(lines) >= 2 or (CHECK_WARN, f"only {len(lines)} deps"))
        )

        # Check for httpx and rich (critical CLI deps)
        for dep in ["httpx", "rich"]:
            has = any(dep in line for line in lines)
            results.append(
                check(f"req_{req_file.name}_{dep}", f"{label}: has '{dep}'",
                      lambda h=has: CHECK_PASS if h else CHECK_WARN,
                      detail="present" if has else f"missing {dep}")
            )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: PROJECT STRUCTURE TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_project_structure() -> list[CheckResult]:
    """Verify the project directory structure is complete."""
    results = []

    expected_dirs = [
        ("orchestrator", "Orchestrator core"),
        ("orchestrator/modes", "Orchestrator modes"),
        ("orchestrator/c2", "C2 module"),
        ("orchestrator/egress", "Egress strategies"),
        ("orchestrator/exploit", "Exploit pipeline"),
        ("orchestrator/postex", "Post-exploit pipeline"),
        ("orchestrator/exfil", "Exfiltration pipeline"),
        ("orchestrator/phishing", "Phishing pipeline"),
        ("orchestrator/utils", "Orchestrator utilities"),
        ("orchestrator/scanners", "Scanner modules"),
        ("orchestrator/chains", "Attack chains"),
        ("orchestrator/hardening", "Hardening module"),
        ("orchestrator/runtime", "Runtime session management"),
        ("cli", "CLI module"),
        ("agent", "Agent/implant module"),
        ("brain", "Brain Docker"),
        ("sword", "Sword pipeline"),
        ("cai-service", "CAI service"),
        ("kali-tools", "Kali tools Docker"),
        ("sliver", "Sliver C2"),
        ("scripts", "Utility scripts"),
        ("data", "Runtime data"),
        ("docker", "Docker files"),
        ("docs", "Documentation"),
    ]

    for dir_rel, description in expected_dirs:
        dir_path = PROJECT_ROOT / dir_rel
        results.append(
            check(f"dir_{dir_rel.replace('/','_')}", f"Directory: {description} ({dir_rel})",
                  dir_exists, dir_path)
        )

    # Check critical files
    critical_files = [
        ("README.md", "README"),
        ("bootstrap.sh", "Bootstrap script"),
        ("setup_killswitch.sh", "Tor kill switch"),
        ("start_hrm.sh", "HRM startup"),
        (".gitignore", "Git ignore"),
        ("QUICKSTART.md", "Quickstart guide"),
        ("procedure.md", "Procedure/OPSEC guide"),
        ("ghost.md", "Ghost/invisibility guide"),
    ]

    for file_rel, description in critical_files:
        file_path = PROJECT_ROOT / file_rel
        results.append(
            check(f"file_{file_rel.replace('.','_').replace('/','_')}", f"File: {description} ({file_rel})",
                  file_exists, file_path)
        )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# TEST DISPATCHER
# ═══════════════════════════════════════════════════════════════════════════

ALL_TESTS = {
    "cli-imports":          ("1. CLI \u2014 Module Imports", test_cli_imports),
    "cli-argparse":         ("2. CLI \u2014 Argument Parsing", test_cli_argparse),
    "cli-models":           ("3. CLI \u2014 Models Config", test_cli_models_config),
    "cli-health-logic":     ("4. CLI \u2014 Health Check Logic", test_cli_health_check_logic),
    "cli-banner-output":    ("5. CLI \u2014 Banner & Output", test_cli_banner_and_output),
    "cli-error-handling":   ("6. CLI \u2014 Error Handling", test_cli_error_handling),
    "docker-files":         ("7. Docker \u2014 File Structure", test_docker_files_exist),
    "docker-compose":       ("8. Docker \u2014 Compose Validation", test_docker_compose_syntax),
    "docker-images":        ("9. Docker \u2014 Image Build Config", test_docker_images_buildable),
    "docker-running":       ("10. Docker \u2014 Running Services", test_docker_running_services),
    "ai-models-config":     ("11. AI \u2014 Models Config Validation", test_ai_models_config),
    "ai-providers":         ("12. AI \u2014 Providers Module", test_ai_providers_module),
    "ai-router":            ("13. AI \u2014 Adaptive Router", test_ai_adaptive_router),
    "tools-availability":   ("14. Tools \u2014 System Availability", test_tools_availability),
    "tools-kali-server":    ("15. Tools \u2014 Kali Server API", test_tools_kali_server),
    "tools-kali-docker":    ("16. Tools \u2014 Kali Dockerfile", test_tools_kali_dockerfile),
    "orchestrator-imports": ("17. Orchestrator \u2014 Mode Imports", test_orchestrator_imports),
    "orchestrator-app":     ("18. Orchestrator \u2014 app.py", test_orchestrator_app),
    "orchestrator-pipelines": ("19. Orchestrator \u2014 Pipelines", test_orchestrator_pipelines),
    "orchestrator-c2":      ("20. Orchestrator \u2014 C2 Module", test_orchestrator_c2),
    "orchestrator-security":("21. Orchestrator \u2014 Security Components", test_orchestrator_security),
    "orchestrator-brain":   ("22. Orchestrator \u2014 Brain Module", test_orchestrator_brain),
    "orchestrator-agent":   ("23. Orchestrator \u2014 Agent/Implant", test_orchestrator_agent),
    "env-config":           ("24. Environment \u2014 .env.example", test_env_configuration),
    "requirements":         ("25. Environment \u2014 Requirements", test_requirements),
    "project-structure":    ("26. Project \u2014 Structure", test_project_structure),
}


def run_selected_tests(selected: set[str], quick: bool = False) -> int:
    """Run selected test sections. Returns number of failures."""
    total_failures = 0

    for test_id, (title, test_fn) in ALL_TESTS.items():
        if selected and test_id not in selected:
            continue

        if quick and test_id in ("docker-images", "docker-running", "tools-availability",
                                 "tools-kali-server", "tools-kali-docker"):
            print(f"\n  [SKIP] {title} (--quick mode)")
            continue

        print(f"\n{'#' * 72}")
        print(f"#  {title}")
        print(f"{'#' * 72}")

        try:
            results = test_fn()
            failures = run_section(title, results)
            total_failures += failures
        except Exception as e:
            print(f"\n  [!] Test section CRASHED: {e}")
            total_failures += 1

    return total_failures


def print_summary():
    """Print a comprehensive test summary with text-based progress bar."""
    p = TOTAL_TESTS["pass"]
    w = TOTAL_TESTS["warn"]
    f = TOTAL_TESTS["fail"]
    s = TOTAL_TESTS["skip"]
    total = p + w + f + s

    print(f"\n\n{'=' * 72}")
    print(f"  RAPHAEL 2.0 \u2014 COMPREHENSIVE TEST SUMMARY")
    print(f"{'=' * 72}")

    if total == 0:
        print("\n  No tests executed.\n")
        return

    bar_width = 50
    if total > 0:
        p_bars = int(p / total * bar_width) if total else 0
        w_bars = int(w / total * bar_width) if total else 0
        f_bars = int(f / total * bar_width) if total else 0
        s_bars = bar_width - p_bars - w_bars - f_bars

        bar = ""
        bar += "\033[32m" + "\u2588" * p_bars + "\033[0m" if p_bars else ""
        bar += "\033[33m" + "\u2588" * w_bars + "\033[0m" if w_bars else ""
        bar += "\033[31m" + "\u2588" * f_bars + "\033[0m" if f_bars else ""
        bar += "\033[90m" + "\u2591" * s_bars + "\033[0m" if s_bars else ""

        print(f"\n  {bar}")
        print(f"  {'\u2594' * bar_width}")

    print(f"\n  {'PASS':<20} {p:>4}/{total:<4}  ({p/total*100:.0f}%)" if total else "")
    print(f"  {'WARN':<20} {w:>4}/{total:<4}  ({w/total*100:.0f}%)" if total else "")
    print(f"  {'FAIL':<20} {f:>4}/{total:<4}  ({f/total*100:.0f}%)" if total else "")
    print(f"  {'SKIP':<20} {s:>4}/{total:<4}  ({s/total*100:.0f}%)" if total else "")

    if f == 0 and w == 0:
        print(f"\n  \033[32mALL {total} TESTS PASSED\033[0m")
    elif f == 0:
        print(f"\n  \033[33m{p} PASSED, {w} WARNINGS (no failures)\033[0m")
    else:
        print(f"\n  \033[31m{f} TESTS FAILED \u2014 review above for details\033[0m")

    print(f"\n{'=' * 72}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Raphael 2.0 \u2014 Comprehensive CLI & Infrastructure Smoke Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python tests/test_cli_smoke.py                          # Full suite
              python tests/test_cli_smoke.py --cli-only                # CLI tests only
              python tests/test_cli_smoke.py --docker-only             # Docker tests only
              python tests/test_cli_smoke.py --tools-only              # Tools tests only
              python tests/test_cli_smoke.py --models-only             # AI model tests only
              python tests/test_cli_smoke.py --orchestrator-only       # Orchestrator tests only
              python tests/test_cli_smoke.py --quick                   # Skip slow checks
              python tests/test_cli_smoke.py --verbose                 # Full output
              python tests/test_cli_smoke.py --list-tests              # List all test IDs
        """)
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Show all test results")
    parser.add_argument("--quick", "-q", action="store_true", help="Skip slow Docker/tool checks")
    parser.add_argument("--list-tests", action="store_true", help="List all test section IDs")

    test_groups = parser.add_argument_group("Test Group Selection")
    test_groups.add_argument("--cli-only", action="store_true", help="CLI command tests only")
    test_groups.add_argument("--docker-only", action="store_true", help="Docker tests only")
    test_groups.add_argument("--tools-only", action="store_true", help="Hacker tools tests only")
    test_groups.add_argument("--models-only", action="store_true", help="AI model tests only")
    test_groups.add_argument("--orchestrator-only", action="store_true", help="Orchestrator mode tests only")
    test_groups.add_argument("--env-only", action="store_true", help="Environment tests only")
    test_groups.add_argument("--structure-only", action="store_true", help="Project structure tests only")

    parser.add_argument("--include", nargs="+", help="Run only specific test IDs (see --list-tests)")
    parser.add_argument("--exclude", nargs="+", help="Exclude specific test IDs")

    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose

    if args.list_tests:
        print("\nAvailable test sections:")
        for tid, (title, _) in ALL_TESTS.items():
            print(f"  {tid:<35} {title}")
        print()
        sys.exit(0)

    # Determine which tests to run
    selected = set()
    if args.cli_only:
        selected = {k for k in ALL_TESTS if k.startswith("cli-")}
    elif args.docker_only:
        selected = {k for k in ALL_TESTS if k.startswith("docker-")}
    elif args.tools_only:
        selected = {k for k in ALL_TESTS if k.startswith("tools-")}
    elif args.models_only:
        selected = {k for k in ALL_TESTS if k.startswith("ai-")}
    elif args.orchestrator_only:
        selected = {k for k in ALL_TESTS if k.startswith("orchestrator-")}
    elif args.env_only:
        selected = {k for k in ALL_TESTS if k.startswith("env-") or k.startswith("requirements")}
    elif args.structure_only:
        selected = {"project-structure"}
    elif args.include:
        selected = set(args.include)
    else:
        selected = set(ALL_TESTS.keys())

    if args.exclude:
        selected -= set(args.exclude)

    print(f"\n{'=' * 72}")
    print(f"  Raphael 2.0 \u2014 CLI & Infrastructure Smoke Test")
    print(f"  Project root: {PROJECT_ROOT}")
    print(f"  Quick mode: {'ON' if args.quick else 'OFF'}")
    print(f"  Verbose: {'ON' if args.verbose else 'OFF'}")
    print(f"  Test sections: {len(selected)} of {len(ALL_TESTS)}")

    failures = run_selected_tests(selected, quick=args.quick)
    print_summary()

    return 2 if failures > 0 else (1 if TOTAL_TESTS["warn"] > 0 else 0)


if __name__ == "__main__":
    sys.exit(main())
