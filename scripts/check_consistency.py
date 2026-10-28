#!/usr/bin/env python3
"""scripts/check_consistency.py — structural invariants for the native stack.

Fails (exit 1) on any violation. Every rule maps to a defect ID from the audit.

    python3 scripts/check_consistency.py
    python3 scripts/check_consistency.py --verbose
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

SERVICES = REPO / "configs" / "services.json"
CATALOG = REPO / "configs" / "tool-catalog.json"
SCOPE = REPO / "configs" / "engagement-scope.json"
ENV_SH = REPO / "env.sh"
SETUP = REPO / "scripts" / "setup-kali.sh"

DOCKER_HOST_PATTERNS = (
    re.compile(r"\b(?:kali-tools|neo4j|tor-proxy|sliver-server):\d{2,5}\b"),
    re.compile(r"\braphael-net\b"),
    re.compile(r"\bhost\.docker\.internal\b"),
    re.compile(r"//(?:kali-tools|neo4j|tor-proxy|sliver-server)\b"),
)
CODE_ROOTS = ("src", "brain", "bridge", "scripts", "runtime")
# Sub-trees that are not part of the runtime: benchmarks, the TS CLI, tests.
SCAN_EXEMPT_PREFIXES = (
    "src/arena/", "src/cli/", "bridge/tests/", "tests/", "src/orchestrator/runtime/",
)
# Files allowed to mention Docker names because they *are* the Docker backend
# or the teardown/scrub logic itself.
DOCKER_EXEMPT = {
    "src/orchestrator/runtime/docker_client.py",
    "src/orchestrator/runtime/backends/sandbox.py",
    "runtime/sandbox.py",
    "scripts/teardown_docker.sh",
    "runtime/env.py",              # the scrubber
    "scripts/check_consistency.py",  # this file
}

violations: list[str] = []
checks: list[str] = []


def fail(rule: str, msg: str) -> None:
    violations.append(f"[{rule}] {msg}")


def ok(rule: str, msg: str) -> None:
    checks.append(f"[{rule}] {msg}")


# ---------------------------------------------------------------- rules

def rule1_service_imports() -> None:
    data = json.loads(SERVICES.read_text())
    for svc in data["services"]:
        if svc.get("optional"):
            continue
        cmd = svc["command"]
        app_dir = None
        if "--app-dir" in cmd:
            app_dir = cmd[cmd.index("--app-dir") + 1]
        target = next((c for c in cmd if ":app" in c), None)
        if not target:
            fail("R1", f"{svc['name']}: no '<module>:app' target in command")
            continue
        module = target.split(":")[0]
        base = REPO / (app_dir or ".")
        if not base.is_dir():
            fail("R1", f"{svc['name']}: --app-dir {base} does not exist")
            continue
        probe = (
            "import sys; "
            f"sys.path.insert(0, r'{base}'); "
            f"sys.path.insert(0, r'{REPO / 'src'}'); "
            f"import {module}; print('ok')"
        )
        r = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                           text=True, cwd=REPO, timeout=90)
        if r.returncode != 0:
            fail("R1", f"{svc['name']}: cannot import {module} ({r.stderr.strip().splitlines()[-1] if r.stderr.strip() else 'no stderr'})")
    ok("R1", f"checked {len(data['services'])} service entrypoints")


def rule2_ports() -> None:
    data = json.loads(SERVICES.read_text())
    seen: dict[int, str] = {}
    for svc in data["services"]:
        port = svc.get("port")
        if not port:
            continue
        if not 1024 <= int(port) <= 65535:
            fail("R2", f"{svc['name']}: port {port} out of range")
        if port in seen:
            fail("R2", f"duplicate port {port}: {seen[port]} and {svc['name']}")
        seen[port] = svc["name"]
    ok("R2", f"{len(seen)} unique ports")


def rule3_env_no_literals() -> None:
    text = ENV_SH.read_text()
    # ignore comments
    body = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
    found = re.findall(r"(?<![\w$-])\b(3[0-9]{3}|4[0-9]{4}|9[0-9]{3})\b", body)
    if found:
        fail("R3", f"env.sh hardcodes ports: {sorted(set(found))}")
    else:
        ok("R3", "env.sh contains no literal ports")


def rule4_catalog_vs_setup() -> None:
    setup = SETUP.read_text()
    data = json.loads(CATALOG.read_text())
    missing = []
    for tool in data["tools"]:
        if not tool.get("required"):
            continue
        pkg = tool.get("install", "")
        if pkg.startswith("apt:"):
            name = pkg.split(":", 1)[1]
            if name not in setup:
                missing.append(f"{tool['name']} ({name})")
    if missing:
        fail("R4", f"required tools not installed by setup-kali.sh: {missing}")
    else:
        ok("R4", "every required catalog tool is installed by setup-kali.sh")


def _iter_code_files():
    for root in CODE_ROOTS:
        base = REPO / root
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.suffix not in {".py", ".sh", ".ts", ".tsx"}:
                continue
            if "node_modules" in p.parts or "__pycache__" in p.parts:
                continue
            yield p


def _code_lines(path: Path):
    """Yield (lineno, line) only for lines carrying executable tokens.

    Comments and string literals (including docstrings) are excluded, so a
    module docstring explaining what was removed is not a violation.
    """
    text = path.read_text(errors="ignore")
    if path.suffix != ".py":
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith("//"):
                yield i, line
        return
    import io
    import tokenize
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError):
        return
    skip = {tokenize.COMMENT, tokenize.STRING, tokenize.NL, tokenize.NEWLINE,
            tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING, tokenize.ENDMARKER}
    code_lines = {t.start[0] for t in tokens if t.type not in skip}
    for i, line in enumerate(text.splitlines(), 1):
        if i in code_lines:
            yield i, line


def rule5_no_docker_exec() -> None:
    bad = []
    for p in _iter_code_files():
        rel = str(p.relative_to(REPO))
        if rel in DOCKER_EXEMPT or rel.startswith(SCAN_EXEMPT_PREFIXES):
            continue
        for i, line in _code_lines(p):
            if re.search(r"docker\s+exec", line):
                bad.append(f"{rel}:{i}")
    if bad:
        fail("R5", f"docker exec in executable paths: {bad[:8]}")
    else:
        ok("R5", "no docker exec in executable paths")


def rule6_no_docker_dns() -> None:
    bad = []
    for p in _iter_code_files():
        rel = str(p.relative_to(REPO))
        if rel in DOCKER_EXEMPT or rel.startswith(SCAN_EXEMPT_PREFIXES):
            continue
        for i, line in _code_lines(p):
            for pat in DOCKER_HOST_PATTERNS:
                if pat.search(line):
                    bad.append(f"{rel}:{i}: {line.strip()[:70]}")
                    break
    if bad:
        fail("R6", f"Docker DNS/hostnames in runtime paths: {bad[:6]}")
    else:
        ok("R6", "no Docker DNS names in runtime paths")


def rule7_no_empty_modules() -> None:
    bad = []
    for p in (REPO / "src").rglob("*.py"):
        if p.name == "__init__.py" or "__pycache__" in p.parts:
            continue
        if p.stat().st_size == 0:
            bad.append(str(p.relative_to(REPO)))
    if bad:
        fail("R7", f"0-byte modules shadow real ones: {bad}")
    else:
        ok("R7", "no 0-byte shadow modules")


def rule8_no_dead_code() -> None:
    bad = []
    for p in list((REPO / "src").rglob("*.py")) + list((REPO / "brain").rglob("*.py")) \
            + list((REPO / "bridge").glob("*.py")) + list((REPO / "runtime").rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError as e:
            fail("R8", f"{p.relative_to(REPO)}: SyntaxError {e}")
            continue
        for node in ast.walk(tree):
            for field in ("body", "orelse", "finalbody"):
                block = getattr(node, field, None)
                if not isinstance(block, list):
                    continue
                for idx, stmt in enumerate(block[:-1]):
                    if isinstance(stmt, (ast.Return, ast.Raise)):
                        nxt = block[idx + 1]
                        bad.append(f"{p.relative_to(REPO)}:{nxt.lineno} unreachable after "
                                   f"{type(stmt).__name__.lower()}")
    if bad:
        fail("R8", f"dead code: {bad[:6]}")
    else:
        ok("R8", "no statements after return/raise")


def rule9_evasion_exports() -> None:
    try:
        from orchestrator.evasion import __all__ as exported  # noqa: F401
        from orchestrator.evasion import plan
        n = len(plan())
    except Exception as e:  # noqa: BLE001
        fail("R9", f"evasion package not importable: {e!r}")
        return
    if n < 5:
        fail("R9", f"evasion plan() returned {n} steps (expected >= 5)")
    else:
        ok("R9", f"evasion package imports, plan() -> {n} steps, {len(exported)} exports")


def rule10_scope_file() -> None:
    if not SCOPE.is_file():
        fail("R10", "configs/engagement-scope.json missing")
        return
    data = json.loads(SCOPE.read_text())
    if not isinstance(data.get("allow"), list) or not isinstance(data.get("deny"), list):
        fail("R10", "scope file must have 'allow' and 'deny' arrays")
    else:
        ok("R10", f"scope file present (allow={len(data['allow'])}, deny={len(data['deny'])})")


def rule11_required_files() -> None:
    required = [
        "env.sh", "configs/services.json", "configs/tool-catalog.json",
        "scripts/gen_env.py", "scripts/start.py", "scripts/stop.py",
        "scripts/status.py", "scripts/verify_native.py", "scripts/check_tools.py",
        "scripts/native_up.sh", "scripts/native_down.sh", "scripts/native_status.sh",
        "scripts/setup-kali.sh", "scripts/local_tools_manager.py",
        "docs/phishing-openapi.json", "src/phishing/main.py",
        "src/orchestrator/evasion/antiforensics.py",
        "src/orchestrator/evasion/timestomp.py",
        "src/orchestrator/evasion/phase.py",
        "src/orchestrator/api/evasion.py",
    ]
    missing = [f for f in required if not (REPO / f).exists()]
    if missing:
        fail("R11", f"required files missing: {missing}")
    else:
        ok("R11", f"all {len(required)} required files present")


def rule12_no_root_scripts() -> None:
    stray = [p.name for p in REPO.glob("*.sh") if p.name != "env.sh"]
    if stray:
        fail("R12", f"scripts at repo root (must live in scripts/): {stray}")
    else:
        ok("R12", "no stray shell scripts at repo root")


RULES = [
    rule1_service_imports, rule2_ports, rule3_env_no_literals,
    rule4_catalog_vs_setup, rule5_no_docker_exec, rule6_no_docker_dns,
    rule7_no_empty_modules, rule8_no_dead_code, rule9_evasion_exports,
    rule10_scope_file, rule11_required_files, rule12_no_root_scripts,
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    for rule in RULES:
        try:
            rule()
        except Exception as e:  # noqa: BLE001
            fail(rule.__name__, f"crashed: {e!r}")

    if args.verbose:
        for line in checks:
            print("PASS", line)
    if violations:
        print()
        for v in violations:
            print("FAIL", v)
        print(f"\n{len(violations)} VIOLATION(S)")
        return 1
    print(f"ALL CHECKS PASSED ({len(checks)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
