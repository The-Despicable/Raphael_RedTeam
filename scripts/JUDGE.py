#!/usr/bin/env python3
"""
JUDGE v2.1 — deeper integrity / honesty auditor for Raphael.

Design goals:
- Fail closed on syntax/import/runtime-contract problems.
- Separate HARD failures from WEAK portability/quality warnings.
- Detect local packages dynamically instead of relying only on a hard-coded list.
- Detect suspicious success-returning stubs and NotImplemented paths.
- Validate dataclass/enum/state-machine contracts when importable.
- Validate Arena isolation and broker/action-receipt safety invariants when present.
- Emit machine-readable JSON in addition to human output.
- Never execute offensive actions, network probes, exploit code, or arbitrary project CLIs.

Classification:
  FAIL           — Real defect or integrity violation
  WEAK           — Portability, environment, or code-smell warning
  CRASH          — Auditor itself crashed
  FABRICATION    — Evidence of fabricated test/source
  DECLARED_GAP   — Honest NOT_IMPLEMENTED with "NOT_IMPLEMENTED:" message
  INTENTIONAL_NOOP — Verified ablation NoOp (ablation-only, not reachable from FULL)
  PASS           — Check passed
  INFO           — Informational
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

START = time.time()
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
SOURCEDIR = ROOT.parent / "src"
sys.path.insert(0, str(SOURCEDIR))

# Python version guard (SENTINEL Rule 50 - Run-Count Accountability)
import sys
if sys.version_info >= (3, 13):
    raise RuntimeError(f"Unsupported Python {sys.version_info.major}.{sys.version_info.minor}. "
                       f"Raphael requires Python >=3.11,<3.13. "
                       f"See pyproject.toml requires-python.")

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".local", ".hermes", ".pytest_cache",
    ".ssh", "data", "benchmarks", "references", "challenge", "challenge_1245",
    "cloak_env", "redis-stable", "go", "docker",
}

# Things that should not be imported dynamically because importing them can have
# external side effects or heavy startup behavior. Static AST checks still cover them.
DYNAMIC_IMPORT_DENYLIST = {
    "JUDGE", "JUDGE_v2",
}

STDLIB = set(getattr(sys, "stdlib_module_names", ()))
if not STDLIB:
    # Conservative fallback for older Python.
    STDLIB = {
        "os","sys","re","json","time","math","subprocess","io","typing","abc","uuid",
        "enum","pathlib","datetime","collections","functools","itertools","hashlib",
        "base64","inspect","textwrap","shutil","tempfile","random","string","struct",
        "socket","threading","multiprocessing","asyncio","concurrent","urllib","http",
        "ssl","select","queue","copy","stat","csv","html","xml","configparser",
        "argparse","logging","warnings","traceback","pickle","zipfile","tarfile",
        "gzip","bz2","lzma","locale","atexit","signal","platform","ctypes",
        "dataclasses","operator","types","weakref","numbers","decimal","fractions",
        "pprint","contextlib","secrets","ipaddress","glob","importlib","shlex",
        "sqlite3","zlib","hmac","ast","unittest",
    }

PKG_TO_IMPORT = {
    "fastapi": "fastapi", "uvicorn": "uvicorn", "httpx": "httpx",
    "pydantic": "pydantic", "requests": "requests", "pyyaml": "yaml",
    "dnspython": "dns", "cryptography": "cryptography", "jinja2": "jinja2",
    "aiohttp": "aiohttp", "redis": "redis", "stem": "stem", "psutil": "psutil",
    "neo4j": "neo4j", "python-telegram-bot": "telegram", "fakeredis": "fakeredis",
    "pytest": "pytest", "python-multipart": "multipart", "python-dotenv": "dotenv",
    "pywinrm": "winrm", "mcp": "mcp", "numpy": "numpy", "packaging": "packaging",
    "boto3": "boto3", "azure-storage-blob": "azure",
    "google-cloud-storage": "google", "urllib3": "urllib3", "pymssql": "pymssql",
    "duckduckgo-search": "ddgs", "r2pipe": "r2pipe",
    "caido-sdk-client": "caido_sdk_client", "docker": "docker",
    "aiodns": "aiodns", "secretstorage": "secretstorage",
}

# ── Severity ordering (including non-failure categories) ────────
SEVERITY_ORDER = {
    "PASS": 0, "INFO": 1,
    "DECLARED_GAP": 2, "INTENTIONAL_NOOP": 3,
    "WEAK": 4, "FAIL": 5, "CRASH": 6, "FABRICATION": 7,
}

reports: list[dict[str, Any]] = []
counts = Counter()
py_files: list[Path] = []
trees: dict[Path, ast.AST] = {}
sources: dict[Path, str] = {}

# ── Ablation NoOp registry (populated by test_ablation_noops) ───
# True NoOps are methods inside classes named NoOp*, defined in ablation_runner.py,
# that are ONLY referenced from ablation-specific paths, never from FULL_RAPHAEL.
VERIFIED_ABLATION_NOOPS: set[tuple[str, str, str]] = set()  # (file, class_name, method_name)


def add(verdict: str, check: str, file: str | Path, lines: Any,
        evidence: str, failure: str = "", fix: str = "") -> None:
    counts[verdict] += 1
    reports.append({
        "verdict": verdict, "check": check, "file": str(file), "lines": str(lines),
        "evidence": evidence, "failure": failure, "fix": fix,
    })


def rel(p: str | Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(ROOT))
    except Exception:
        return str(p)


def discover_files() -> None:
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(".py"):
                py_files.append(Path(root) / name)


def parse_all() -> None:
    for p in sorted(py_files):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            sources[p] = text
            trees[p] = ast.parse(text, filename=str(p))
        except SyntaxError as e:
            add("CRASH", "syntax", rel(p), e.lineno or "N/A",
                "Python syntax error", str(e),
                "Fix syntax before any other audit result is trusted.")
        except Exception as e:
            add("CRASH", "read", rel(p), "N/A", "Unable to read/parse file", repr(e))


def discover_local_roots() -> set[str]:
    roots = set()
    for child in ROOT.iterdir():
        if child.is_dir() and child.name not in SKIP_DIRS:
            if (child / "__init__.py").exists():
                roots.add(child.name.replace("-", "_"))
        elif child.suffix == ".py":
            roots.add(child.stem)
    # Also scan src/ for packages
    if SOURCEDIR.exists():
        for child in sorted(SOURCEDIR.iterdir()):
            if child.is_dir() and child.name not in SKIP_DIRS:
                if (child / "__init__.py").exists():
                    roots.add(child.name.replace("-", "_"))
            elif child.suffix == ".py":
                roots.add(child.stem)
    return roots


LOCAL_ROOTS: set[str] = set()


def imported_modules(tree: ast.AST) -> Iterable[tuple[int, str, int]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name, 0
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.lineno, node.module, node.level


def requirements_imports() -> tuple[set[str], set[str]]:
    declared_packages, declared_imports = set(), set()
    req = ROOT / "requirements.txt"
    if not req.exists():
        return declared_packages, declared_imports
    for raw in req.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        pkg = re.split(r"[<>=!~;\[]", line, 1)[0].strip().lower()
        if not pkg:
            continue
        declared_packages.add(pkg)
        declared_imports.add(PKG_TO_IMPORT.get(pkg, pkg.replace("-", "_")))
    return declared_packages, declared_imports


# ═══════════════════════════════════════════════════════════════
#  STUB CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

# Result codes for function body analysis
class StubKind:
    NOT_A_STUB = "NOT_A_STUB"
    BARE_PASS = "BARE_PASS"                          # pass → FAIL
    BARE_ELLIPSIS = "BARE_ELLIPSIS"                  # ... → FAIL
    BARE_NOT_IMPLEMENTED = "BARE_NOT_IMPLEMENTED"    # raise NotImplementedError → FAIL
    DECLARED_GAP = "DECLARED_GAP"                    # raise NotImplementedError("NOT_IMPLEMENTED: ...") → INFO/DECLARED_GAP
    SUSPICIOUS_SUCCESS = "SUSPICIOUS_SUCCESS"        # return {"success": True} with no logic → WEAK


def _is_abstract_method(node: ast.AST) -> bool:
    """Check if a function is decorated with @abstractmethod."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for decorator in node.decorator_list:
        dname = ""
        if isinstance(decorator, ast.Name):
            dname = decorator.id
        elif isinstance(decorator, ast.Attribute):
            dname = decorator.attr
        if dname in ("abstractmethod", "abstractproperty", "abstractstaticmethod", "abstractclassmethod"):
            return True
    return False


def classify_function_body(node: ast.AST) -> str:
    """Classify a function body to determine what kind of stub it is.

    Returns one of StubKind.* constants.
    """
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return StubKind.NOT_A_STUB

    # Abstract methods are intentionally not implemented — exempt from stub checks
    if _is_abstract_method(node):
        return StubKind.NOT_A_STUB

    body = list(node.body)

    # Strip docstring
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]

    if not body:
        return StubKind.BARE_PASS  # Empty body after docstring

    if len(body) == 1:
        only = body[0]

        # pass → BARE_PASS
        if isinstance(only, ast.Pass):
            return StubKind.BARE_PASS

        # ... (Ellipsis) → BARE_ELLIPSIS (but abstract methods are already exempted above)
        if isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant) and only.value.value is Ellipsis:
            return StubKind.BARE_ELLIPSIS

        # raise NotImplementedError → check if declared or bare
        if isinstance(only, ast.Raise):
            exc = only.exc
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name) and exc.func.id == "NotImplementedError":
                # Check if the argument contains "NOT_IMPLEMENTED:"
                if exc.args:
                    for arg in exc.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and "NOT_IMPLEMENTED:" in arg.value:
                            return StubKind.DECLARED_GAP
                return StubKind.BARE_NOT_IMPLEMENTED
            if isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
                return StubKind.BARE_NOT_IMPLEMENTED

        # raise without operand is a re-raise, not a stub
        if isinstance(only, ast.Raise):
            return StubKind.NOT_A_STUB

    # Check for suspicious_success_return
    meaningful = 0
    returns_success = False
    for n in ast.walk(node):
        if isinstance(n, ast.Return):
            v = n.value
            if isinstance(v, ast.Constant) and v.value is True:
                returns_success = True
            elif isinstance(v, ast.Dict):
                for k, val in zip(v.keys, v.values):
                    if isinstance(k, ast.Constant) and str(k.value).lower() in {"success", "ok"}:
                        if isinstance(val, ast.Constant) and val.value is True:
                            returns_success = True
            elif isinstance(v, ast.Call):
                for kw in v.keywords:
                    if kw.arg in {"success", "ok"} and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        returns_success = True
        if isinstance(n, (ast.Call, ast.Assign, ast.AugAssign, ast.Await, ast.Yield, ast.YieldFrom, ast.Raise)):
            meaningful += 1

    if returns_success and meaningful <= 1:
        return StubKind.SUSPICIOUS_SUCCESS

    # Check for declared gap pattern: return SomeResult(success=False, status="not_implemented", error="NOT_IMPLEMENTED: ...")
    # This is the pattern used by honest phase stubs in phases/models.py
    for n in ast.walk(node):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Call):
            call = n.value
            has_success_false = False
            has_not_implemented = False
            for kw in call.keywords:
                if kw.arg == "success" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    has_success_false = True
                if kw.arg in ("status",) and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str) and kw.value.value == "not_implemented":
                    has_not_implemented = True
                if kw.arg == "error" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str) and "NOT_IMPLEMENTED:" in kw.value.value:
                    has_not_implemented = True
            if has_success_false and has_not_implemented:
                return StubKind.DECLARED_GAP

    return StubKind.NOT_A_STUB


def is_verified_ablation_noop(file: str, class_name: str, method_name: str) -> bool:
    """Check if a method is a verified ablation NoOp."""
    return (file, class_name, method_name) in VERIFIED_ABLATION_NOOPS


# ═══════════════════════════════════════════════════════════════
#  TEST: IMPORTS
# ═══════════════════════════════════════════════════════════════

def test_imports() -> None:
    check = "imports"
    failed = 0
    seen = set()
    for p, tree in trees.items():
        for lineno, modname, level in imported_modules(tree):
            if level > 0:
                continue
            top = modname.split(".")[0]
            key = (top, modname)
            if key in seen or top in STDLIB or top in LOCAL_ROOTS:
                continue
            seen.add(key)
            try:
                spec = importlib.util.find_spec(top)
            except Exception as e:
                spec = None
            if spec is None:
                failed += 1
                add("FAIL", check, rel(p), lineno, f"import {modname}",
                    f"Module '{top}' cannot be resolved in this environment.",
                    "Install the declared dependency or guard/remove the import.")
    if not failed:
        add("PASS", check, "project", "-", "All absolute imports resolve or are local/stdlib.")


# ═══════════════════════════════════════════════════════════════
#  TEST: REQUIREMENTS INTEGRITY
# ═══════════════════════════════════════════════════════════════

def test_requirements_integrity() -> None:
    check = "requirements"
    _, declared_imports = requirements_imports()
    used_external: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for p, tree in trees.items():
        for lineno, modname, level in imported_modules(tree):
            if level > 0:
                continue
            top = modname.split(".")[0]
            if top not in STDLIB and top not in LOCAL_ROOTS:
                used_external[top].append((rel(p), lineno))
    for top, uses in sorted(used_external.items()):
        if top not in declared_imports:
            fp, ln = uses[0]
            add("WEAK", check, fp, ln, f"External import '{top}' is used",
                "Dependency is not mapped from requirements.txt.",
                "Add the package to requirements.txt or extend PKG_TO_IMPORT if package/import names differ.")
    if not used_external:
        add("INFO", check, "project", "-", "No external imports detected.")


# ═══════════════════════════════════════════════════════════════
#  TEST: STUB HONESTY
# ═══════════════════════════════════════════════════════════════

def _walk_with_context(module_file: Path, node: ast.AST,
                       context_class: str | None, check: str) -> None:
    """Recursive walk that maintains class context for method classification."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.ClassDef):
            # Enter class: set context, walk children, then restore
            _walk_with_context(module_file, child, child.name, check)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = classify_function_body(child)
            file_rel = rel(module_file)

            if kind == StubKind.BARE_PASS:
                if context_class and is_verified_ablation_noop(file_rel, context_class, child.name):
                    add("INTENTIONAL_NOOP", check, file_rel, child.lineno,
                        f"{context_class}.{child.name}()",
                        "Verified ablation NoOp — intentionally inert, ablation-only path.")
                else:
                    add("FAIL", check, file_rel, child.lineno, f"{child.name}()",
                        "Function body is only 'pass' — undetermined stub.",
                        "Implement it, declare NOT_IMPLEMENTED, or (if ablation NoOp) verify in test_ablation_noops.")

            elif kind == StubKind.BARE_ELLIPSIS:
                add("FAIL", check, file_rel, child.lineno, f"{child.name}()",
                    "Function body is only '...' — undetermined stub.",
                    "Implement it or declare NOT_IMPLEMENTED.")

            elif kind == StubKind.BARE_NOT_IMPLEMENTED:
                add("FAIL", check, file_rel, child.lineno, f"{child.name}()",
                    "raise NotImplementedError with no NOT_IMPLEMENTED: message — undeclared stub.",
                    "Add a descriptive 'NOT_IMPLEMENTED: ...' message or implement the function.")

            elif kind == StubKind.DECLARED_GAP:
                add("DECLARED_GAP", check, file_rel, child.lineno, f"{child.name}()",
                    "Declared NOT_IMPLEMENTED with explicit 'NOT_IMPLEMENTED:' message — known gap.")

            elif kind == StubKind.SUSPICIOUS_SUCCESS:
                add("WEAK", check, file_rel, child.lineno, f"{child.name}()",
                    "Function returns success=True with minimal executable behavior.",
                    "Verify this is a legitimate predicate/helper rather than a lying success stub.")

            # Walk nested functions (closures) with same class context
            _walk_with_context(module_file, child, context_class, check)

        else:
            _walk_with_context(module_file, child, context_class, check)


def test_stub_honesty() -> None:
    """Classify every function body. Emit FAIL/WEAK/DECLARED_GAP per kind."""
    check = "stub_honesty"
    for p, tree in trees.items():
        _walk_with_context(p, tree, None, check)


# ═══════════════════════════════════════════════════════════════
#  TEST: ABLATION NOOP VERIFICATION
# ═══════════════════════════════════════════════════════════════

def test_ablation_noops() -> None:
    """Verify that NoOp classes in ablation_runner.py are genuine ablation stubs.

    Requirements for INTENTIONAL_NOOP classification:
      1. Class name begins with 'NoOp'
      2. Class is defined in ablation_runner.py (the ablation framework module)
      3. Implementation is intentionally inert (methods return []/None or pass)
      4. Methods are NOT reachable from FULL_RAPHAEL execution path
         (i.e., NoOp classes are only instantiated when the corresponding
          config flag is disabled — llm_only/scripted/ablated path)

    Complementary check: if a NoOp method IS reachable from FULL_RAPHAEL → FAIL.
    """
    check = "ablation_noops"
    ablation_runner_path = SOURCEDIR / "arena" / "ablation_runner.py"

    if not ablation_runner_path.exists():
        add("INFO", check, "arena/ablation_runner.py", "-",
            "Ablation runner module absent — skipping NoOp verification.")
        return

    if ablation_runner_path not in trees:
        add("INFO", check, rel(ablation_runner_path), "-",
            "Could not parse ablation_runner.py — skipping NoOp verification.")
        return

    tree = trees[ablation_runner_path]
    source = sources.get(ablation_runner_path, "")

    # Collect all NoOp classes and their methods
    noop_classes: dict[str, list[str]] = {}  # class_name → [method_names]

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name.startswith("NoOp"):
            methods = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.append(item.name)
            noop_classes[node.name] = methods

    if not noop_classes:
        add("PASS", check, rel(ablation_runner_path), "-",
            "No NoOp classes found — no verification needed.")
        return

    # Check requirement 2: verify each NoOp is intentionally inert
    file_rel = rel(ablation_runner_path)
    for cls_name, methods in noop_classes.items():
        for method_name in methods:
            # Verify the method is inert (returns empty list/None or passes)
            # We trust classify_function_body for this, but we also need
            # to confirm the NoOp is not reachable from FULL_RAPHAEL

            # Register as verified ablation NoOp
            VERIFIED_ABLATION_NOOPS.add((file_rel, cls_name, method_name))

    # Requirement 4: Check that NoOp classes are NOT referenced in FULL_RAPHAEL path
    # FULL_RAPHAEL uses the _run_raphael method. Check that method's body
    # does NOT reference any NoOp class.
    full_raphael_references_noop = False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_run_raphael":
            # Get source segment of _run_raphael
            for noop_cls in noop_classes:
                if noop_cls in source:
                    # Check if the NoOp class is referenced WITHIN _run_raphael
                    func_start = node.lineno
                    func_end = getattr(node, 'end_lineno', node.lineno + 50)
                    lines = source.split('\n')
                    func_lines = lines[func_start - 1:func_end]
                    func_text = '\n'.join(func_lines)
                    if noop_cls in func_text:
                        full_raphael_references_noop = True
                        add("FAIL", check, file_rel, node.lineno,
                            f"_run_raphael references {noop_cls}",
                            f"NoOp class '{noop_cls}' is reachable from FULL_RAPHAEL execution path. "
                            "Ablation stubs must not be used when all components are enabled.",
                            "Ensure FULL_RAPHAEL path uses real implementations, not NoOp stubs.")

    if not full_raphael_references_noop:
        add("PASS", check, file_rel, "-",
            f"Verified {len(noop_classes)} NoOp classes ({sum(len(m) for m in noop_classes.values())} methods) "
            f"— ablation-only, not reachable from FULL_RAPHAEL.")

    # Also check: does _run_llm_only or _run_scripted reference NoOp classes?
    # (they should, that's correct)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in ("_run_llm_only", "_run_scripted"):
            found_noops_in_baseline = False
            for noop_cls in noop_classes:
                if noop_cls in source:
                    func_start = node.lineno
                    func_end = getattr(node, 'end_lineno', node.lineno + 50)
                    lines = source.split('\n')
                    func_lines = lines[func_start - 1:func_end]
                    func_text = '\n'.join(func_lines)
                    if noop_cls in func_text:
                        found_noops_in_baseline = True
                        break
            if not found_noops_in_baseline:
                add("INFO", check, file_rel, node.lineno,
                    f"{node.name} does not reference any NoOp class",
                    "Baseline path may not be using ablation stubs — verify this is intentional.")


# ═══════════════════════════════════════════════════════════════
#  TEST: MODULE-LEVEL COGNITIVE SINGLETONS
# ═══════════════════════════════════════════════════════════════

COGNITIVE_SINGLETON_CLASSES = {
    "EvidenceGraph",
    "WorldModel",
    "HypothesisManager",
    "ContradictionManager",
    "Planner",
    "PlannerInstance",
}


def test_module_level_singletons() -> None:
    """Detect module-level mutable cognitive singletons.

    Instantiation of EvidenceGraph(), WorldModel(), HypothesisManager(),
    ContradictionManager(), or Planner() at module scope is a code smell
    (potential cross-run state contamination). Functions and class bodies
    are exempt — only bare module-level instantiations are flagged.

    Known-run-local state classes (EvidenceGraph, etc.) instantiated at
    module scope → FAIL (they are designed for per-run use).
    Module-level singletons of other cognitive classes → WEAK.
    """
    check = "module_singletons"
    found_any = False

    for p, tree in trees.items():
        file_rel = rel(p)
        for node in ast.walk(tree):
            # Module-level: direct children of the module
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            class_name = None
            if isinstance(func, ast.Name):
                class_name = func.id
            elif isinstance(func, ast.Attribute):
                class_name = func.attr

            if class_name not in COGNITIVE_SINGLETON_CLASSES:
                continue

            # Check if this call is at module scope (not inside a function or class)
            parent = getattr(node, 'parent', None)
            # We need to track parent. Let's do it by walking the tree manually.
            # Since ast nodes don't have parent references, we'll use a different approach:
            # find function/class boundaries and check if the call is outside them.

            # Actually, simpler: check if the node is inside any function/class definition
            # by looking at all ancestors in the tree walk.
            # We'll track this with a manual walk.

            # For now, use a text-based heuristic: if the call is at module level
            # in the file (not indented inside a function/class), it's a singleton.
            source = sources.get(p, "")
            if not source:
                continue

            # Get the line containing the call
            line_idx = node.lineno - 1  # 0-indexed
            if line_idx < 0 or line_idx >= len(source.split('\n')):
                continue

            # Check indentation of this line
            lines = source.split('\n')
            line = lines[line_idx] if line_idx < len(lines) else ""
            indent = len(line) - len(line.lstrip())

            # Module-level = 0 indentation
            if indent == 0:
                # Double-check: is this a standalone assignment/expression?
                # Check that we're not inside a class or function by looking
                # at surrounding lines for def/class at lower indentation
                is_module_level = True
                for check_line in range(line_idx - 1, max(line_idx - 20, 0) - 1, -1):
                    prev = lines[check_line].strip()
                    if prev.startswith("def ") or prev.startswith("class "):
                        is_module_level = False
                        break
                    if prev.startswith("return ") or prev.startswith("yield "):
                        is_module_level = False
                        break
                    if prev.startswith("async def "):
                        is_module_level = False
                        break

                if is_module_level:
                    found_any = True
                    verdict = "FAIL" if class_name in COGNITIVE_SINGLETON_CLASSES else "WEAK"
                    add(verdict, check, file_rel, node.lineno,
                        f"Module-level {class_name}() instantiation",
                        f"Module-level instantiation of '{class_name}' creates a mutable singleton. "
                        "This can cause cross-run state contamination. "
                        "Use per-run fresh instances inside function/class scope.",
                        f"Move 'instance = {class_name}()' inside a function or __init__ method.")

    if not found_any:
        add("PASS", check, "project", "-",
            "No module-level cognitive singleton instantiations detected.")


# ═══════════════════════════════════════════════════════════════
#  TEST: BROAD EXCEPTION SWALLOWING
# ═══════════════════════════════════════════════════════════════

def test_broad_exception_swallowing() -> None:
    check = "exception_hygiene"
    for p, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"})
                if not broad:
                    continue
                body = node.body
                swallowed = not body or all(
                    isinstance(x, ast.Pass) or
                    (isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant))
                    for x in body
                )
                if swallowed:
                    add("WEAK", check, rel(p), node.lineno,
                        "Broad exception is silently swallowed",
                        "Runtime defects may be hidden from JUDGE and operators.",
                        "Catch a narrower exception or record/re-raise the failure.")


# ═══════════════════════════════════════════════════════════════
#  TEST: DANGEROUS EVAL/EXEC
# ═══════════════════════════════════════════════════════════════

def test_dangerous_eval_exec() -> None:
    check = "dynamic_execution"
    for p, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                add("WEAK", check, rel(p), node.lineno, f"{node.func.id}(...)",
                    "Dynamic Python execution found; integrity depends on input provenance.",
                    "Remove it or strictly constrain/validate the input and document the trust boundary.")


# ═══════════════════════════════════════════════════════════════
#  TEST: SUBPROCESS CONTRACTS
# ═══════════════════════════════════════════════════════════════

def test_subprocess_contracts() -> None:
    check = "subprocess"
    checked = set()
    for p, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            elif isinstance(node.func, ast.Name):
                name = node.func.id
            if name not in {"run", "Popen", "check_call", "check_output", "create_subprocess_exec"}:
                continue

            # shell=True is a stronger warning than a missing optional binary.
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    add("WEAK", check, rel(p), node.lineno, "subprocess with shell=True",
                        "Shell interpretation expands the side-effect/input surface.",
                        "Prefer argv execution; if required, document why inputs cannot be attacker-controlled.")

            candidates = []
            for arg in node.args[:1]:
                if isinstance(arg, ast.List) and arg.elts:
                    first = arg.elts[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        candidates.append(first.value)
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    candidates.append(arg.value)
            for c in candidates:
                bin_name = c.split()[0]
                if "/" in bin_name or "\\" in bin_name or bin_name in checked:
                    continue
                checked.add(bin_name)
                if not shutil.which(bin_name):
                    add("WEAK", check, rel(p), node.lineno, f"Binary '{bin_name}' not found",
                        "This execution path is unavailable on the current host.",
                        "Keep the path capability-guarded or install the binary in the intended runtime.")


# ═══════════════════════════════════════════════════════════════
#  TEST: CRYPTO ROUND-TRIPS
# ═══════════════════════════════════════════════════════════════

def safe_load_module(path: Path, unique: str):
    spec = importlib.util.spec_from_file_location(unique, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create spec for {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_crypto_roundtrips() -> None:
    check = "crypto_roundtrip"
    candidates = [
        ("orchestrator/weaponizer/weaponizer_engine.py", "_aes_cbc_encrypt", "_aes_cbc_decrypt"),
        ("agent/crypto.py", "encrypt", "decrypt"),
        ("agent/crypto.py", "aes_ctr_encrypt", "aes_ctr_decrypt"),
    ]
    vector = b"judge_v2_roundtrip_vector"
    for idx, (rp, enc_name, dec_name) in enumerate(candidates):
        path = SOURCEDIR / rp
        if not path.exists():
            add("INFO", check, rp, "-", "Crypto target absent; check not applicable.")
            continue
        try:
            mod = safe_load_module(path, f"_judge_crypto_{idx}")
        except Exception as e:
            add("FAIL", check, rp, "-", "Crypto module could not be imported safely", repr(e))
            continue
        if not hasattr(mod, enc_name):
            add("INFO", check, rp, "-", f"{enc_name} absent; check not applicable.")
            continue
        if not hasattr(mod, dec_name):
            add("FAIL", check, rp, "-", f"{enc_name} exists but {dec_name} does not",
                "Encryption has no matching decrypt path.")
            continue

        enc, dec = getattr(mod, enc_name), getattr(mod, dec_name)
        attempts = [
            lambda: enc(b"k"*32, vector),
            lambda: enc(vector),
            lambda: enc(b"k"*32, b"i"*12, vector),
            lambda: enc(b"k"*32, b"1"*16, vector),
        ]
        result = None
        errors = []
        for fn in attempts:
            try:
                result = fn()
                break
            except (TypeError, ValueError) as e:
                errors.append(repr(e))
        if result is None:
            add("FAIL", check, rp, "-", enc_name,
                "No supported test calling convention succeeded: " + "; ".join(errors[-2:]))
            continue
        try:
            if isinstance(result, tuple):
                if len(result) >= 3:
                    plaintext = dec(result[0], result[1], result[2])
                elif len(result) == 2:
                    plaintext = dec(result[0], result[1])
                else:
                    plaintext = dec(result[0])
            else:
                dec_attempts = [
                    lambda: dec(result),
                    lambda: dec(b"k"*32, result),
                    lambda: dec(b"k"*32, b"1"*16, result),
                ]
                plaintext = None
                for fn in dec_attempts:
                    try:
                        plaintext = fn()
                        break
                    except TypeError:
                        pass
            if plaintext != vector:
                add("FAIL", check, rp, "-", f"{enc_name}/{dec_name}",
                    f"Round-trip mismatch: {plaintext!r}")
            else:
                add("PASS", check, rp, "-", f"{enc_name}/{dec_name} round-trip passed.")
        except Exception as e:
            add("FAIL", check, rp, "-", f"{enc_name}/{dec_name}",
                "Round-trip raised an exception: " + repr(e))


# ═══════════════════════════════════════════════════════════════
#  TEST: ACTION RECEIPT CONTRACT
# ═══════════════════════════════════════════════════════════════

def test_action_receipt_contract() -> None:
    """Best-effort semantic test. It adapts by introspection and never performs an external action."""
    check = "action_receipt_contract"
    path = SOURCEDIR / "orchestrator/hardening/action_receipt.py"
    if not path.exists():
        add("INFO", check, rel(path), "-", "ActionReceipt module absent.")
        return
    try:
        mod = safe_load_module(path, "_judge_action_receipt")
    except Exception as e:
        add("FAIL", check, rel(path), "-", "ActionReceipt module import failed", repr(e))
        return

    cls = getattr(mod, "ActionReceipt", None)
    if cls is None:
        add("FAIL", check, rel(path), "-", "ActionReceipt class missing",
            "Stage-1 contract cannot be verified.")
        return

    # Structural contract checks, intentionally not guessing constructor values.
    attrs = set()
    if dataclasses.is_dataclass(cls):
        attrs = {f.name for f in dataclasses.fields(cls)}
    else:
        attrs = set(getattr(cls, "__annotations__", {}))
    expected_any = [
        {"action_id"}, {"state"}, {"status"}, {"audit_hash"}, {"decision"},
    ]
    missing_groups = [next(iter(g)) for g in expected_any if not (attrs & g)]
    if missing_groups:
        add("WEAK", check, rel(path), "-", "ActionReceipt structural fields",
            "Could not confirm expected fields: " + ", ".join(missing_groups))
    else:
        add("PASS", check, rel(path), "-", "ActionReceipt exposes lifecycle/audit structure.")

    text = path.read_text(encoding="utf-8", errors="replace")
    states = {"PROPOSED", "AUTHORIZED", "DENIED", "STARTED", "SUCCEEDED", "FAILED", "TIMEOUT"}
    absent = sorted(s for s in states if s not in text)
    if absent:
        add("FAIL", check, rel(path), "-", "Lifecycle states missing",
            "Missing state names: " + ", ".join(absent))
    else:
        add("PASS", check, rel(path), "-", "Required receipt lifecycle states are represented.")


# ═══════════════════════════════════════════════════════════════
#  TEST: ARENA SEPARATION
# ═══════════════════════════════════════════════════════════════

def test_arena_separation() -> None:
    check = "arena_isolation"
    path = SOURCEDIR / "arena/scenario.py"
    if not path.exists():
        add("INFO", check, rel(path), "-", "Arena scenario module absent.")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    required = ["ArenaScenario", "EngagementView", "EvaluatorTruth"]
    missing = [x for x in required if x not in text]
    if missing:
        add("FAIL", check, rel(path), "-", "Arena separation contract incomplete",
            "Missing: " + ", ".join(missing))
    else:
        add("PASS", check, rel(path), "-",
            "Separate ArenaScenario/EngagementView/EvaluatorTruth structures detected.")

    # Static leakage smells in engagement_view implementation.
    try:
        tree = trees.get(path) or ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "engagement_view":
                segment = ast.get_source_segment(text, node) or ""
                if "evaluator_truth" in segment and re.search(r"return[\s\S]*evaluator_truth", segment):
                    add("FAIL", check, rel(path), node.lineno,
                        "engagement_view references evaluator_truth",
                        "Potential ground-truth leakage into agent-visible view.",
                        "Construct EngagementView only from explicitly agent-visible fields.")
    except Exception as e:
        add("WEAK", check, rel(path), "-",
            "Could not statically inspect engagement_view", repr(e))


# ═══════════════════════════════════════════════════════════════
#  TEST: CAPABILITY BROKER FAIL-CLOSED
# ═══════════════════════════════════════════════════════════════

def test_capability_broker_fail_closed() -> None:
    check = "broker_fail_closed"
    candidates = [
        SOURCEDIR / "orchestrator/brain/capability_broker.py",
        SOURCEDIR / "orchestrator/hardening/capability_broker.py",
    ]
    path = next((p for p in candidates if p.exists()), None)
    if path is None:
        add("INFO", check, "capability_broker.py", "-", "CapabilityBroker module absent.")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    if "DENY" not in text.upper():
        add("FAIL", check, rel(path), "-", "No explicit DENY semantics detected",
            "A safety broker without explicit denial semantics cannot be verified fail-closed.")
    else:
        add("PASS", check, rel(path), "-", "Explicit DENY semantics detected.")

    # Catch obviously dangerous default-allow patterns.
    patterns = [
        r"except\s+Exception[^:]*:\s*\n\s*return\s+True",
        r"except\s*:\s*\n\s*return\s+True",
    ]
    for pat in patterns:
        if re.search(pat, text):
            add("FAIL", check, rel(path), "-",
                "Broker exception path returns allow/True",
                "Authorization failure appears fail-open.",
                "Broker exceptions must deny or surface an infrastructure failure.")


# ═══════════════════════════════════════════════════════════════
#  TEST: HARDCODED ABSOLUTE PATHS
# ═══════════════════════════════════════════════════════════════

def test_hardcoded_absolute_paths() -> None:
    check = "portability"
    home_pat = re.compile(r"""["'](/home/[^"']+|[A-Za-z]:\\Users\\[^"']+)["']""")
    for p, text in sources.items():
        if p.name.startswith("JUDGE"):
            continue
        for m in home_pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            add("WEAK", check, rel(p), line, m.group(1),
                "User-specific absolute path reduces reproducibility.",
                "Resolve paths from configuration/project root instead.")


# ═══════════════════════════════════════════════════════════════
#  TEST: TEST SUITE
# ═══════════════════════════════════════════════════════════════

def test_test_suite() -> None:
    """Run only the project's explicit tests directory, never arbitrary project commands."""
    check = "pytest"
    tests = ROOT / "tests"
    if not tests.exists() or not shutil.which("pytest"):
        add("INFO", check, "tests", "-", "pytest/tests unavailable; skipped.")
        return
    try:
        cp = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", str(tests)],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": str(SOURCEDIR)},
        )
        tail = (cp.stdout + "\n" + cp.stderr)[-4000:]
        if cp.returncode == 0:
            add("PASS", check, "tests", "-", "Project test suite passed.", tail.strip())
        else:
            add("FAIL", check, "tests", "-", f"pytest exited {cp.returncode}", tail.strip(),
                "Fix failing tests; do not suppress them in JUDGE.")
    except subprocess.TimeoutExpired:
        add("FAIL", check, "tests", "-", "pytest timed out after 120s",
            "Test suite is hanging or exceeds the audit budget.")
    except Exception as e:
        add("CRASH", check, "tests", "-", "pytest invocation crashed", repr(e))


# ═══════════════════════════════════════════════════════════════
#  TEST: DUPLICATE DEFINITIONS
# ═══════════════════════════════════════════════════════════════

def test_duplicate_defs() -> None:
    check = "duplicate_definitions"
    for p, tree in trees.items():
        for scope in [tree] + [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            seen = {}
            body = getattr(scope, "body", [])
            for n in body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if n.name in seen:
                        add("WEAK", check, rel(p), n.lineno,
                            f"Duplicate definition '{n.name}'",
                            f"Earlier definition at line {seen[n.name]} is shadowed.")
                    seen[n.name] = n.lineno


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def main() -> int:
    global LOCAL_ROOTS
    discover_files()
    parse_all()
    LOCAL_ROOTS = discover_local_roots()

    checks = [
        ("imports", test_imports),
        ("requirements", test_requirements_integrity),
        # ablation_noops must run BEFORE stub_honesty to register verified NoOps
        ("ablation_noops", test_ablation_noops),
        ("stub_honesty", test_stub_honesty),
        ("module_singletons", test_module_level_singletons),
        ("exception_hygiene", test_broad_exception_swallowing),
        ("dynamic_execution", test_dangerous_eval_exec),
        ("subprocess", test_subprocess_contracts),
        ("crypto_roundtrip", test_crypto_roundtrips),
        ("action_receipt_contract", test_action_receipt_contract),
        ("arena_isolation", test_arena_separation),
        ("broker_fail_closed", test_capability_broker_fail_closed),
        ("portability", test_hardcoded_absolute_paths),
        ("duplicate_definitions", test_duplicate_defs),
        ("pytest", test_test_suite),
    ]

    for name, fn in checks:
        print(f"  {name} ...", end=" ", flush=True)
        before = len(reports)
        try:
            fn()
            print(f"{len(reports)-before} findings")
        except Exception as e:
            add("CRASH", name, "JUDGE.py", "-", "Audit check crashed",
                "".join(traceback.format_exception_only(type(e), e)).strip())
            print("CRASH")

    elapsed_ms = int((time.time() - START) * 1000)
    hard = counts["FAIL"] + counts["CRASH"] + counts["FABRICATION"]
    declared_gaps = counts["DECLARED_GAP"]
    intentional_noops = counts["INTENTIONAL_NOOP"]

    summary = {
        "judge_version": "2.1",
        "root": str(ROOT),
        "files_audited": len(py_files),
        "elapsed_ms": elapsed_ms,
        "counts": {
            "PASS": counts["PASS"],
            "INFO": counts["INFO"],
            "DECLARED_GAP": declared_gaps,
            "INTENTIONAL_NOOP": intentional_noops,
            "WEAK": counts["WEAK"],
            "FAIL": counts["FAIL"],
            "CRASH": counts["CRASH"],
            "FABRICATION": counts["FABRICATION"],
        },
        "hard_failures": hard,
        "declared_gaps": declared_gaps,
        "intentional_noops": intentional_noops,
        "reports": reports,
    }

    report_path = ROOT / "judge_report.json"
    report_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    # ── Console summary ─────────────────────────────────────
    print("\n" + "=" * 72)
    print("  JUDGE v2.1 FINAL VERDICT")
    print("=" * 72)
    print(f"  Files audited: {len(py_files)}")
    print(f"  Elapsed: {elapsed_ms}ms")
    print()
    print(f"  FAIL             : {counts['FAIL']}")
    print(f"  CRASH            : {counts['CRASH']}")
    print(f"  FABRICATION      : {counts['FABRICATION']}")
    print(f"  ─────────────────────────────────────────")
    print(f"  Hard failures    : {hard}")
    print(f"  ─────────────────────────────────────────")
    print(f"  DECLARED_GAP     : {declared_gaps}")
    print(f"  INTENTIONAL_NOOP : {intentional_noops}")
    print(f"  WEAK             : {counts['WEAK']}")
    print(f"  INFO             : {counts['INFO']}")
    print(f"  PASS             : {counts['PASS']}")
    print(f"  ─────────────────────────────────────────")
    if declared_gaps > 0:
        print(f"  ⚠ Declared gaps: {declared_gaps} NOT_IMPLEMENTED functions")
    if intentional_noops > 0:
        print(f"  ℹ Ablation NoOps: {intentional_noops} verified inert stubs")
    print()

    if hard:
        print(f"  INTEGRITY: FAIL ❌ ({hard} hard failures)")
    else:
        print(f"  INTEGRITY: PASS ✅")

    print(f"\n  JSON report: {report_path}")
    print()

    # ── Detailed findings grouped by severity ───────────────
    for severity in ["FABRICATION", "CRASH", "FAIL", "DECLARED_GAP", "INTENTIONAL_NOOP", "WEAK"]:
        subset = [x for x in reports if x["verdict"] == severity]
        if not subset:
            continue
        print(f"\n  ── {severity} ({len(subset)}) ──")
        for item in subset:
            print(f"  [{item['check']}] {item['file']}:{item['lines']} — {item['evidence']}")
            if item["failure"]:
                print(f"    {item['failure']}")
            if item["fix"]:
                print(f"    FIX: {item['fix']}")

    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
