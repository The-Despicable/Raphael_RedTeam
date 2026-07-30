import json
import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("binary_analyzer")

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False
    logger.warning("r2pipe not available - binary analysis limited")


@dataclass
class FunctionInfo:
    name: str
    address: int
    size: int
    is_import: bool = False
    is_entry: bool = False
    calls: list[int] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    cyclomatic_complexity: int = 1


@dataclass
class BinaryAnalysis:
    filepath: str
    arch: str
    bits: int
    endian: str
    file_type: str
    entry_point: int
    sections: list[dict]
    imports: list[dict]
    exports: list[dict]
    strings: list[str]
    functions: list[FunctionInfo]
    suspicious_patterns: list[dict]
    shell_commands: list[str]
    format_strings: list[str]
    crypto_constants: list[str]
    risk_score: int = 0


class BinaryAnalyzer:
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self._r2_cache: dict[str, Any] = {}

    def analyze(self, filepath: str, deep: bool = False) -> BinaryAnalysis:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Binary not found: {filepath}")

        if R2PIPE_AVAILABLE:
            return self._analyze_with_r2(filepath, deep)
        else:
            return self._analyze_fallback(filepath)

    def _analyze_with_r2(self, filepath: str, deep: bool) -> BinaryAnalysis:
        r2 = r2pipe.open(filepath, flags=["-2"])
        try:
            r2.cmd("e asm.describe=false")
            r2.cmd("e asm.pseudo=false")

            info = json.loads(r2.cmd("ij"))
            if not info:
                raise ValueError("Failed to get binary info")

            arch = info.get("arch", "unknown")
            bits = info.get("bits", 0)
            endian = info.get("endian", "little")
            file_type = info.get("type", "unknown")
            entry = info.get("entry", 0)

            sections = r2.cmdj("iSj") or []
            imports = r2.cmdj("iij") or []
            exports = r2.cmdj("iEj") or []

            strings = self._extract_strings(r2)
            functions = self._analyze_functions(r2, deep)
            suspicious = self._find_suspicious_patterns(r2, strings, functions)
            shell_cmds = self._extract_shell_commands(strings, functions)
            format_strs = self._extract_format_strings(strings, functions)
            crypto_consts = self._extract_crypto_constants(strings)

            risk = self._calculate_risk_score(suspicious, shell_cmds, format_strs, imports)

            return BinaryAnalysis(
                filepath=filepath,
                arch=arch,
                bits=bits,
                endian=endian,
                file_type=file_type,
                entry_point=entry,
                sections=sections,
                imports=imports,
                exports=exports,
                strings=strings,
                functions=functions,
                suspicious_patterns=suspicious,
                shell_commands=shell_cmds,
                format_strings=format_strs,
                crypto_constants=crypto_consts,
                risk_score=risk,
            )
        finally:
            r2.quit()

    def _analyze_fallback(self, filepath: str) -> BinaryAnalysis:
        strings = self._strings_fallback(filepath)
        imports = self._imports_fallback(filepath)

        suspicious = []
        shell_cmds = [s for s in strings if any(cmd in s.lower() for cmd in
            ["sh ", "bash", "cmd.exe", "powershell", "system(", "popen", "execv", "CreateProcess"])]
        format_strs = [s for s in strings if re.search(r"%[sdnfpx]", s)]

        risk = len(shell_cmds) * 5 + len(format_strs) * 3 + len(imports) * 1

        return BinaryAnalysis(
            filepath=filepath,
            arch="unknown",
            bits=0,
            endian="unknown",
            file_type="unknown",
            entry_point=0,
            sections=[],
            imports=imports,
            exports=[],
            strings=strings,
            functions=[],
            suspicious_patterns=suspicious,
            shell_commands=shell_cmds,
            format_strings=format_strs,
            crypto_constants=[],
            risk_score=risk,
        )

    def _strings_fallback(self, filepath: str, min_len: int = 4) -> list[str]:
        try:
            result = subprocess.run(
                ["strings", "-n", str(min_len), filepath],
                capture_output=True, text=True, timeout=30
            )
            return [s.strip() for s in result.stdout.splitlines() if s.strip()]
        except Exception:
            return []

    def _imports_fallback(self, filepath: str) -> list[dict]:
        imports = []
        try:
            result = subprocess.run(
                ["objdump", "-T", filepath],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                if "UND" in line and not line.startswith(" "):
                    parts = line.split()
                    if len(parts) >= 4:
                        imports.append({"name": parts[-1], "type": "FUNC"})
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return imports

    def _extract_strings(self, r2) -> list[str]:
        try:
            raw = r2.cmd("izzj")
            if raw:
                data = json.loads(raw)
                return [s.get("string", "") for s in data if s.get("string")]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    def _analyze_functions(self, r2, deep: bool) -> list[FunctionInfo]:
        functions = []
        try:
            afl = r2.cmdj("aflj")
            if not afl:
                return functions

            for f in afl:
                addr = f.get("offset", 0)
                name = f.get("name", f"fcn.{addr:x}")
                size = f.get("size", 0)
                is_import = f.get("is-import", False)
                is_entry = f.get("is-entry", False)

                strings = []
                calls = []

                if deep:
                    try:
                        f_strings = r2.cmdj(f"izz @ {addr}")
                        if f_strings:
                            strings = [s.get("string", "") for s in f_strings if s.get("string")]
                        f_calls = r2.cmdj(f"axtj @ {addr}")
                        if f_calls:
                            calls = [c.get("from", 0) for c in f_calls if c.get("type") == "CALL"]
                    except Exception:
                        logger.debug("Non-critical error", exc_info=True)

                cc = 1
                if deep:
                    try:
                        cc = max(1, len(calls) + 1)
                    except Exception:
                        logger.debug("Non-critical error", exc_info=True)

                functions.append(FunctionInfo(
                    name=name,
                    address=addr,
                    size=size,
                    is_import=is_import,
                    is_entry=is_entry,
                    calls=calls,
                    strings=strings,
                    cyclomatic_complexity=cc,
                ))
        except Exception as e:
            logger.warning(f"Function analysis failed: {e}")

        return functions

    def _find_suspicious_patterns(self, r2, strings: list[str], functions: list[FunctionInfo]) -> list[dict]:
        patterns = []

        dangerous_imports = {
            "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
            "CreateProcess", "WinExec", "ShellExecute", "system", "_popen", "_wsystem",
            "dlopen", "dlsym", "LoadLibrary", "GetProcAddress",
            "mmap", "VirtualAlloc", "mprotect", "VirtualProtect",
            "ptrace", "fork", "clone", "vfork",
            "socket", "connect", "bind", "listen", "accept",
            "send", "recv", "sendto", "recvfrom",
        }

        for imp in functions:
            if imp.is_import and imp.name in dangerous_imports:
                patterns.append({
                    "type": "dangerous_import",
                    "function": imp.name,
                    "address": imp.address,
                    "severity": "high",
                })

        shell_strs = [s for s in strings if any(
            kw in s.lower() for kw in
            ["/bin/sh", "/bin/bash", "cmd.exe", "powershell", "wget", "curl", "nc ", "netcat",
             "socat", "telnet", "ssh ", "scp ", "base64 -d", "eval(", "exec("]
        )]
        for s in shell_strs:
            patterns.append({
                "type": "shell_command_string",
                "string": s[:200],
                "severity": "high",
            })

        format_strings = [s for s in strings if re.search(r"%[sdnfpx]{1,2}[^a-zA-Z]", s)]
        for s in format_strings:
            patterns.append({
                "type": "format_string",
                "string": s[:200],
                "severity": "medium",
            })

        return patterns

    def _extract_shell_commands(self, strings: list[str], functions: list[FunctionInfo]) -> list[str]:
        cmds = set()
        shell_keywords = [
            "sh -c", "bash -c", "cmd /c", "powershell -c", "system(", "popen(",
            "execve(", "CreateProcess", "WinExec", "ShellExecute", "subprocess.",
            "os.system", "os.popen", "commands.getstatusoutput",
        ]
        for s in strings:
            for kw in shell_keywords:
                if kw in s:
                    cmds.add(s.strip())
                    break
        return list(cmds)

    def _extract_format_strings(self, strings: list[str], functions: list[FunctionInfo]) -> list[str]:
        fmt_strings = []
        for s in strings:
            if re.search(r"%[sdnfpx]{1,2}[^a-zA-Z0-9%]", s):
                fmt_strings.append(s.strip())
        return fmt_strings

    def _extract_crypto_constants(self, strings: list[str]) -> list[str]:
        crypto = []
        for s in strings:
            if re.search(r"(AES|RSA|SHA|MD5|DES|RC4|Blowfish|ChaCha|Poly1305|Curve25519|secp256k1|0x[0-9a-f]{32,})", s, re.I):
                crypto.append(s.strip())
        return crypto

    def _calculate_risk_score(self, suspicious: list[dict], shell_cmds: list[str],
                              format_strs: list[str], imports: list[dict]) -> int:
        score = 0
        for s in suspicious:
            if s.get("severity") == "high":
                score += 10
            elif s.get("severity") == "medium":
                score += 5
        score += len(shell_cmds) * 5
        score += len(format_strs) * 3
        score += len([i for i in imports if i.get("name", "") in
                     {"system", "popen", "exec", "CreateProcess"}]) * 15
        return min(score, 100)


def analyze_binary(filepath: str, deep: bool = False) -> BinaryAnalysis:
    analyzer = BinaryAnalyzer()
    return analyzer.analyze(filepath, deep)


def analyze_from_bytes(data: bytes, deep: bool = False) -> BinaryAnalysis:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        return analyze_binary(tmp, deep)
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            logger.debug("Non-critical error", exc_info=True)


async def auto_analyze_downloaded_binary(url: str, headers: dict = None) -> Optional[BinaryAnalysis]:
    import requests
    try:
        r = requests.get(url, headers=headers or {}, timeout=30, verify=False)
        if r.status_code == 200 and r.content:
            return analyze_from_bytes(r.content)
    except Exception as e:
        logger.warning(f"Failed to download/analyze binary from {url}: {e}")
    return None