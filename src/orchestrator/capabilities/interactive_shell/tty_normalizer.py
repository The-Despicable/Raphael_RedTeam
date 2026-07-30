"""tty_normalizer.py — TTY output normalization and evidence extraction.

Converts raw ANSI/terminal byte streams into structured Evidence objects
for the EvidenceGraph and WorldModel.

Pipeline:
    Raw bytes -> ANSI strip -> Backspace handling -> Prompt detection
    -> Command/Output segmentation -> Structured parsing -> Evidence
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional, Dict

from orchestrator.brain.evidence import Evidence, TrustLevel, get_evidence_graph

logger = logging.getLogger("tty_normalizer")


# ── ANSI Escape Sequence Regex ────────────────────────────────────

# Common ANSI escape sequences
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
ANSI_OSC_RE = re.compile(r"\x1b\][^\x07]*\x07")  # Operating System Command
ANSI_8BIT_RE = re.compile(r"\x1b[@-Z\\-_]")       # 8-bit control sequences
CSI_RE = re.compile(r"\x1b\[[0-9;]*[mKHJ]")       # Color/Style/Erase
LINK_RE = re.compile(r"\x1b\]8;;([^\x07]+)\x07")  # Hyperlinks

# Backspace handling
BACKSPACE_CHAR = "\x08"
DELETE_CHAR = "\x7f"

# Common prompt patterns
# NOTE: Prompts appear at the BEGINNING of TTY lines, followed by the command.
# Patterns should match at line starts (via re.MULTILINE + ^ anchor) rather
# than requiring end-of-line ($) which won't match when command follows prompt.
DEFAULT_PROMPT_PATTERNS = [
    r"^[\w\-\.]+[@\s][\w\-\.]+[:~\w\-\./]*[\$\#>]\s*",  # user@host$ or user@host:~$ or root@host#
    r"^root@[\w\-\.]+[:~\w\-\./]*[\$\#>]\s*",             # root@host:~#
    r"^[\w\-\.]+[\$\#>]\s*",                               # simple host$ or hostname#
    r"^\([\w\-\.]+\)\s*[\w\-\.@]+[:~\w\-\./]*[\$\#>]\s*", # (venv) user@host:~$
    r"^PS1\s*=",                                            # PS1 assignment
    r"^\$\s*",                                              # bare $
    r"^#\s*",                                               # bare #
    r"^>\s*",                                               # generic >
]


@dataclass
class ParsedCommand:
    """A parsed command with its output."""
    command: str
    output_lines: List[str]
    raw_output: str
    timestamp: float
    exit_code: Optional[int] = None
    duration_ms: float = 0.0
    prompt_before: str = ""
    prompt_after: str = ""


@dataclass
class ParsedOutput:
    """Normalized TTY output with parsed commands."""
    session_id: str
    commands: List[ParsedCommand]
    raw_buffer: str
    parsed_at: float = field(default_factory=time.time)


class TTYNormalizer:
    """
    Normalizes raw TTY streams into structured command/output pairs.

    Handles:
    - ANSI escape sequence stripping (colors, cursor movement, etc.)
    - Backspace/delete character processing
    - Prompt detection and command/output segmentation
    - Line wrapping and terminal width handling
    """

    def __init__(
        self,
        prompt_patterns: List[str] = None,
        encoding: str = "utf-8",
        terminal_width: int = 120,
    ):
        self.prompt_patterns = prompt_patterns or DEFAULT_PROMPT_PATTERNS
        self.compiled_prompts = [re.compile(p, re.MULTILINE) for p in self.prompt_patterns]
        self.encoding = encoding
        self.terminal_width = terminal_width

        # State for incremental processing
        self._buffer = ""
        self._processed_buffer = ""
        self._pending_command = None
        self._last_prompt = ""
        self._command_count = 0

    def process_chunk(self, raw_bytes: bytes) -> List[ParsedCommand]:
        """
        Process a chunk of raw TTY output.

        Returns list of completed ParsedCommand objects.
        Incomplete commands remain in buffer for next chunk.
        """
        try:
            decoded = raw_bytes.decode(self.encoding, errors="replace")
        except UnicodeDecodeError:
            decoded = raw_bytes.decode("latin-1", errors="replace")

        # Strip ANSI escapes
        cleaned = self._strip_ansi(decoded)

        # Handle backspace/delete
        cleaned = self._process_backspaces(cleaned)

        # Add to buffer
        self._buffer += cleaned

        # Parse completed commands
        completed = self._parse_buffer()

        return completed

    def _strip_ansi(self, text: str) -> str:
        """Remove ANSI escape sequences."""
        # Remove OSC sequences first (can contain newlines)
        text = ANSI_OSC_RE.sub("", text)
        # Remove CSI and other ANSI
        text = CSI_RE.sub("", text)
        text = ANSI_ESCAPE_RE.sub("", text)
        text = ANSI_8BIT_RE.sub("", text)
        # Remove hyperlink sequences
        text = LINK_RE.sub(r"\1", text)
        return text

    def _process_backspaces(self, text: str) -> str:
        """Process backspace (^H) and delete (^?) characters."""
        result = []
        for char in text:
            if char in (BACKSPACE_CHAR, DELETE_CHAR):
                if result:
                    result.pop()
            else:
                result.append(char)
        return "".join(result)

    def _parse_buffer(self) -> List[ParsedCommand]:
        """Parse buffer for completed commands.

        Logic:
        1. Find the first prompt → marks start of a new command cycle
        2. Content after the prompt, until newline, is the command text
        3. Everything until the next prompt is the command's output
        4. When next prompt is found, the previous command is complete
        """
        completed = []

        while True:
            # Find the NEXT prompt in the buffer
            prompt_match = self._find_next_prompt()
            if not prompt_match:
                break

            prompt_text = prompt_match.group(0)
            prompt_end = prompt_match.end()

            # If we have a pending command, this prompt marks the end of its output
            if self._pending_command is not None:
                # Everything from pending_start to this prompt's start is output
                output_start = self._pending_start
                output_end = prompt_match.start()
                output_text = self._buffer[output_start:output_end].rstrip("\n")

                cmd = ParsedCommand(
                    command=self._pending_command.strip(),
                    output_lines=output_text.splitlines() if output_text else [],
                    raw_output=output_text,
                    timestamp=time.time(),
                    prompt_before=self._last_prompt,
                    prompt_after=prompt_text,
                )
                completed.append(cmd)
                self._command_count += 1
                self._pending_command = None

            # Advance buffer past this prompt
            self._buffer = self._buffer[prompt_end:]
            self._last_prompt = prompt_text

            # Check if there's a command on the same line as the prompt
            # (everything from start of buffer until first newline)
            newline_idx = self._buffer.find("\n")
            if newline_idx >= 0:
                # There is a command on this line
                cmd_text = self._buffer[:newline_idx]
                if cmd_text.strip():
                    self._pending_command = cmd_text
                    self._pending_start = 0
                    self._buffer = self._buffer[newline_idx + 1:]
                else:
                    # Empty command — skip the newline and continue
                    self._buffer = self._buffer[newline_idx + 1:]
            else:
                # No newline yet — either no command or incomplete
                # Check if there's any non-whitespace (a command)
                if self._buffer.strip():
                    self._pending_command = self._buffer.strip()
                    self._pending_start = 0
                    self._buffer = ""
                # If buffer is empty or just whitespace, it's an empty prompt — break

        return completed

    def _find_next_prompt(self) -> Optional[re.Match]:
        """Find the next prompt in buffer."""
        earliest = None
        earliest_pos = len(self._buffer)

        for pattern in self.compiled_prompts:
            match = pattern.search(self._buffer)
            if match and match.start() < earliest_pos:
                earliest = match
                earliest_pos = match.start()

        return earliest

    def flush(self) -> List[ParsedCommand]:
        """Flush any remaining buffer as a final command."""
        completed = []

        if self._pending_command and self._buffer:
            # Treat remaining buffer as output
            cmd = ParsedCommand(
                command=self._pending_command.strip(),
                output_lines=self._buffer.splitlines(),
                raw_output=self._buffer,
                timestamp=time.time(),
                prompt_before=self._last_prompt,
                prompt_after="(EOF)",
            )
            completed.append(cmd)
            self._command_count += 1

        # Clear state
        self._buffer = ""
        self._pending_command = None
        self._last_prompt = ""

        return completed

    def get_stats(self) -> Dict[str, Any]:
        return {
            "buffer_size": len(self._buffer),
            "pending_command": self._pending_command is not None,
            "command_count": self._command_count,
            "last_prompt": self._last_prompt[:50] if self._last_prompt else "",
        }


class EvidenceExtractor:
    """
    Extracts structured Evidence objects from parsed TTY output.

    Creates Evidence of types:
    - COMMAND_EXECUTED
    - COMMAND_OUTPUT
    - FILE_CONTENT
    - PROCESS_LIST
    - NETWORK_CONNECTIONS
    - USER_ACCOUNTS
    - CREDENTIAL
    - VULNERABILITY_INDICATOR
    """

    def __init__(self, evidence_graph=None):
        self.evidence_graph = evidence_graph or get_evidence_graph()

    def extract_from_command(
        self,
        parsed: ParsedCommand,
        session_id: str,
        target: str,
        collected_by: str = "",
    ) -> List[Evidence]:
        """Extract all evidence from a parsed command."""
        evidence_list = []

        # 1. COMMAND_EXECUTED evidence
        cmd_evidence = self._create_command_evidence(parsed, session_id, target, collected_by)
        evidence_list.append(cmd_evidence)

        # 2. COMMAND_OUTPUT evidence (if output exists)
        if parsed.raw_output.strip():
            output_evidence = self._create_output_evidence(parsed, session_id, target, collected_by, cmd_evidence.evidence_id)
            evidence_list.append(output_evidence)

        # 3. Structured parsing based on command
        structured = self._parse_structured_output(parsed, target=target, collected_by=collected_by)
        for ev in structured:
            if self.evidence_graph:
                self.evidence_graph.add_derived_from(ev.evidence_id, cmd_evidence.evidence_id)
            evidence_list.append(ev)

        return evidence_list

    def _create_command_evidence(
        self,
        parsed: ParsedCommand,
        session_id: str,
        target: str,
        collected_by: str,
    ) -> Evidence:
        return Evidence.create(
            raw_content=f"$ {parsed.command}",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail=f"shell_session:{session_id}",
            target=target,
            phase="execution",
            evidence_type="command_executed",
            description=f"Command executed in shell session {session_id}",
            structured_content={
                "session_id": session_id,
                "command": parsed.command,
                "exit_code": parsed.exit_code,
                "duration_ms": parsed.duration_ms,
                "prompt_before": parsed.prompt_before,
                "prompt_after": parsed.prompt_after,
            },
            collected_by=collected_by,
        )

    def _create_output_evidence(
        self,
        parsed: ParsedCommand,
        session_id: str,
        target: str,
        collected_by: str,
        parent_id: str,
    ) -> Evidence:
        return Evidence.create(
            raw_content=parsed.raw_output,
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail=f"shell_session:{session_id}",
            target=target,
            phase="execution",
            evidence_type="command_output",
            description=f"Output of command: {parsed.command[:80]}",
            structured_content={
                "session_id": session_id,
                "command": parsed.command,
                "output_lines": len(parsed.output_lines),
                "exit_code": parsed.exit_code,
            },
            collected_by=collected_by,
        )

    def _parse_structured_output(
        self,
        parsed: ParsedCommand,
        target: str = "",
        collected_by: str = "",
    ) -> List[Evidence]:
        """Parse command output for structured data."""
        evidence = []
        output = parsed.raw_output
        command = parsed.command.lower()

        # FILE_CONTENT: cat, less, more, head, tail
        if any(cmd in command for cmd in ["cat ", "head ", "tail ", "less ", "more "]):
            # Extract file path from command
            parts = parsed.command.split()
            if len(parts) > 1:
                file_path = parts[1]
                ev = Evidence.create(
                    raw_content=output,
                    trust_level=TrustLevel.TOOL_OBSERVATION,
                    source_detail=f"shell:cat {file_path}",
                    target=parsed.command.split()[1] if len(parts) > 1 else target,
                    phase="post_exploitation",
                    evidence_type="file_content",
                    description=f"File content: {file_path}",
                    structured_content={
                        "path": file_path,
                        "content": output,
                        "size_bytes": len(output.encode()),
                    },
                    collected_by=collected_by or parsed.command,
                )
                evidence.append(ev)

        # PROCESS_LIST: ps, top, htop
        elif any(cmd in command for cmd in ["ps ", "top", "htop"]):
            processes = self._parse_process_list(output)
            if processes:
                ev = Evidence.create(
                    raw_content=output,
                    trust_level=TrustLevel.TOOL_OBSERVATION,
                    source_detail=f"shell:{command}",
                    target=target,
                    phase="post_exploitation",
                    evidence_type="process_list",
                    description=f"Process list ({len(processes)} processes)",
                    structured_content={"processes": processes},
                    collected_by=collected_by or parsed.command,
                )
                evidence.append(ev)

        # NETWORK_CONNECTIONS: netstat, ss, lsof
        elif any(cmd in command for cmd in ["netstat ", "ss ", "lsof "]):
            connections = self._parse_netstat(output)
            if connections:
                ev = Evidence.create(
                    raw_content=output,
                    trust_level=TrustLevel.TOOL_OBSERVATION,
                    source_detail=f"shell:{command}",
                    target=target,
                    phase="post_exploitation",
                    evidence_type="network_connections",
                    description=f"Network connections ({len(connections)} entries)",
                    structured_content={"connections": connections},
                    collected_by=collected_by or parsed.command,
                )
                evidence.append(ev)

        # USER_ACCOUNTS: cat /etc/passwd, getent passwd, id, who, w
        elif any(cmd in command for cmd in ["/etc/passwd", "getent passwd", "getent group", " id", " who", " w"]):
            users = self._parse_user_list(output)
            if users:
                ev = Evidence.create(
                    raw_content=output,
                    trust_level=TrustLevel.TOOL_OBSERVATION,
                    source_detail=f"shell:{command}",
                    target=target,
                    phase="post_exploitation",
                    evidence_type="user_accounts",
                    description=f"User accounts ({len(users)} entries)",
                    structured_content={"accounts": users},
                    collected_by=collected_by or parsed.command,
                )
                evidence.append(ev)

        # CREDENTIAL: shadow, sudoers, ssh keys, .bash_history, env
        elif any(pattern in command for pattern in ["/etc/shadow", "/etc/sudoers", ".ssh/", "authorized_keys", "id_rsa", "id_ed25519", "bash_history", "env | grep -i pass", "env | grep -i key", "env | grep -i token"]):
            creds = self._extract_credentials(output, command)
            if creds:
                for cred in creds:
                    ev = Evidence.create(
                        raw_content=cred["raw"],
                        trust_level=TrustLevel.TARGET_CONTROLLED,
                        source_detail=f"shell:{command}",
                        target=target,
                        phase="credential_access",
                        evidence_type="credential",
                        description=f"Credential found: {cred['type']}",
                        structured_content=cred,
                        collected_by=collected_by or parsed.command,
                    )
                    evidence.append(ev)

        # VULNERABILITY_INDICATOR: kernel version, sudo version, suid files, capabilities
        elif any(pattern in command for pattern in ["uname -a", "cat /proc/version", "lsb_release", "sudo -V", "find / -perm -4000", "getcap -r", "dpkg -l", "rpm -qa"]):
            vulns = self._check_vulnerability_indicators(output, command)
            for vuln in vulns:
                ev = Evidence.create(
                    raw_content=vuln["raw"],
                    trust_level=TrustLevel.TOOL_OBSERVATION,
                    source_detail=f"shell:{command}",
                    target=target,
                    phase="vulnerability_assessment",
                    evidence_type="vulnerability_indicator",
                    description=vuln["description"],
                    structured_content=vuln,
                    collected_by=collected_by or parsed.command,
                )
                evidence.append(ev)

        return evidence

    # ── Structured Parsers ────────────────────────────────────────

    def _parse_process_list(self, output: str) -> List[Dict]:
        """Parse ps/top output."""
        processes = []
        lines = output.strip().splitlines()

        # Skip header
        data_lines = lines[1:] if len(lines) > 1 else lines

        for line in data_lines:
            line = line.strip()
            if not line:
                continue
            # Try common ps formats: ps aux, ps -ef, etc.
            parts = line.split(None, 10)
            if len(parts) >= 10:
                try:
                    processes.append({
                        "user": parts[0],
                        "pid": int(parts[1]),
                        "ppid": int(parts[2]) if parts[2].isdigit() else 0,
                        "cpu": float(parts[3]) if parts[3].replace(".", "").isdigit() else 0,
                        "mem": float(parts[4]) if parts[4].replace(".", "").isdigit() else 0,
                        "vsz": parts[5],
                        "rss": parts[6],
                        "tty": parts[7],
                        "stat": parts[8],
                        "start": parts[9],
                        "cmd": parts[10] if len(parts) > 10 else "",
                    })
                except (ValueError, IndexError):
                    pass
        return processes

    def _parse_netstat(self, output: str) -> List[Dict]:
        """Parse netstat/ss output."""
        connections = []
        lines = output.strip().splitlines()

        for line in lines[2:]:  # Skip headers
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "proto": parts[0],
                    "recv_q": parts[1],
                    "send_q": parts[2],
                    "local_addr": parts[3],
                    "foreign_addr": parts[4],
                    "state": parts[5] if len(parts) > 5 else "",
                    "pid": parts[6] if len(parts) > 6 else "",
                })
        return connections

    def _parse_user_list(self, output: str) -> List[Dict]:
        """Parse /etc/passwd, getent, id, who, w output."""
        users = []

        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # /etc/passwd format: user:x:uid:gid:gecos:home:shell
            if ":" in line and line.count(":") >= 6:
                parts = line.split(":")
                users.append({
                    "username": parts[0],
                    "uid": int(parts[2]) if parts[2].isdigit() else 0,
                    "gid": int(parts[3]) if parts[3].isdigit() else 0,
                    "gecos": parts[4],
                    "home": parts[5],
                    "shell": parts[6],
                })
            # id output: uid=1000(user) gid=1000(user) groups=...
            elif "uid=" in line:
                users.append({"raw": line})

        return users

    def _extract_credentials(self, output: str, command: str) -> List[Dict]:
        """Extract credentials from output."""
        creds = []

        # Look for patterns
        patterns = {
            "password_hash": r"(\$[0-9a-z]+\$[^\$]+\$[^\s:]+)",
            "ssh_private_key": r"(-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)",
            "ssh_public_key": r"(ssh-(?:rsa|dsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]+\s*\S*)",
            "api_key": r"([Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]\s*[=:]\s*[A-Za-z0-9_\-]{20,})",
            "aws_secret": r"(aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40})",
            "jwt": r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
        }

        for cred_type, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                creds.append({
                    "type": cred_type,
                    "raw": match[:200],  # Truncate
                    "source_command": command,
                    "hash": hashlib.sha256(match.encode()).hexdigest()[:16],
                })

        return creds

    def _check_vulnerability_indicators(self, output: str, command: str) -> List[Dict]:
        """Check output for vulnerability indicators."""
        vulns = []

        # Kernel version
        if "uname" in command or "/proc/version" in command:
            match = re.search(r"Linux version ([\d\.\-]+)", output)
            if match:
                version = match.group(1)
                vulns.append({
                    "vuln_class": "kernel_version_disclosure",
                    "description": f"Kernel version disclosed: {version}",
                    "raw": version,
                    "confidence": 0.8,
                })

        # SUID files
        if "find" in command and "-perm" in command and "4000" in command:
            suid_files = [l.strip() for l in output.splitlines() if l.strip()]
            for f in suid_files[:20]:  # Limit
                vulns.append({
                    "vuln_class": "suid_binary",
                    "description": f"SUID binary found: {f}",
                    "raw": f,
                    "confidence": 0.7,
                })

        # Capabilities
        if "getcap" in command:
            cap_lines = [l.strip() for l in output.splitlines() if "=" in l]
            for c in cap_lines[:20]:
                vulns.append({
                    "vuln_class": "file_capabilities",
                    "description": f"File capability: {c}",
                    "raw": c,
                    "confidence": 0.6,
                })

        # Sudo version
        if "sudo -V" in command or "sudo --version" in command:
            match = re.search(r"Sudo version ([\d\.]+)", output)
            if match:
                vulns.append({
                    "vuln_class": "sudo_version_disclosure",
                    "description": f"Sudo version: {match.group(1)}",
                    "raw": match.group(1),
                    "confidence": 0.9,
                })

        return vulns


# ── Utility Functions ─────────────────────────────────────────────

def normalize_tty_stream(
    raw_bytes: bytes,
    session_id: str,
    target: str,
    prompt_patterns: List[str] = None,
) -> ParsedOutput:
    """One-shot normalization of a complete TTY stream."""
    normalizer = TTYNormalizer(prompt_patterns=prompt_patterns)
    commands = normalizer.process_chunk(raw_bytes)
    commands.extend(normalizer.flush())
    return ParsedOutput(
        session_id=session_id,
        commands=commands,
        raw_buffer=raw_bytes.decode("utf-8", errors="replace"),
    )


def extract_evidence_from_tty(
    raw_bytes: bytes,
    session_id: str,
    target: str,
    collected_by: str = "",
    prompt_patterns: List[str] = None,
) -> List[Evidence]:
    """Convenience: normalize and extract evidence in one call."""
    parsed = normalize_tty_stream(raw_bytes, session_id, target, prompt_patterns)
    extractor = EvidenceExtractor()
    all_evidence = []
    for cmd in parsed.commands:
        all_evidence.extend(extractor.extract_from_command(cmd, session_id, target, collected_by))
    return all_evidence