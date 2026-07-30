"""ssh_shell.py — SSHShellCapability implementation using paramiko.

Provides interactive SSH shell sessions with PTY allocation, command execution,
and output streaming. Integrates with the InteractiveShellCapability interface.
"""

import asyncio
import logging
import re
import time
from typing import Optional

import paramiko

from .capability import (
    InteractiveShellCapability,
    ShellCapabilityType,
    ShellConnectionInfo,
    ShellCommandResult,
    ShellCapabilityFactory,
)

logger = logging.getLogger("interactive_shell.ssh")


class SSHShellCapability(InteractiveShellCapability):
    """
    SSH interactive shell capability using paramiko.

    Features:
    - PTY allocation with configurable dimensions
    - Shell command execution with prompt detection
    - Raw byte I/O for interactive prompts
    - Automatic reconnection (optional)
    - Connection health monitoring
    """

    def __init__(self, connection_info: ShellConnectionInfo):
        super().__init__(connection_info)
        self._client: Optional[paramiko.SSHClient] = None
        self._channel: Optional[paramiko.Channel] = None
        self._shell: Optional[paramiko.ChannelFile] = None
        self._stdin: Optional[paramiko.ChannelFile] = None
        self._prompt_pattern: str = r"[$#>]\s*$"  # Default prompt regex
        self._banner: str = ""
        self._encoding: str = "utf-8"

    async def connect(self) -> bool:
        """Establish SSH connection and spawn interactive shell."""
        if self._status != "DISCONNECTED":
            logger.warning("SSHShellCapability.connect() called in state %s", self._status)
            return False

        self._status = "CONNECTING"
        loop = asyncio.get_event_loop()

        try:
            # Create SSH client in thread pool (paramiko is blocking)
            await loop.run_in_executor(None, self._do_connect)
            self._status = "ACTIVE"
            self._connected_at = time.time()
            self._last_activity = time.time()
            logger.info("SSH session %s connected to %s", self._session_id, self.target)
            return True

        except Exception as e:
            self._status = "ERROR"
            logger.error("SSH connection failed for %s: %s", self.target, e)
            await self._cleanup()
            return False

    def _do_connect(self):
        """Blocking SSH connection logic (runs in executor)."""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Prepare connection kwargs
        connect_kwargs = {
            "hostname": self.connection_info.target,
            "port": self.connection_info.port,
            "username": self.connection_info.username,
            "timeout": self.connection_info.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }

        # Authentication
        if self.connection_info.auth_method == "key" and self.connection_info.private_key_path:
            connect_kwargs["key_filename"] = self.connection_info.private_key_path
        elif self.connection_info.auth_method == "password" and self.connection_info.password:
            connect_kwargs["password"] = self.connection_info.password
        elif self.connection_info.auth_method == "none":
            pass  # No auth
        else:
            # Try key first, then password
            if self.connection_info.private_key_path:
                connect_kwargs["key_filename"] = self.connection_info.private_key_path
            if self.connection_info.password:
                connect_kwargs["password"] = self.connection_info.password

        # Connect
        self._client.connect(**connect_kwargs)

        # Open channel with PTY
        self._channel = self._client.invoke_shell(
            term="xterm-256color",
            width=self.connection_info.pty_cols,
            height=self.connection_info.pty_rows,
        )
        self._channel.settimeout(0.1)  # Non-blocking reads

        # Get stdin/stdout for the shell
        self._stdin = self._channel.makefile("wb")
        self._shell = self._channel.makefile("rb")

        # Read initial banner/prompt
        self._banner = self._read_initial_output()
        self._detect_prompt()

    def _read_initial_output(self, timeout: float = 5.0) -> str:
        """Read initial banner and first prompt."""
        output = []
        start = time.time()
        while time.time() - start < timeout:
            try:
                chunk = self._shell.read(4096)
                if chunk:
                    output.append(chunk.decode(self._encoding, errors="replace"))
                    # Check if we see a prompt
                    if re.search(self._prompt_pattern, output[-1]):
                        break
            except (paramiko.SSHException, OSError, UnicodeDecodeError):
                break
            time.sleep(0.05)
        return "".join(output)

    def _detect_prompt(self):
        """Detect shell prompt from banner."""
        # Common prompt patterns
        patterns = [
            r"[\w\-\.]+[@\s][\w\-\.]+[\$\#>]\s*$",  # user@host$ or host#
            r"root@[\w\-\.]+:.*[\$\#>]\s*$",         # root@host:~#
            r"[\w\-\.]+[\$\#>]\s*$",                 # simple host$
            r"[\$\#>]\s*$",                          # bare prompt
        ]
        for pattern in patterns:
            if re.search(pattern, self._banner, re.MULTILINE):
                self._prompt_pattern = pattern
                logger.debug("SSH session %s detected prompt pattern: %s", self._session_id, pattern)
                return
        logger.debug("SSH session %s using default prompt pattern", self._session_id)

    async def disconnect(self) -> bool:
        """Gracefully disconnect SSH session."""
        if self._status in ("DISCONNECTED", "TERMINATED", "TERMINATING"):
            return True

        self._status = "TERMINATING"
        try:
            await asyncio.get_event_loop().run_in_executor(None, self._do_disconnect)
            self._status = "TERMINATED"
            logger.info("SSH session %s disconnected", self._session_id)
            return True
        except Exception as e:
            logger.error("Error disconnecting SSH session %s: %s", self._session_id, e)
            self._status = "TERMINATED"
            return False

    def _do_disconnect(self):
        """Blocking disconnect logic."""
        if self._channel:
            try:
                self._channel.send("exit\n")
                time.sleep(0.2)
            except Exception:
                pass
        self._cleanup()

    def _cleanup(self):
        """Clean up SSH resources."""
        for attr in ["_shell", "_stdin", "_channel"]:
            obj = getattr(self, attr, None)
            if obj:
                try:
                    obj.close()
                except Exception:
                    pass
                setattr(self, attr, None)
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    async def send_command(
        self,
        command: str,
        timeout: float = 30.0,
        expect_prompt: bool = True,
    ) -> ShellCommandResult:
        """Send command and capture output."""
        if not self.is_connected:
            raise RuntimeError(f"SSH session {self._session_id} not connected")

        start_time = time.time()
        loop = asyncio.get_event_loop()

        try:
            result = await loop.run_in_executor(
                None, self._do_send_command, command, timeout, expect_prompt
            )
            duration_ms = (time.time() - start_time) * 1000
            result.duration_ms = duration_ms
            self._update_activity(bytes_sent=len(command), bytes_received=len(result.stdout) + len(result.stderr))
            return result

        except Exception as e:
            logger.error("SSH command failed in session %s: %s", self._session_id, e)
            return ShellCommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration_ms=(time.time() - start_time) * 1000,
                raw_output=str(e),
            )

    def _do_send_command(
        self,
        command: str,
        timeout: float,
        expect_prompt: bool,
    ) -> ShellCommandResult:
        """Blocking command execution."""
        # Send command with newline
        self._stdin.write((command + "\n").encode(self._encoding))
        self._stdin.flush()

        # Read output until prompt or timeout
        output = []
        start = time.time()
        prompt_seen = False

        while time.time() - start < timeout:
            try:
                chunk = self._shell.read(4096)
                if chunk:
                    decoded = chunk.decode(self._encoding, errors="replace")
                    output.append(decoded)
                    if expect_prompt and re.search(self._prompt_pattern, decoded):
                        prompt_seen = True
                        break
                elif not self._channel.active:
                    break
            except (paramiko.SSHException, OSError) as e:
                logger.debug("SSH read error: %s", e)
                break
            except UnicodeDecodeError:
                # Skip undecodable chunks
                pass
            time.sleep(0.01)

        raw_output = "".join(output)
        stdout, stderr = self._split_stdout_stderr(raw_output, command)
        exit_code = self._extract_exit_code(raw_output) if not prompt_seen else 0

        return ShellCommandResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=0,  # Will be updated by caller
            raw_output=raw_output,
        )

    def _split_stdout_stderr(self, raw: str, command: str) -> tuple[str, str]:
        """Heuristically split stdout/stderr from raw output."""
        # Remove the command echo if present
        lines = raw.splitlines()
        if lines and lines[0].strip() == command.strip():
            lines = lines[1:]

        # Remove prompt lines
        cleaned = []
        for line in lines:
            if not re.search(self._prompt_pattern, line):
                cleaned.append(line)

        # For SSH, stderr is typically mixed. We can't cleanly separate
        # without shell cooperation. Return all as stdout for now.
        return "\n".join(cleaned), ""

    def _extract_exit_code(self, raw: str) -> int:
        """Try to extract exit code from output (e.g., echo $?)."""
        # Look for exit code patterns
        patterns = [
            r"exit code[:\s]+(\d+)",
            r"Exit[:\s]+(\d+)",
            r"\$ \?\s*\n\s*(\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    pass
        return 0  # Assume success if we can't determine

    async def send_raw(self, data: bytes) -> int:
        """Send raw bytes to the shell."""
        if not self.is_connected or not self._stdin:
            raise RuntimeError("Not connected")
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._do_send_raw, data)

    def _do_send_raw(self, data: bytes) -> int:
        self._stdin.write(data)
        self._stdin.flush()
        return len(data)

    async def read_output(self, timeout: float = 5.0) -> str:
        """Read available output without sending a command."""
        if not self.is_connected:
            return ""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._do_read_output, timeout)

    def _do_read_output(self, timeout: float) -> str:
        output = []
        start = time.time()
        while time.time() - start < timeout:
            try:
                chunk = self._shell.read(4096)
                if chunk:
                    output.append(chunk.decode(self._encoding, errors="replace"))
                else:
                    break
            except (paramiko.SSHException, OSError):
                break
            time.sleep(0.01)
        return "".join(output)

    async def resize_pty(self, cols: int, rows: int) -> bool:
        """Resize the PTY."""
        if not self.is_connected or not self._channel:
            return False
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, self._channel.resize_pty, cols, rows
            )
            self.connection_info.pty_cols = cols
            self.connection_info.pty_rows = rows
            return True
        except Exception as e:
            logger.error("PTY resize failed: %s", e)
            return False

    def _check_health(self) -> bool:
        """Check if SSH connection is still alive."""
        if not self._channel or not self._client:
            return False
        try:
            return self._channel.active and self._client.get_transport() is not None and self._client.get_transport().is_active()
        except Exception:
            return False

    def get_banner(self) -> str:
        """Return the initial connection banner."""
        return self._banner


# Register with factory
ShellCapabilityFactory.register(ShellCapabilityType.SSH, SSHShellCapability)