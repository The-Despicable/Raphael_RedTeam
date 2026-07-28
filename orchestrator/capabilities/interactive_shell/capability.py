"""capability.py — InteractiveShellCapability interface and base implementation.

Defines the abstract base class for all interactive shell capabilities
(SSH, reverse shell, bind shell, meterpreter) and the data structures
for connection information.
"""

import abc
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("interactive_shell.capability")


class ShellCapabilityType(str, Enum):
    """Supported interactive shell capability types."""
    SSH = "ssh"
    REVERSE_TCP = "reverse_tcp"
    BIND_TCP = "bind_tcp"
    METERPRETER = "meterpreter"


@dataclass
class ShellConnectionInfo:
    """Connection parameters for a shell capability."""
    capability_type: ShellCapabilityType
    target: str                    # Target IP/hostname
    port: int = 22                 # Target port (SSH=22, reverse/bind=varies)
    username: str = ""             # Username for SSH
    password: str = ""             # Password (if auth_method=password)
    private_key_path: str = ""     # Path to SSH private key
    auth_method: str = "password"  # "password", "key", "none"
    lhost: str = ""                # Local host for reverse shell callback
    lport: int = 0                 # Local port for reverse shell callback
    timeout: float = 30.0          # Connection timeout
    pty_cols: int = 120            # PTY width
    pty_rows: int = 40             # PTY height
    env: dict = field(default_factory=dict)  # Environment variables
    metadata: dict = field(default_factory=dict)  # Arbitrary metadata


@dataclass
class ShellCommandResult:
    """Result of a command execution."""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    raw_output: str = ""           # Raw TTY output (before normalization)
    timestamp: float = field(default_factory=time.time)


class InteractiveShellCapability(abc.ABC):
    """
    Abstract base class for interactive shell capabilities.

    All shell capabilities must implement this interface. The CapabilityBroker
    interacts with shells exclusively through this interface — no direct
    socket/PTY access is permitted outside this abstraction.

    State machine:
        DISCONNECTED -> CONNECTING -> ACTIVE -> (IDLE) -> TERMINATING -> TERMINATED
                                    \-> ERROR

    Thread safety: Implementations should be thread-safe for concurrent
    send_command/read_output calls, or document their concurrency model.
    """

    def __init__(self, connection_info: ShellConnectionInfo):
        self.connection_info = connection_info
        self._session_id: str = f"shell_{uuid.uuid4().hex[:12]}"
        self._status: str = "DISCONNECTED"
        self._connected_at: float = 0.0
        self._last_activity: float = 0.0
        self._command_count: int = 0
        self._bytes_sent: int = 0
        self._bytes_received: int = 0

    # ── Properties ────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def capability_type(self) -> ShellCapabilityType:
        return self.connection_info.capability_type

    @property
    def target(self) -> str:
        return self.connection_info.target

    @property
    def status(self) -> str:
        return self._status

    @property
    def is_connected(self) -> bool:
        return self._status in ("ACTIVE", "IDLE")

    @property
    def is_alive(self) -> bool:
        """Check if connection is still responsive."""
        return self.is_connected and self._check_health()

    @property
    def connected_at(self) -> float:
        return self._connected_at

    @property
    def last_activity(self) -> float:
        return self._last_activity

    @property
    def idle_seconds(self) -> float:
        if self._last_activity == 0:
            return 0.0
        return time.time() - self._last_activity

    @property
    def command_count(self) -> int:
        return self._command_count

    @property
    def bytes_sent(self) -> int:
        return self._bytes_sent

    @property
    def bytes_received(self) -> int:
        return self._bytes_received

    # ── Abstract Methods ──────────────────────────────────────────

    @abc.abstractmethod
    async def connect(self) -> bool:
        """
        Establish the shell connection.

        Returns:
            True if connection successful, False otherwise.

        Side effects:
            - Sets _status to "CONNECTING" then "ACTIVE" on success
            - Sets _connected_at timestamp
            - Raises exception on unrecoverable error (caller should catch)
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def disconnect(self) -> bool:
        """
        Gracefully terminate the shell session.

        Returns:
            True if clean disconnect, False if forced.

        Side effects:
            - Sets _status to "TERMINATING" then "TERMINATED"
            - Closes underlying transport
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def send_command(
        self,
        command: str,
        timeout: float = 30.0,
        expect_prompt: bool = True,
    ) -> ShellCommandResult:
        """
        Send a command and wait for output.

        Args:
            command: Command string to execute
            timeout: Maximum time to wait for output
            expect_prompt: Whether to wait for shell prompt before returning

        Returns:
            ShellCommandResult with stdout, stderr, exit_code, and timing
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def send_raw(self, data: bytes) -> int:
        """
        Send raw bytes to the shell (for interactive prompts, Ctrl-C, etc.).

        Args:
            data: Raw bytes to send

        Returns:
            Number of bytes sent
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def read_output(self, timeout: float = 5.0) -> str:
        """
        Read available output without sending a command.

        Args:
            timeout: Maximum time to wait for output

        Returns:
            Raw output string (may include ANSI escape sequences)
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def resize_pty(self, cols: int, rows: int) -> bool:
        """
        Resize the pseudo-terminal.

        Args:
            cols: Terminal width in columns
            rows: Terminal height in rows

        Returns:
            True if resize successful
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _check_health(self) -> bool:
        """
        Internal health check — called by is_alive property.

        Returns:
            True if connection appears healthy
        """
        raise NotImplementedError

    # ── Helper Methods ────────────────────────────────────────────

    def _update_activity(self, bytes_sent: int = 0, bytes_received: int = 0):
        """Update activity tracking."""
        self._last_activity = time.time()
        self._command_count += 1
        self._bytes_sent += bytes_sent
        self._bytes_received += bytes_received

    def get_stats(self) -> dict:
        """Return session statistics."""
        return {
            "session_id": self._session_id,
            "capability_type": self.capability_type.value,
            "target": self.target,
            "status": self._status,
            "connected_at": self._connected_at,
            "last_activity": self._last_activity,
            "idle_seconds": self.idle_seconds,
            "command_count": self._command_count,
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
        }


class ShellCapabilityFactory:
    """Factory for creating shell capability instances."""

    _registry: dict[ShellCapabilityType, type] = {}

    @classmethod
    def register(cls, capability_type: ShellCapabilityType, impl_class: type):
        """Register a capability implementation."""
        cls._registry[capability_type] = impl_class
        logger.info("Registered shell capability: %s -> %s", capability_type.value, impl_class.__name__)

    @classmethod
    def create(cls, connection_info: ShellConnectionInfo) -> InteractiveShellCapability:
        """Create a capability instance for the given connection info."""
        impl_class = cls._registry.get(connection_info.capability_type)
        if not impl_class:
            raise ValueError(f"No implementation registered for {connection_info.capability_type.value}")
        return impl_class(connection_info)

    @classmethod
    def get_supported_types(cls) -> list[ShellCapabilityType]:
        return list(cls._registry.keys())