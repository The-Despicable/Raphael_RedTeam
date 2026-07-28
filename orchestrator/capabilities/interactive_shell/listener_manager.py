"""listener_manager.py — Broker-exclusive reverse shell listener provisioning.

The CapabilityBroker is the ONLY component that can create listeners.
This enforces the egress control invariant: reverse shells only connect
to authorized LHOST/LPORT combinations provisioned by the Broker.
"""

import asyncio
import logging
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("listener_manager")


@dataclass
class ListenerConfig:
    """Configuration for a reverse shell listener."""
    lhost: str
    lport: int
    protocol: str = "tcp"          # "tcp" or "tls"
    cert_path: str = ""            # TLS certificate (required if protocol=tls)
    key_path: str = ""             # TLS private key (required if protocol=tls)
    allowed_callback_cidrs: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"
    ])
    callback_timeout: float = 60.0
    max_connections: int = 1       # Usually 1 for reverse shells
    session_id: str = ""           # Associated session ID


@dataclass
class ActiveListener:
    """Active listener with metadata."""
    config: ListenerConfig
    socket: socket.socket
    ssl_context: Optional[ssl.SSLContext] = None
    created_at: float = field(default_factory=time.time)
    connections_accepted: int = 0
    last_callback_at: float = 0.0


class ListenerManager:
    """
    Manages reverse shell listeners exclusively for the CapabilityBroker.

    Key invariants:
    - Only Broker can call create_listener() / destroy_listener()
    - Listeners only bind to authorized LHOST/LPORT ranges
    - Each listener is tied to a specific session_id
    - Automatic cleanup on session termination
    - TLS support for encrypted callbacks
    """

    def __init__(
        self,
        allowed_lhost_cidrs: List[str] = None,
        allowed_lport_range: tuple = (4444, 4544),
    ):
        """
        Args:
            allowed_lhost_cidrs: CIDR ranges allowed for LHOST binding
            allowed_lport_range: (min_port, max_port) for LPORT allocation
        """
        self.allowed_lhost_cidrs = allowed_lhost_cidrs or [
            "127.0.0.1/32",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
        self.allowed_lport_range = allowed_lport_range
        self._listeners: Dict[int, ActiveListener] = {}  # lport -> ActiveListener
        self._port_to_session: Dict[int, str] = {}
        self._session_to_port: Dict[str, int] = {}
        self._allocated_ports: Set[int] = set()

    def validate_lhost(self, lhost: str) -> bool:
        """Check if LHOST is in allowed CIDR ranges."""
        import ipaddress
        try:
            addr = ipaddress.ip_address(lhost)
            for cidr in self.allowed_lhost_cidrs:
                if addr in ipaddress.ip_network(cidr):
                    return True
        except Exception:
            pass
        return False

    def validate_lport(self, lport: int) -> bool:
        """Check if LPORT is in allowed range."""
        min_port, max_port = self.allowed_lport_range
        return min_port <= lport <= max_port

    def allocate_port(self, preferred_port: int = 0) -> int:
        """Allocate an available port in the allowed range."""
        min_port, max_port = self.allowed_lport_range

        if preferred_port and self.validate_lport(preferred_port):
            if preferred_port not in self._allocated_ports:
                # Check if port is actually available
                if self._is_port_available(preferred_port):
                    self._allocated_ports.add(preferred_port)
                    return preferred_port

        # Auto-allocate
        for port in range(min_port, max_port + 1):
            if port not in self._allocated_ports and self._is_port_available(port):
                self._allocated_ports.add(port)
                return port

        raise RuntimeError(f"No available ports in range {min_port}-{max_port}")

    def _is_port_available(self, port: int) -> bool:
        """Check if a port is available for binding."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return True
        except OSError:
            return False

    async def create_listener(
        self,
        session_id: str,
        lhost: str,
        lport: int = 0,
        protocol: str = "tcp",
        cert_path: str = "",
        key_path: str = "",
        allowed_callback_cidrs: List[str] = None,
        callback_timeout: float = 60.0,
    ) -> ListenerConfig:
        """
        Create and start a reverse shell listener.

        This is called by CapabilityBroker.authorize_shell_session()
        for reverse_tcp capability types.

        Returns:
            ListenerConfig with the actual bound lhost/lport
        """
        # Validate
        if not self.validate_lhost(lhost):
            raise ValueError(f"LHOST {lhost} not in allowed CIDR ranges")

        # Allocate port if not specified
        if lport == 0:
            lport = self.allocate_port()
        elif not self.validate_lport(lport):
            raise ValueError(f"LPORT {lport} not in allowed range {self.allowed_lport_range}")
        elif lport in self._allocated_ports:
            raise ValueError(f"Port {lport} already allocated")
        elif not self._is_port_available(lport):
            raise ValueError(f"Port {lport} not available")

        # Validate TLS config
        if protocol == "tls":
            if not cert_path or not key_path:
                raise ValueError("TLS requires cert_path and key_path")
            import os
            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                raise ValueError("Certificate or key file not found")

        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind
        try:
            sock.bind((lhost, lport))
        except OSError as e:
            self._allocated_ports.discard(lport)
            raise RuntimeError(f"Failed to bind {lhost}:{lport}: {e}")

        sock.listen(5)
        sock.setblocking(False)

        # Create SSL context if TLS
        ssl_context = None
        if protocol == "tls":
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(cert_path, key_path)
            # Require client cert? No - we just want encryption
            ssl_context.verify_mode = ssl.CERT_NONE

        # Track listener
        config = ListenerConfig(
            lhost=lhost,
            lport=lport,
            protocol=protocol,
            cert_path=cert_path,
            key_path=key_path,
            allowed_callback_cidrs=allowed_callback_cidrs or self.allowed_lhost_cidrs,
            callback_timeout=callback_timeout,
            session_id=session_id,
        )

        active = ActiveListener(
            config=config,
            socket=sock,
            ssl_context=ssl_context,
        )

        self._listeners[lport] = active
        self._port_to_session[lport] = session_id
        self._session_to_port[session_id] = lport

        logger.info(
            "Listener created for session %s: %s:%d (%s)",
            session_id, lhost, lport, protocol
        )

        return config

    def get_listener(self, lport: int) -> Optional[socket.socket]:
        """Get raw socket for a listener (used by ReverseShellCapability)."""
        active = self._listeners.get(lport)
        return active.socket if active else None

    def get_listener_config(self, lport: int) -> Optional[ListenerConfig]:
        """Get listener configuration."""
        active = self._listeners.get(lport)
        return active.config if active else None

    def get_listener_for_session(self, session_id: str) -> Optional[ActiveListener]:
        """Get active listener for a session."""
        lport = self._session_to_port.get(session_id)
        if lport:
            return self._listeners.get(lport)
        return None

    async def destroy_listener(self, session_id: str) -> bool:
        """Destroy listener associated with a session."""
        lport = self._session_to_port.pop(session_id, None)
        if lport is None:
            logger.warning("No listener found for session %s", session_id)
            return False

        active = self._listeners.pop(lport, None)
        self._port_to_session.pop(lport, None)
        self._allocated_ports.discard(lport)

        if active:
            try:
                active.socket.close()
            except Exception as e:
                logger.error("Error closing listener socket: %s", e)

            logger.info("Listener destroyed for session %s (port %d)", session_id, lport)
            return True

        return False

    async def destroy_listener_by_port(self, lport: int) -> bool:
        """Destroy listener by port."""
        active = self._listeners.get(lport)
        if not active:
            return False

        session_id = active.config.session_id
        return await self.destroy_listener(session_id)

    def get_all_listeners(self) -> List[ListenerConfig]:
        """Get all active listener configs."""
        return [active.config for active in self._listeners.values()]

    def get_listener_stats(self, lport: int) -> Optional[Dict]:
        """Get listener statistics."""
        active = self._listeners.get(lport)
        if not active:
            return None

        return {
            "lport": active.config.lport,
            "lhost": active.config.lhost,
            "protocol": active.config.protocol,
            "session_id": active.config.session_id,
            "created_at": active.created_at,
            "uptime_seconds": time.time() - active.created_at,
            "connections_accepted": active.connections_accepted,
            "last_callback_at": active.last_callback_at,
        }

    def record_callback(self, lport: int, client_addr: tuple):
        """Record a callback connection."""
        active = self._listeners.get(lport)
        if active:
            active.connections_accepted += 1
            active.last_callback_at = time.time()

    async def cleanup_expired(self, max_age_seconds: float = 3600):
        """Clean up listeners older than max_age (orphaned sessions)."""
        now = time.time()
        expired = [
            lport for lport, active in self._listeners.items()
            if now - active.created_at > max_age_seconds
        ]

        for lport in expired:
            session_id = self._port_to_session.get(lport)
            if session_id:
                logger.warning("Cleaning up expired listener for session %s (port %d)", session_id, lport)
                await self.destroy_listener(session_id)

    async def shutdown_all(self):
        """Shutdown all listeners (graceful shutdown)."""
        ports = list(self._listeners.keys())
        for lport in ports:
            await self.destroy_listener_by_port(lport)

        logger.info("All listeners shut down")


# ── Global instance ───────────────────────────────────────────────

_listener_manager: Optional[ListenerManager] = None


def get_listener_manager() -> ListenerManager:
    """Get or create global listener manager."""
    global _listener_manager
    if _listener_manager is None:
        _listener_manager = ListenerManager()
    return _listener_manager


def set_listener_manager(manager: ListenerManager):
    """Set global listener manager (for testing)."""
    global _listener_manager
    _listener_manager = manager