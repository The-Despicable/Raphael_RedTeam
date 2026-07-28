from __future__ import annotations

import asyncio
import socket
import json
import time
import secrets
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime

from aiohttp import web
import dns.message
import dns.query
import dns.rdatatype

from raphael.verifier.types import (
    ObservationChannel,
    ChannelObservation,
    PreflightRecord,
    generate_canary_token,
)


class BaseChannel(ABC):
    """Base class for observation channels."""

    @abstractmethod
    async def start(self, **kwargs) -> None:
        """Start the channel listener."""
        raise RuntimeError("Not implemented")

    @abstractmethod
    async def stop(self) -> None:
        """Stop the channel listener."""
        raise RuntimeError("Not implemented")

    @abstractmethod
    async def observe(self, preflight: PreflightRecord, timeout: float) -> ChannelObservation:
        """Observe for a result within timeout."""
        raise RuntimeError("Not implemented")


class TCPListenerChannel(BaseChannel):
    """TCP listener for reverse/bind shells."""

    def __init__(self, host: str = "0.0.0.0"):
        self.host = host
        self.port: Optional[int] = None
        self.server: Optional[asyncio.Server] = None
        self.connection_event = asyncio.Event()
        self.connection_data: Dict[str, Any] = {}

    async def start(self, port: int = 0) -> int:
        """Start TCP listener. If port=0, OS assigns ephemeral port."""
        self.port = port
        self.server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )
        if self.port == 0:
            self.port = self.server.sockets[0].getsockname()[1]
        await self.server.start_serving()
        return self.port

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming connection."""
        addr = writer.get_extra_info("peername")
        self.connection_data = {
            "peer": f"{addr[0]}:{addr[1]}",
            "connected_at": time.time(),
        }
        self.connection_event.set()
        writer.close()
        await writer.wait_closed()

    async def stop(self) -> None:
        """Stop TCP listener."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def observe(self, preflight: PreflightRecord, timeout: float) -> ChannelObservation:
        """Wait for incoming connection."""
        start = time.perf_counter()
        try:
            await asyncio.wait_for(self.connection_event.wait(), timeout=timeout)
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.TCP_LISTENER,
                success=True,
                evidence=self.connection_data,
                duration_ms=duration * 1000,
            )
        except asyncio.TimeoutError:
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.TCP_LISTENER,
                success=False,
                evidence={},
                error="timeout",
                duration_ms=duration * 1000,
            )


class HTTPCanaryChannel(BaseChannel):
    """HTTP canary token server for file write verification."""

    def __init__(self, host: str = "0.0.0.0"):
        self.host = host
        self.port: Optional[int] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.hit_event = asyncio.Event()
        self.hit_data: Dict[str, Any] = {}
        self.canary_token: str = ""

    def generate_token(self) -> str:
        """Generate canary token for file embedding."""
        self.canary_token = f"CANARY_{generate_canary_token(24)}"
        return self.canary_token

    async def start(self, port: int = 0) -> int:
        """Start HTTP canary server."""
        self.port = port
        app = web.Application()
        app.router.add_get("/canary/{token}", self._handle_canary)
        app.router.add_post("/canary/{token}", self._handle_canary)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        if self.port == 0:
            self.port = self.site._server.sockets[0].getsockname()[1]
        return self.port

    async def _handle_canary(self, request: web.Request) -> web.Response:
        """Handle canary token hit."""
        token = request.match_info.get("token", "")
        if token and token in self.canary_token:
            self.hit_data = {
                "token": token,
                "method": request.method,
                "headers": dict(request.headers),
                "remote": request.remote,
                "timestamp": time.time(),
            }
            self.hit_event.set()
            return web.Response(text="OK")
        return web.Response(status=404, text="Not found")

    async def stop(self) -> None:
        """Stop HTTP canary server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

    async def observe(self, preflight: PreflightRecord, timeout: float) -> ChannelObservation:
        """Wait for canary token hit."""
        start = time.perf_counter()
        try:
            await asyncio.wait_for(self.hit_event.wait(), timeout=timeout)
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.HTTP_CANARY,
                success=True,
                evidence=self.hit_data,
                duration_ms=duration * 1000,
            )
        except asyncio.TimeoutError:
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.HTTP_CANARY,
                success=False,
                evidence={},
                error="timeout",
                duration_ms=duration * 1000,
            )


class DNSCallbackChannel(BaseChannel):
    """DNS callback listener for blind RCE detection."""

    def __init__(self, host: str = "0.0.0.0"):
        self.host = host
        self.port: Optional[int] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional["_DNSProtocol"] = None
        self.query_event = asyncio.Event()
        self.query_data: Dict[str, Any] = {}
        self.domain: str = ""

    class _DNSProtocol(asyncio.DatagramProtocol):
        def __init__(self, parent: "DNSCallbackChannel"):
            self.parent = parent

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: tuple) -> None:
            try:
                msg = dns.message.from_wire(data)
                for q in msg.question:
                    self.parent.query_data = {
                        "qname": str(q.name),
                        "qtype": dns.rdatatype.to_text(q.rdtype),
                        "remote": f"{addr[0]}:{addr[1]}",
                        "timestamp": time.time(),
                    }
                    self.parent.query_event.set()
            except Exception:
                pass

    async def start(self, port: int = 53) -> int:
        """Start DNS listener."""
        self.port = port
        loop = asyncio.get_event_loop()
        self.protocol = self._DNSProtocol(self)
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self.protocol,
            local_addr=(self.host, self.port),
        )
        if self.port == 0:
            self.port = self.transport.get_extra_info("socket").getsockname()[1]
        return self.port

    def set_domain(self, domain: str) -> None:
        """Set the expected callback domain."""
        self.domain = domain

    async def stop(self) -> None:
        """Stop DNS listener."""
        if self.transport:
            self.transport.close()

    async def observe(self, preflight: PreflightRecord, timeout: float) -> ChannelObservation:
        """Wait for DNS query."""
        start = time.perf_counter()
        try:
            await asyncio.wait_for(self.query_event.wait(), timeout=timeout)
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.DNS_CALLBACK,
                success=True,
                evidence=self.query_data,
                duration_ms=duration * 1000,
            )
        except asyncio.TimeoutError:
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.DNS_CALLBACK,
                success=False,
                evidence={},
                error="timeout",
                duration_ms=duration * 1000,
            )


class ProcessCheckChannel(BaseChannel):
    """Process execution check for command injection verification."""

    def __init__(self, host: str = "0.0.0.0"):
        self.host = host
        self.port: Optional[int] = None
        self.server: Optional[asyncio.Server] = None
        self.check_event = asyncio.Event()
        self.check_data: Dict[str, Any] = {}

    async def start(self, port: int = 0) -> int:
        """Start process check listener."""
        self.port = port
        self.server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )
        if self.port == 0:
            self.port = self.server.sockets[0].getsockname()[1]
        await self.server.start_serving()
        return self.port

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming connection - indicates command execution."""
        addr = writer.get_extra_info("peername")
        data = await reader.read(1024)
        self.check_data = {
            "peer": f"{addr[0]}:{addr[1]}",
            "data": data.decode(errors="ignore") if data else "",
            "connected_at": time.time(),
        }
        self.check_event.set()
        writer.close()
        await writer.wait_closed()

    async def stop(self) -> None:
        """Stop process check listener."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def observe(self, preflight: PreflightRecord, timeout: float) -> ChannelObservation:
        """Wait for process execution callback."""
        start = time.perf_counter()
        try:
            await asyncio.wait_for(self.check_event.wait(), timeout=timeout)
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.PROCESS_CHECK,
                success=True,
                evidence=self.check_data,
                duration_ms=duration * 1000,
            )
        except asyncio.TimeoutError:
            duration = time.perf_counter() - start
            return ChannelObservation(
                channel=ObservationChannel.PROCESS_CHECK,
                success=False,
                evidence={},
                error="timeout",
                duration_ms=duration * 1000,
            )


def create_channel(channel_type: ObservationChannel, **kwargs) -> BaseChannel:
    """Factory function to create channel instances."""
    if channel_type == ObservationChannel.TCP_LISTENER:
        return TCPListenerChannel(**kwargs)
    elif channel_type == ObservationChannel.HTTP_CANARY:
        return HTTPCanaryChannel(**kwargs)
    elif channel_type == ObservationChannel.DNS_CALLBACK:
        return DNSCallbackChannel(**kwargs)
    elif channel_type == ObservationChannel.PROCESS_CHECK:
        return ProcessCheckChannel(**kwargs)
    else:
        raise ValueError(f"Unknown channel type: {channel_type}")