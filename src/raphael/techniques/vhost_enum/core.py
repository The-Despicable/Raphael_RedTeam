from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from raphael.blackboard import Blackboard
from raphael.eventbus import EventBus
from raphael.techniques.vhost_enum.types import (
    EnumConfig,
    EnumMethod,
    EnumSession,
    EnumStatus,
    DiscoveredHost,
    VHOSTTarget,
)
from raphael.techniques.vhost_enum.enumerators import (
    create_enumerator,
    BaseEnumerator,
)

logger = logging.getLogger(__name__)


class VHOSTEnumTechnique:
    """VHOST Enumeration Technique - discovers virtual hosts on a target."""

    def __init__(self, blackboard: Blackboard, eventbus: EventBus):
        self.blackboard = blackboard
        self.eventbus = eventbus
        self._current_session: Optional[EnumSession] = None
        self._enumerators: Dict[str, 'BaseEnumerator'] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def execute(self, config: EnumConfig) -> EnumSession:
        """
        Execute VHOST enumeration with all configured methods.
        
        Args:
            config: Enumeration configuration
            
        Returns:
            EnumSession with all discovered hosts
        """
        session_id = str(uuid.uuid4())
        session = EnumSession(
            session_id=session_id,
            target=config.target,
            methods=config.methods,
            status=EnumStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        
        self._current_session = session
        self._running = True
        
        for method in config.methods:
            self._enumerators[method.value] = create_enumerator(method.value, config)
        
        logger.info(f"Starting VHOST enumeration session {session_id} for {config.target.ip}")
        
        try:
            all_discovered = []
            
            if EnumMethod.DNS_BRUTE in config.methods:
                enum = self._enumerators.get(EnumMethod.DNS_BRUTE.value)
                if enum:
                    enum.discovered = []
                    await enum.enumerate(config.target)
                    all_discovered.extend(enum.discovered)
            
            if EnumMethod.CT_LOGS in config.methods:
                enum = self._enumerators.get(EnumMethod.CT_LOGS.value)
                if enum:
                    enum.discovered = []
                    await enum.enumerate(config.target)
                    all_discovered.extend(enum.discovered)
            
            if EnumMethod.HOST_FUZZ in config.methods:
                enum = self._enumerators.get(EnumMethod.HOST_FUZZ.value)
                if enum:
                    enum.discovered = []
                    await enum.enumerate(config.target)
                    all_discovered.extend(enum.discovered)
            
            if EnumMethod.SSL_SAN in config.methods:
                enum = self._enumerators.get(EnumMethod.SSL_SAN.value)
                if enum:
                    enum.discovered = []
                    await enum.enumerate(config.target)
                    all_discovered.extend(enum.discovered)
            
            unique = self._deduplicate(all_discovered)
            
            if config.recursive and len(unique) > 0:
                recursive_discovered = await self._recursive_enumerate(unique, config)
                all_discovered.extend(recursive_discovered)
            
            session.discovered = self._deduplicate(all_discovered)
            
            for host in session.discovered:
                await self._publish_discovery(host, config)
            
            session.status = EnumStatus.COMPLETED
            session.completed_at = datetime.now(timezone.utc)
            
            logger.info(f"VHOST enumeration complete: {len(session.discovered)} hosts discovered")
            
        except Exception as e:
            logger.error(f"VHOST enumeration failed: {e}")
            session.status = EnumStatus.FAILED
            session.errors.append(str(e))
            session.completed_at = datetime.now(timezone.utc)
        
        finally:
            self._running = False
        
        return session

    async def _publish_discovery(self, host: 'DiscoveredHost', config: EnumConfig) -> None:
        """Publish a discovered host to the blackboard."""
        try:
            from raphael.blackboard.schemas import ServiceNode
            
            service_node = {
                "host": host.host,
                "port": host.port,
                "service": "https" if host.ssl_info else "http",
                "version": None,
                "vhost": host.host,
                "tech_stack": {
                    "method": host.method.value,
                    "status_code": str(host.status_code),
                    "content_length": str(host.content_length),
                    "content_hash": host.content_hash,
                },
                "headers": host.headers,
                "confidence": host.confidence,
                "discovered_by": host.technique_id,
            }
            
            await self.blackboard.write("service.discovered", service_node)
            
        except Exception as e:
            logger.error(f"Failed to publish discovery for {host.host}: {e}")

    def _deduplicate(self, hosts: List['DiscoveredHost']) -> List['DiscoveredHost']:
        """Remove duplicate hosts based on content hash and hostname."""
        seen_hashes = set()
        seen_hosts = set()
        unique = []
        
        for host in hosts:
            key = (host.host, host.content_hash)
            if key not in seen_hashes and host.host not in seen_hosts:
                seen_hashes.add(host.content_hash)
                seen_hosts.add(host.host)
                unique.append(host)
        
        return unique

    async def _recursive_enumerate(self, initial_hosts: List['DiscoveredHost'], config: EnumConfig) -> List['DiscoveredHost']:
        """Recursively enumerate subdomains of discovered hosts."""
        if config.recursive_depth <= 0:
            return []
        
        discovered = []
        seen = set()
        
        for host in initial_hosts:
            if host.host in seen:
                continue
            seen.add(host.host)
            
            if config.target.hostname and host.host.endswith(config.target.hostname):
                prefix = host.host[:-len(config.target.hostname)-1]
                if prefix and "." not in prefix:
                    new_target = VHOSTTarget(
                        ip=config.target.ip,
                        port=config.target.port,
                        hostname=host.host,
                        ssl=config.target.ssl,
                    )
                    new_config = EnumConfig(
                        target=new_target,
                        methods=[EnumMethod.DNS_BRUTE, EnumMethod.HOST_FUZZ],
                        recursive_depth=config.recursive_depth - 1,
                        wordlist=config.wordlist,
                        wordlist_inline=config.wordlist_inline,
                        threads=config.threads,
                        timeout=config.timeout,
                        recursive=config.recursive,
                        rate_limit=config.rate_limit,
                    )
                    
                    sub_session = await self.execute(new_config)
                    discovered.extend(sub_session.discovered)
        
        return []

    async def stop(self) -> None:
        """Stop any running enumeration."""
        self._running = False
        for enum in self._enumerators.values():
            await enum.close()

    def get_status(self) -> Optional[EnumSession]:
        """Get current session status."""
        return self._current_session