from __future__ import annotations

import asyncio
import hashlib
import ssl
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import aiodns
except ImportError:
    aiodns = None

from raphael.techniques.vhost_enum.types import (
    EnumConfig,
    EnumMethod,
    DiscoveredHost,
    VHOSTTarget,
    EnumStatus,
)

logger = logging.getLogger(__name__)


class BaseEnumerator(ABC):
    """Base class for VHOST enumerators."""

    def __init__(self, config: EnumConfig):
        self.config = config
        self.target = config.target
        self.discovered: List[DiscoveredHost] = []
        self._session: Optional[aiohttp.ClientSession] = None
        self._dns_resolver: Optional[aiodns.DNSResolver] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None

    @property
    @abstractmethod
    def method(self) -> EnumMethod:
        raise RuntimeError("Not implemented")

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=self.config.threads,
                ssl=self.target.ssl,
                enable_cleanup_closed=True,
            )
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": "Raphael-VHOSTEnum/2.0"},
            )
        return self._session

    async def _get_dns(self) -> aiodns.DNSResolver:
        if self._dns_resolver is None:
            self._dns_resolver = aiodns.DNSResolver()
        return self._dns_resolver

    async def _get_limiter(self) -> asyncio.Semaphore:
        if self._rate_limiter is None:
            self._rate_limiter = asyncio.Semaphore(self.config.rate_limit)
        return self._rate_limiter

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
        if self._dns_resolver:
            self._dns_resolver.cancel()

    def _make_host(self, host: str, method: EnumMethod, status: int,
                   body: bytes, headers: Dict[str, str],
                   ssl_info: Optional[Dict] = None) -> DiscoveredHost:
        return DiscoveredHost(
            host=host,
            ip=self.target.ip,
            port=self.target.port,
            method=method,
            status_code=status,
            content_length=len(body),
            content_hash=hashlib.sha256(body).hexdigest()[:16],
            headers=headers,
            ssl_info=ssl_info,
            technique_id=f"vhost_enum.{method.value}",
            confidence=self._calculate_confidence(status, len(body), headers),
        )

    def _calculate_confidence(self, status: int, length: int, headers: Dict) -> float:
        conf = 0.5
        if 200 <= status < 300:
            conf += 0.3
        elif 300 <= status < 400:
            conf += 0.1
        if length > 100:
            conf += 0.1
        if "server" in headers or "x-powered-by" in headers:
            conf += 0.1
        return min(conf, 1.0)

    @abstractmethod
    async def enumerate(self, target: VHOSTTarget) -> List[DiscoveredHost]:
        raise RuntimeError("Not implemented")


class DNSBruteEnumerator(BaseEnumerator):
    """DNS brute-force subdomain enumeration."""

    @property
    def method(self) -> EnumMethod:
        return EnumMethod.DNS_BRUTE

    async def enumerate(self, target: VHOSTTarget) -> List[DiscoveredHost]:
        wordlist = self._load_wordlist()
        if not wordlist:
            logger.warning("No wordlist for DNS brute force")
            return []

        domain = target.hostname or target.ip
        resolver = await self._get_dns()

        semaphore = await self._get_limiter()

        async def resolve_subdomain(sub: str) -> List[DiscoveredHost]:
            async with semaphore:
                fqdn = f"{sub}.{domain}" if sub else domain
                try:
                    result = await resolver.query(fqdn, "A")
                    hosts = []
                    for r in result:
                        ip = r.host
                        dh = await self._verify_host(fqdn, ip, target.port, target.ssl)
                        if dh:
                            hosts.append(dh)
                    return hosts
                except aiodns.error.DNSError:
                    return []
                except Exception as e:
                    logger.debug(f"DNS query failed for {fqdn}: {e}")
                    return []

        tasks = [resolve_subdomain(w) for w in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                self.discovered.extend(r)

        return self.discovered

    def _load_wordlist(self) -> List[str]:
        if self.config.wordlist_inline:
            return self.config.wordlist_inline
        if self.config.wordlist:
            try:
                with open(self.config.wordlist) as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logger.warning(f"Wordlist not found: {self.config.wordlist}")
        return ["www", "mail", "api", "dev", "test", "staging", "admin", "app", "blog", "shop"]

    async def _verify_host(self, host: str, ip: str, port: int, ssl: bool) -> Optional[DiscoveredHost]:
        protocol = "https" if ssl else "http"
        port_str = f":{port}" if port not in (80, 443) else ""
        url = f"{protocol}://{host}{port_str}/"

        try:
            session = await self._get_session()
            async with session.get(url, allow_redirects=self.config.follow_redirects) as resp:
                body = await resp.read()
                if resp.status < 500:
                    return self._make_host(host, EnumMethod.DNS_BRUTE, resp.status, body, dict(resp.headers))
        except Exception:
            pass
        return None


class CTLogsEnumerator(BaseEnumerator):
    """Certificate Transparency logs enumeration."""

    @property
    def method(self) -> EnumMethod:
        return EnumMethod.CT_LOGS

    async def enumerate(self, target: VHOSTTarget) -> List[DiscoveredHost]:
        domain = target.hostname or target.ip
        if not domain or domain.replace(".", "").isdigit():
            return []

        subdomains = await self._query_ct_logs(domain)
        semaphore = await self._get_limiter()

        async def verify_subdomain(sub: str) -> List[DiscoveredHost]:
            async with semaphore:
                return await self._verify_subdomain(sub, target)

        tasks = [verify_subdomain(s) for s in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                self.discovered.extend(r)

        return self.discovered

    async def _query_ct_logs(self, domain: str) -> Set[str]:
        subdomains = set()
        logs = [
            "https://crt.sh/?q=%.{}&output=json".format(domain),
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names".format(domain),
        ]

        session = await self._get_session()
        for url in logs:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if isinstance(data, list):
                            for entry in data:
                                if "name_value" in entry:
                                    for name in entry["name_value"].split("\n"):
                                        subdomains.add(name.strip().rstrip("."))
                                elif "dns_names" in entry:
                                    for name in entry["dns_names"]:
                                        subdomains.add(name.strip().rstrip("."))
            except Exception as e:
                logger.debug(f"CT log query failed for {url}: {e}")

        return subdomains

    async def _verify_subdomain(self, subdomain: str, target: VHOSTTarget) -> List[DiscoveredHost]:
        hosts = []
        try:
            resolver = await self._get_dns()
            result = await resolver.query(subdomain, "A")
            for r in result:
                dh = await self._verify_host(subdomain, r.host, target.port, target.ssl)
                if dh:
                    hosts.append(dh)
        except Exception:
            pass
        return hosts

    async def _verify_host(self, host: str, ip: str, port: int, ssl: bool) -> Optional[DiscoveredHost]:
        protocol = "https" if ssl else "http"
        port_str = f":{port}" if port not in (80, 443) else ""
        url = f"{protocol}://{host}{port_str}/"

        try:
            session = await self._get_session()
            async with session.get(url, allow_redirects=self.config.follow_redirects) as resp:
                body = await resp.read()
                if resp.status < 500:
                    return self._make_host(host, EnumMethod.CT_LOGS, resp.status, body, dict(resp.headers))
        except Exception:
            pass
        return None


class HostFuzzEnumerator(BaseEnumerator):
    """Host header fuzzing for VHOST discovery."""

    @property
    def method(self) -> EnumMethod:
        return EnumMethod.HOST_FUZZ

    async def enumerate(self, target: VHOSTTarget) -> List[DiscoveredHost]:
        wordlist = self._load_wordlist()
        if not wordlist:
            return []

        base_host = target.hostname or target.ip
        port = target.port
        protocol = "https" if target.ssl else "http"
        port_str = f":{port}" if port not in (80, 443) else ""
        base_url = f"{protocol}://{base_host}{port_str}"

        semaphore = await self._get_limiter()

        async def fuzz_host(host: str) -> Optional[DiscoveredHost]:
            async with semaphore:
                return await self._fuzz_request(base_url, host)

        tasks = [fuzz_host(w) for w in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, DiscoveredHost):
                self.discovered.append(r)

        return self.discovered

    def _load_wordlist(self) -> List[str]:
        if self.config.wordlist_inline:
            return self.config.wordlist_inline
        if self.config.wordlist:
            try:
                with open(self.config.wordlist) as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                pass
        return ["www", "mail", "api", "dev", "test", "staging", "admin", "app", "blog", "shop",
                "internal", "devops", "ci", "cd", "stage", "prod", "production", "uat", "qa"]

    async def _fuzz_request(self, base_url: str, host_header: str) -> Optional[DiscoveredHost]:
        headers = {"Host": host_header}

        try:
            session = await self._get_session()
            async with session.get(base_url, headers=headers, allow_redirects=self.config.follow_redirects) as resp:
                body = await resp.read()
                if resp.status < 500 and len(body) != len(await self._get_baseline()):
                    return self._make_host(host_header, EnumMethod.HOST_FUZZ, resp.status, body, dict(resp.headers))
        except Exception:
            pass
        return None

    async def _get_baseline(self) -> bytes:
        try:
            session = await self._get_session()
            async with session.get(self.target.hostname or self.target.ip) as resp:
                return await resp.read()
        except Exception:
            return b""


class SSLSANEnumerator(BaseEnumerator):
    """SSL SAN (Subject Alternative Name) certificate parsing."""

    @property
    def method(self) -> EnumMethod:
        return EnumMethod.SSL_SAN

    async def enumerate(self, target: VHOSTTarget) -> List[DiscoveredHost]:
        if not target.ssl and target.port != 443:
            return []

        host = target.hostname or target.ip
        port = target.port if target.port != 80 else 443

        san_names = await self._get_san_names(host, port)
        if not san_names:
            return []

        semaphore = await self._get_limiter()

        async def verify_san(name: str) -> Optional[DiscoveredHost]:
            async with semaphore:
                return await self._verify_host(name, target.port, target.ssl)

        tasks = [verify_san(name) for name in san_names if name != host]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, DiscoveredHost):
                self.discovered.append(r)

        return self.discovered

    async def _get_san_names(self, host: str, port: int) -> Set[str]:
        names = set()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.connect((host, port))
                cert = ssock.getpeercert()
                if cert:
                    for ext in cert.get("subjectAltName", []):
                        if ext[0] == "DNS":
                            names.add(ext[1])
        except Exception as e:
            logger.debug(f"SSL SAN extraction failed for {host}:{port}: {e}")

        return names

    async def _verify_host(self, host: str, port: int, ssl: bool) -> Optional[DiscoveredHost]:
        protocol = "https" if ssl else "http"
        port_str = f":{port}" if port not in (80, 443) else ""
        url = f"{protocol}://{host}{port_str}/"

        try:
            session = await self._get_session()
            async with session.get(url, allow_redirects=self.config.follow_redirects) as resp:
                body = await resp.read()
                if resp.status < 500:
                    return self._make_host(host, EnumMethod.SSL_SAN, resp.status, body, dict(resp.headers))
        except Exception:
            pass
        return None


class RecursiveEnumerator(BaseEnumerator):
    """Recursive VHOST discovery using discovered hosts as new bases."""

    @property
    def method(self) -> EnumMethod:
        return EnumMethod.RECURSIVE

    async def enumerate(self, target: VHOSTTarget) -> List[DiscoveredHost]:
        return []


def create_enumerator(method: str, config: EnumConfig) -> BaseEnumerator:
    """Factory to create enumerator instances."""
    method_map = {
        "dns_brute": DNSBruteEnumerator,
        "ct_logs": CTLogsEnumerator,
        "host_fuzz": HostFuzzEnumerator,
        "ssl_san": SSLSANEnumerator,
        "recursive": RecursiveEnumerator,
    }
    cls = method_map.get(method)
    if cls is None:
        raise ValueError(f"Unknown enumerator: {method}")
    return cls(config)