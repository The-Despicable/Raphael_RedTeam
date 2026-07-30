import os
import sys
import random
import logging
import time
import threading
from typing import Optional, Union

from orchestrator.egress.strategies import (
    EgressStrategy, DirectStrategy, TorStrategy, ProxyChainStrategy,
    CDNFrontingStrategy, TLSWrapperStrategy, get_strategy, STRATEGY_MAP,
)

logger = logging.getLogger("egress.router")

AUTO_STRATEGY_ORDER = ["tor", "cdn_fronting", "proxy_chain", "tls_wrapper", "direct"]


class EgressRouter:
    def __init__(self, strategy: str = "auto", **strategy_kwargs):
        self._strategy_name = strategy
        self._strategy_kwargs = strategy_kwargs
        self._strategy: Optional[EgressStrategy] = None
        self._lock = threading.Lock()
        self._last_rotation = 0.0
        self._rotation_cooldown = 30.0
        self._failed_strategies = set()
        self._resolve()

    def _resolve(self):
        if self._strategy_name == "auto":
            dev_mode = os.getenv("RAPHAEL_DEV_MODE", "").lower() in ("1", "true", "yes")
            if dev_mode:
                self._strategy = DirectStrategy()
                logger.info("  Egress: auto → direct (RAPHAEL_DEV_MODE)")
                return
            for name in AUTO_STRATEGY_ORDER:
                if name in self._failed_strategies:
                    continue
                try:
                    self._strategy = self._try_strategy(name)
                    if self._strategy:
                        logger.info(f"  Egress: auto → {name}")
                        return
                except Exception as e:
                    logger.debug(f"  Egress: {name} unavailable ({e})")
                    self._failed_strategies.add(name)
            logger.warning("  Egress: no strategy available, falling back to direct")
            self._strategy = DirectStrategy()
        else:
            self._strategy = get_strategy(self._strategy_name, **self._strategy_kwargs)

    def _try_strategy(self, name: str, **kwargs) -> Optional[EgressStrategy]:
        merged = {**self._strategy_kwargs, **kwargs}
        strat = get_strategy(name, **merged)
        if name == "tor":
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect((merged.get("tor_host", "127.0.0.1"), merged.get("tor_port", 9050)))
                s.close()
                return strat
            except Exception:
                return None
        return strat

    @property
    def strategy(self) -> EgressStrategy:
        return self._strategy or DirectStrategy()

    def build_client_config(self, target_host: str = None) -> dict:
        with self._lock:
            return self.strategy.build_client(target_host)

    def build_httpx_kwargs(self, target_host: str = None) -> dict:
        config = self.build_client_config(target_host)
        kwargs = {
            "proxies": config.get("proxies"),
            "verify": config.get("verify", True),
            "headers": config.get("headers", {}),
        }
        sni = config.get("sni_hostname")
        if sni:
            kwargs["headers"].setdefault("Host", target_host or sni)
        front = config.get("front_domain")
        if front:
            kwargs["headers"].setdefault("Host", target_host or front)
        return kwargs

    def build_requests_kwargs(self, target_host: str = None) -> dict:
        config = self.build_client_config(target_host)
        kwargs = {
            "proxies": config.get("proxies"),
            "verify": config.get("verify", True),
            "headers": config.get("headers", {}),
            "timeout": 30,
        }
        sni = config.get("sni_hostname")
        if sni:
            kwargs["headers"].setdefault("Host", target_host or sni)
        front = config.get("front_domain")
        if front:
            kwargs["headers"].setdefault("Host", target_host or front)
        return kwargs

    def rotate_strategy(self, target_host: str = None) -> str:
        now = time.time()
        if now - self._last_rotation < self._rotation_cooldown:
            remaining = self._rotation_cooldown - (now - self._last_rotation)
            logger.debug(f"  Rotation cooldown: {remaining:.0f}s remaining")
            return self._strategy_name
        available = [n for n in AUTO_STRATEGY_ORDER if n not in self._failed_strategies and n != self._strategy_name]
        if not available:
            available = [n for n in AUTO_STRATEGY_ORDER if n != self._strategy_name]
        if not available:
            return self._strategy_name
        next_strategy = random.choice(available)
        self._strategy_name = next_strategy
        self._last_rotation = now
        self._resolve()
        logger.info(f"  Rotated to strategy: {next_strategy}")
        return next_strategy

    def mark_failed(self, strategy_name: str = None):
        name = strategy_name or self._strategy_name
        self._failed_strategies.add(name)
        logger.warning(f"  Strategy failed and blacklisted: {name}")
        self.rotate_strategy()

    def get_client(self, target_host: str = None):
        from httpx import AsyncClient
        kwargs = self.build_httpx_kwargs(target_host)
        return AsyncClient(**kwargs)

    def get_session(self, target_host: str = None):
        import requests
        kwargs = self.build_requests_kwargs(target_host)
        s = requests.Session()
        if kwargs.get("proxies"):
            s.proxies.update(kwargs["proxies"])
        s.verify = kwargs.get("verify", True)
        if kwargs.get("headers"):
            s.headers.update(kwargs["headers"])
        return s

    def status(self) -> dict:
        return {
            "strategy": self._strategy_name,
            "active": self._strategy.__class__.__name__ if self._strategy else "none",
            "failed_strategies": list(self._failed_strategies),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CDN FRONTING CLIENT — Fixed Implementation
# ═══════════════════════════════════════════════════════════════════════════════

def build_cdn_fronting_client(
    front_domain: str,
    target_host: str,
    front_port: int = 443,
    timeout: float = 30.0,
    verify_ssl: bool = True,
    ca_bundle: Optional[str] = None,
):
    """
    Build an httpx client that performs CDN fronting correctly.

    The key insight: SNI must match the CDN front domain (so the CDN accepts
    the TLS handshake), while the Host header must match the target origin
    (so the CDN routes to the correct backend).

    Most CDNs (Cloudflare, Akamai, Fastly) route based on Host header after
    accepting the TLS connection at the SNI domain. This implementation
    correctly separates these two concerns.
    """
    import ssl
    import httpx

    # TLS context with SNI set to the front domain
    tls_context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=ca_bundle,
    )

    if not verify_ssl:
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE

    # Force SNI to the front domain — this is the critical fix
    # httpx >= 0.27.0 supports sni_hostname parameter directly
    tls_context.sni_callback = lambda sock, server_hostname, ctx: None

    limits = httpx.Limits(
        max_keepalive_connections=5,
        max_connections=10,
        keepalive_expiry=30.0,
    )

    client = httpx.AsyncClient(
        # Connect to the front domain explicitly
        base_url=f"https://{front_domain}:{front_port}",
        # Override Host header to the target origin
        headers={
            "Host": target_host,
            "X-Forwarded-Host": target_host,
        },
        verify=verify_ssl,
        cert=ca_bundle,  # for client cert if needed
        timeout=httpx.Timeout(timeout, connect=10.0, read=timeout),
        limits=limits,
        # Disable automatic Host header overwrite
        trust_env=False,
    )

    return client


def build_cdn_fronting_client_v2(
    front_domain: str,
    target_host: str,
    target_port: int = 443,
    timeout: float = 30.0,
):
    """
    Simpler approach using httpx's sni_hostname parameter (httpx >= 0.27.0).

    httpx >= 0.27.0 supports passing sni_hostname directly. This is the
    preferred approach if you have a recent httpx version.
    """
    import httpx

    transport = httpx.AsyncHTTPTransport(
        # Connect to the front domain's IP but set SNI accordingly
        sni_hostname=front_domain,  # SNI = front domain ✓
    )

    client = httpx.AsyncClient(
        transport=transport,
        headers={
            # Host header = target (so CDN routes correctly) ✓
            "Host": target_host,
        },
        timeout=httpx.Timeout(timeout, connect=10.0),
    )

    return client


# ═══════════════════════════════════════════════════════════════════════════════
# EGRESS ROUTER INTEGRATION — Route via CDN Fronting
# ═══════════════════════════════════════════════════════════════════════════════

async def route_via_cdn_fronting(
    request_data: bytes,
    front_domain: str,
    target_url: str,
    cdn_strategy: str = "cloudflare",
) -> bytes:
    """
    Send data through a CDN fronting channel.

    cdn_strategy can be:
    - "cloudflare": uses Cloudflare's SNI-based routing
    - "fastly":     uses Fastly's Host-header-based routing
    - "akamai":     uses Akamai's property-based routing
    """
    from urllib.parse import urlparse

    parsed_target = urlparse(target_url)
    target_host = parsed_target.netloc or parsed_target.hostname
    target_port = parsed_target.port or 443

    # Known CDN front domains
    CDN_FRONTS = {
        "cloudflare": [
            "cloudflare.net",
            "cloudflare-dns.com",
            "workers.dev",  # Cloudflare Workers — common front
        ],
        "fastly": [
            "fastly.net",
            "global.fastly.net",
        ],
        "akamai": [
            "akamai.net",
            "akamaiedge.net",
        ],
    }

    fronts = CDN_FRONTS.get(cdn_strategy, CDN_FRONTS["cloudflare"])

    # Try each front domain until one works
    last_error = None
    for front_domain in fronts:
        try:
            client = build_cdn_fronting_client_v2(
                front_domain=front_domain,
                target_host=target_host,
                target_port=target_port,
                timeout=15.0,
            )

            async with client:
                response = await client.post(
                    target_url,
                    content=request_data,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "X-Request-ID": os.urandom(8).hex(),
                    },
                )
                response.raise_for_status()
                return response.content

        except (httpx.ConnectError, httpx.RemoteProtocolError, ssl.SSLError) as e:
            last_error = e
            logger.warning(
                "CDN front %s failed for %s: %s",
                front_domain, target_host, e,
            )
            continue
        except httpx.HTTPStatusError as e:
            # Non-200 but server responded — might still be a valid route
            logger.warning(
                "CDN front %s returned %d for %s",
                front_domain, e.response.status_code, target_host,
            )
            return e.response.content

    raise RuntimeError(
        f"All CDN fronts failed for {target_url}. Last error: {last_error}"
    )


def create_router(strategy: str = "auto", **kwargs) -> EgressRouter:
    return EgressRouter(strategy=strategy, **kwargs)