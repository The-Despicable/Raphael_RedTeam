import os
import random
import logging
import ssl
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("egress.strategies")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
]

# IMPORTANT: Replace with your own fronting domain before production use.
# See front_domains.py for details on why real third-party domains are
# not safe to use here.
FRONT_DOMAINS = [
    "your-cdn-fronting-domain-1.example.com",
    "your-cdn-fronting-domain-2.example.com",
]


class EgressStrategy(ABC):
    def __init__(self):
        self.user_agent = random.choice(USER_AGENTS)

    @abstractmethod
    def build_client(self, target_host: str = None) -> dict:
        raise RuntimeError("Not implemented")

    def get_headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }


class DirectStrategy(EgressStrategy):
    def build_client(self, target_host: str = None) -> dict:
        return {
            "proxies": {},
            "verify": True,
            "headers": self.get_headers(),
        }


class TorStrategy(EgressStrategy):
    def __init__(self, tor_host: str = "127.0.0.1", tor_port: int = 9050):
        super().__init__()
        self.proxy_url = f"socks5h://{tor_host}:{tor_port}"

    def build_client(self, target_host: str = None) -> dict:
        return {
            "proxies": {"http": self.proxy_url, "https": self.proxy_url},
            "verify": True,
            "headers": self.get_headers(),
        }


class ProxyChainStrategy(EgressStrategy):
    """Selects a single proxy from a pool (single-hop proxy selection, not true chaining).
       True multi-hop chaining would require sequential proxy tunneling via SOCKS."""

    def __init__(self, proxies: list = None):
        super().__init__()
        self.proxies = proxies or []

    def add_proxy(self, proxy_url: str):
        self.proxies.append(proxy_url)

    def build_client(self, target_host: str = None) -> dict:
        if not self.proxies:
            return DirectStrategy().build_client(target_host)
        proxy = random.choice(self.proxies)
        return {
            "proxies": {"http": proxy, "https": proxy},
            "verify": os.getenv("EGRESS_VERIFY", "false").lower() == "true",
            "headers": self.get_headers(),
        }


class CDNFrontingStrategy(EgressStrategy):
    """CDN fronting via SNI spoofing. Sets the Host header to the front domain
       (matching SNI). The actual target should be routed via the CDN's routing
       rules (path-based or custom header). Note: most major CDNs have patched
       against this technique."""

    def __init__(self, front_domains: list = None, cdn_ip_pool: dict = None):
        super().__init__()
        self.front_domains = front_domains or FRONT_DOMAINS
        self.cdn_ip_pool = cdn_ip_pool or {}

    def build_client(self, target_host: str = None) -> dict:
        front_domain = random.choice(self.front_domains)
        config = {
            "proxies": {},
            "verify": False,
            "headers": self.get_headers(),
            "front_domain": front_domain,
        }
        config["headers"]["Host"] = front_domain
        cdn_ips = self.cdn_ip_pool.get(front_domain)
        if cdn_ips:
            config["cdn_ip"] = random.choice(cdn_ips)
        logger.debug(f"  CDN fronting: SNI/Host={front_domain}, target={target_host or '(direct)'}")
        return config


class TLSWrapperStrategy(EgressStrategy):
    """TLS wrapper with SNI spoofing.

    WARNING: By default, server certificate verification is disabled
    (CERT_NONE). This means the TLS connection provides encryption but
    NOT authentication — an active MITM attacker can intercept traffic.
    Set EGRESS_VERIFY_CERT=true in .env to enable verification if your
    threat model requires it.

    The default SNI hostnames are placeholders. Replace them with your
    own domain before production use. Using real third-party domains
    for SNI spoofing is detectable and potentially illegal."""

    def __init__(self, sni_domains: list = None):
        super().__init__()
        self.sni_domains = sni_domains or [
            "your-sni-fronting-domain-1.example.com",
            "your-sni-fronting-domain-2.example.com",
        ]
        self._verify_cert = os.getenv("EGRESS_VERIFY_CERT", "false").lower() == "true"
        if not self._verify_cert:
            logger.warning(
                "TLSWrapper: certificate verification disabled (CERT_NONE). "
                "Set EGRESS_VERIFY_CERT=true in .env to enable."
            )

    def build_client(self, target_host: str = None) -> dict:
        sni = random.choice(self.sni_domains)
        ctx = ssl.create_default_context()
        if self._verify_cert:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            logger.debug(f"  TLS wrapper: SNI={sni}, cert_verify=OFF")
        return {
            "proxies": {},
            "verify": self._verify_cert,
            "ssl_context": ctx,
            "sni_hostname": sni,
            "headers": self.get_headers(),
        }


STRATEGY_MAP = {
    "direct": DirectStrategy,
    "tor": TorStrategy,
    "proxy_chain": ProxyChainStrategy,
    "cdn_fronting": CDNFrontingStrategy,
    "tls_wrapper": TLSWrapperStrategy,
}


def get_strategy(name: str, **kwargs) -> EgressStrategy:
    cls = STRATEGY_MAP.get(name)
    if not cls:
        raise ValueError(f"Unknown egress strategy: {name}. Available: {list(STRATEGY_MAP.keys())}")
    return cls(**kwargs)
