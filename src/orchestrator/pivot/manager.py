import os
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("pivot_manager")


@dataclass
class PivotHop:
    session_id: str
    hostname: str
    address: str
    proxy_url: str
    port: int = 1081
    reachable_nets: list[str] = field(default_factory=list)


class PivotManager:
    def __init__(self):
        self._hops: list[PivotHop] = []

    @property
    def chain_length(self) -> int:
        return len(self._hops)

    @property
    def deepest_proxy(self) -> Optional[str]:
        if not self._hops:
            return None
        return self._hops[-1].proxy_url

    def add_hop(self, hop: PivotHop):
        self._hops.append(hop)
        logger.info(f"Pivot: added hop {hop.hostname} ({hop.address}) → {hop.proxy_url}")

    def remove_hop(self, session_id: str):
        self._hops = [h for h in self._hops if h.session_id != session_id]

    def proxies_for_target(self, target: str) -> list[str]:
        urls = []
        for hop in self._hops:
            for net in hop.reachable_nets:
                if self._ip_in_net(target, net):
                    urls.append(hop.proxy_url)
        return urls

    def env_for_target(self, target: str) -> dict:
        proxy = self.deepest_proxy
        if proxy:
            return {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy}
        return {}

    def _ip_in_net(self, ip: str, net: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
        except ValueError:
            return False

    def chain_url(self, depth: int = -1) -> Optional[str]:
        if not self._hops:
            return None
        hops = self._hops[:depth] if depth > 0 else self._hops
        return "/".join(h.proxy_url for h in hops)

    def chain_proxies_dict(self, depth: int = -1) -> dict:
        url = self.chain_url(depth)
        if not url:
            return {}
        return {"http": url, "https": url}

    def auto_route(self, target: str) -> tuple[Optional[str], list[str]]:
        matching = []
        for hop in self._hops:
            for net in hop.reachable_nets:
                if self._ip_in_net(target, net):
                    matching.append(hop)
        if not matching:
            deepest = self.deepest_proxy
            return deepest, [h.proxy_url for h in self._hops]
        chain = "/".join(h.proxy_url for h in matching)
        return chain, [h.proxy_url for h in matching]

    def route_through(self, hop_index: int) -> Optional[str]:
        if hop_index >= len(self._hops):
            return None
        return self._hops[hop_index].proxy_url


_pivot: Optional[PivotManager] = None


def get_pivot() -> PivotManager:
    global _pivot
    if _pivot is None:
        _pivot = PivotManager()
    return _pivot
