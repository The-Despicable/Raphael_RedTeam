"""ProxyGuard — Tor proxy lifecycle and circuit management."""

import logging
import random
import time
import requests
from typing import Optional


logger = logging.getLogger("proxy_guard")


class ProxyError(Exception):
    pass


class ProxyGuard:
    TOR_PROXY = "socks5h://127.0.0.1:9050"
    TOR_CONTROL = ("127.0.0.1", 9051)
    TOR_PASSWORD = ""

    def __init__(self):
        self._session: Optional[requests.Session] = None
        self._last_request = 0.0
        self._min_delay = 0.5
        self._circuit_id: Optional[str] = None
        self._init_session()

    def _init_session(self):
        self._session = requests.Session()
        self._session.verify = False
        self._session.proxies = {
            "http": self.TOR_PROXY,
            "https": self.TOR_PROXY,
        }
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        })

    def verify(self):
        try:
            r = self._session.get("https://check.torproject.org/api/ip", timeout=10)
            if r.status_code != 200:
                raise ProxyError(f"Proxy check failed: HTTP {r.status_code}")
            data = r.json()
            if not data.get("IsTor", False):
                raise ProxyError("Not routed through Tor")
            self._circuit_id = data.get("IP", "unknown")
            logger.info(f"ProxyGuard verified — circuit: {self._circuit_id}")
        except requests.RequestException as e:
            raise ProxyError(f"Proxy unreachable: {e}")

    def new_circuit(self, target_ip: Optional[str] = None) -> str:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(self.TOR_CONTROL)
            if self.TOR_PASSWORD:
                s.sendall(f"AUTHENTICATE \"{self.TOR_PASSWORD}\"\r\n".encode())
            else:
                s.sendall(b"AUTHENTICATE\r\n")
            resp = s.recv(1024)
            if b"250" not in resp:
                raise ProxyError(f"Tor auth failed: {resp.decode().strip()}")
            s.sendall(b"SIGNAL NEWNYM\r\n")
            resp = s.recv(1024)
            s.close()
            if b"250" not in resp:
                raise ProxyError(f"NEWNYM failed: {resp.decode().strip()}")
            self._circuit_id = f"circuit-{random.randint(10000, 99999)}"
            logger.info(f"New Tor circuit: {self._circuit_id}")
            time.sleep(2)
            return self._circuit_id
        except socket.error as e:
            raise ProxyError(f"Tor control socket failed: {e}")

    def _enforce_timing(self):
        elapsed = time.time() - self._last_request
        if elapsed < self._min_delay:
            time.sleep(self._min_delay - elapsed)
        self._last_request = time.time()

    def abort(self):
        if self._session:
            self._session.close()
            self._session = None
        logger.info("ProxyGuard session aborted")
