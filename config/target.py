"""Target configuration abstraction layer.

Usage:
    from config.target import TargetConfig
    TARGET = TargetConfig.from_env()
    session.get(f"{TARGET.base_url}/admin/login", headers={"Host": TARGET.vhost})
"""
import os
from dataclasses import dataclass


@dataclass
class TargetConfig:
    ip: str = "127.0.0.1"
    port: int = 80
    vhost: str = "localhost"
    scheme: str = "http"
    web_root: str = "/var/www/html"
    session_path: str = "/var/lib/php/sessions"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.ip}:{self.port}"

    @classmethod
    def from_env(cls) -> "TargetConfig":
        return cls(
            ip=os.getenv("TARGET_IP", "127.0.0.1"),
            port=int(os.getenv("TARGET_PORT", "80")),
            vhost=os.getenv("TARGET_VHOST", "localhost"),
            scheme=os.getenv("TARGET_SCHEME", "http"),
            web_root=os.getenv("TARGET_WEB_ROOT", "/var/www/html"),
            session_path=os.getenv("TARGET_SESSION_PATH", "/var/lib/php/sessions"),
        )


_active_target: str | None = None


def set_target(target: str) -> None:
    global _active_target
    _active_target = target
    os.environ["TARGET_IP"] = target
