import os
import time
import hashlib
import hmac
from fastapi import Request, HTTPException
from typing import Optional


API_KEYS = {}
KEY_RATE_LIMITS = {}


def load_api_keys(config_path: Optional[str] = None):
    import yaml
    path = config_path or os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
            for key, opts in cfg.get("api_keys", {}).items():
                API_KEYS[key] = opts.get("scopes", ["*"])
                KEY_RATE_LIMITS[key] = opts.get("rate_limit", 60)
    except (FileNotFoundError, yaml.YAMLError):
        pass


def validate_api_key(token: str) -> Optional[dict]:
    if token in API_KEYS:
        return {"key": token, "scopes": API_KEYS[token]}
    return None


class RateLimiter:
    def __init__(self):
        self.windows: dict[str, list[float]] = {}

    def check(self, key: str, limit: int = 60, window: int = 60) -> bool:
        now = time.time()
        if key not in self.windows:
            self.windows[key] = []
        self.windows[key] = [t for t in self.windows[key] if now - t < window]
        if len(self.windows[key]) >= limit:
            return False
        self.windows[key].append(now)
        return True


_rate_limiter = RateLimiter()


async def authenticate(request: Request) -> Optional[dict]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        user = validate_api_key(token)
        if user:
            limit = KEY_RATE_LIMITS.get(token, 60)
            if not _rate_limiter.check(token, limit):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            return user
    raise HTTPException(status_code=401, detail="Invalid or missing API key")
