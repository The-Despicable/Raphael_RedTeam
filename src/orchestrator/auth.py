"""API key authentication with scope-based access control."""
import hashlib
import os
import secrets
import time
from fastapi import Header, HTTPException
from typing import Optional

API_KEYS: dict[str, dict] = {}

SCOPES = {
    "admin": [
        "engagements:rw", "engagements:r",
        "agents:rw", "agents:r",
        "findings:rw", "findings:r",
        "config:rw", "config:r",
        "logs:rw", "logs:r",
        "agent:execute", "agent:read",
        "tools:read", "tools:execute",
        "sessions:rw", "sessions:r",
    ],
    "operator": [
        "engagements:rw", "engagements:r",
        "agents:r",
        "findings:rw",
        "config:r",
        "agent:execute", "agent:read",
        "tools:read", "tools:execute",
        "sessions:rw", "sessions:r",
    ],
    "viewer": [
        "engagements:r",
        "findings:r",
        "agent:read",
        "tools:read",
        "sessions:r",
    ],
    "agent": [
        "agents:rw",
        "findings:w",
        "agent:execute",
    ],
}


# Whitelist of scopes allowed to be appended via env var extra scopes
EXTRA_SCOPE_WHITELIST = {
    "engagements:rw", "engagements:r",
    "agents:rw", "agents:r",
    "findings:rw", "findings:r",
    "config:rw", "config:r",
    "logs:rw", "logs:r",
    "agent:execute", "agent:read",
    "tools:read", "tools:execute",
    "sessions:rw", "sessions:r",
}


def load_keys():
    """Load API keys from environment variables.
    
    Expected format:
        RAPHAEL_KEY_<name>=<role>[,<extra_scope>...]|<api_key>
    
    Example:
        RAPHAEL_KEY_admin=admin,agent:execute|my-secret-key-here
    """
    for var, val in os.environ.items():
        if var.startswith("RAPHAEL_KEY_"):
            try:
                parts = val.split("|", 1)
                if len(parts) != 2:
                    continue
                scopes_str, key = parts
                kh = hashlib.sha256(key.encode()).hexdigest()
                scope_list = scopes_str.split(",")
                role = scope_list[0] if scope_list[0] in SCOPES else "viewer"
                resolved_scopes = list(SCOPES.get(role, []))
                for s in scope_list[1:]:
                    if s in EXTRA_SCOPE_WHITELIST:
                        resolved_scopes.append(s)
                API_KEYS[kh] = {
                    "name": var,
                    "scopes": list(set(resolved_scopes)),
                    "created": time.time(),
                }
            except Exception:
                continue

    legacy_key = os.getenv("API_KEY", "")
    if legacy_key:
        kh = hashlib.sha256(legacy_key.encode()).hexdigest()
        if kh not in API_KEYS:
            API_KEYS[kh] = {
                "name": "API_KEY_legacy",
                "scopes": SCOPES.get("admin", []),
                "created": time.time(),
            }


def require_scope(*scopes: str):
    """FastAPI dependency that requires the given scopes."""
    async def dependency(authorization: Optional[str] = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
        key = authorization[7:]
        kh = hashlib.sha256(key.encode()).hexdigest()
        if kh not in API_KEYS:
            raise HTTPException(status_code=401, detail="Unknown API key")
        entry = API_KEYS[kh]
        for needed in scopes:
            if needed not in entry["scopes"]:
                raise HTTPException(status_code=403, detail=f"Scope '{needed}' required")
        return entry
    return dependency


def generate_key(role: str = "operator") -> tuple[str, str]:
    """Generate a new API key for a given role. Returns (raw_key, formatted_string)."""
    key = secrets.token_hex(32)
    kh = hashlib.sha256(key.encode()).hexdigest()
    API_KEYS[kh] = {
        "name": f"key_{role}_{int(time.time())}",
        "scopes": SCOPES.get(role, SCOPES["viewer"]),
        "created": time.time(),
    }
    return key, f"{role}|{','.join(API_KEYS[kh]['scopes'])}|{key}"
