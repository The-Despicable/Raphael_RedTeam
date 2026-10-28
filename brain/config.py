"""Configuration for the Autonomous Brain microservice.

Reads environment variables (and an optional `.env` file) with safe defaults.
Never hard-fails on missing optional systems (LLM keys, Neo4j, Sliver, Tor);
those degrade gracefully and surface their state via /health.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration. Pydantic v2 settings model."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Identity / runtime -------------------------------------------------
    service_name: str = Field(default="autonomous-brain", alias="SERVICE_NAME")
    version: str = "2.0.0"
    port: int = Field(default=3700, alias="PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # --- Persistence --------------------------------------------------------
    brain_db: str = Field(default="/data/brain.db", alias="BRAIN_DB")

    # --- Tor ----------------------------------------------------------------
    tor_socks: str = Field(default="tor-proxy:9050", alias="TOR_SOCKS")
    tor_control: str = Field(default="tor-proxy:9051", alias="TOR_CONTROL")
    tor_control_pass: Optional[str] = Field(default=None, alias="TOR_CONTROL_PASS")

    # --- Sliver -------------------------------------------------------------
    sliver_operator_config: Optional[str] = Field(
        default=None, alias="SLIVER_OPERATOR_CONFIG"
    )

    # --- Kali tools ---------------------------------------------------------
    kali_tools_url: str = Field(
        default="http://kali-tools:3800", alias="KALI_TOOLS_URL"
    )

    # --- Neo4j (optional) ---------------------------------------------------
    neo4j_uri: Optional[str] = Field(default=None, alias="NEO4J_URI")
    neo4j_user: Optional[str] = Field(default=None, alias="NEO4J_USER")
    neo4j_pass: Optional[str] = Field(default=None, alias="NEO4J_PASS")

    # --- LLM (OpenAI-compatible) -------------------------------------------
    openai_base_url: str = Field(
        default="https://api.openai.com/v1", alias="OPENAI_BASE_URL"
    )
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    omniroute_api_key: Optional[str] = Field(default=None, alias="OMNIROUTE_API_KEY")
    llm_model: str = Field(default="gpt-4o-mini", alias="LLM_MODEL")
    llm_request_timeout: float = Field(default=60.0, alias="LLM_REQUEST_TIMEOUT")

    # --- Cost control -------------------------------------------------------
    raphael_cost_control: bool = Field(default=True, alias="RAPHAEL_COST_CONTROL")
    max_spend_tokens: int = Field(default=200_000, alias="MAX_SPEND_TOKENS", ge=0)

    # --- Concurrency --------------------------------------------------------
    task_concurrency: int = Field(default=2, alias="TASK_CONCURRENCY", ge=1)

    # --- Gates & limits -----------------------------------------------------
    # How long a step requiring operator approval may block before being skipped.
    approval_timeout_seconds: float = Field(
        default=60.0, alias="APPROVAL_TIMEOUT_SECONDS", ge=1.0
    )
    # Hard cap applied to any per-call tool timeout (protects the coordinator
    # from callers passing huge values via /tools/execute).
    max_tool_timeout: float = Field(default=300.0, alias="MAX_TOOL_TIMEOUT", ge=1.0)

    # --- Security (optional) -----------------------------------------------
    # When set, all endpoints except /health, /version and / require this key
    # in the X-API-Key header. Leave unset for the previous open behaviour.
    brain_api_key: Optional[str] = Field(default=None, alias="BRAIN_API_KEY")

    # --- ML toggle (torch/transformers optional) ---------------------------
    raphael_enable_ml: bool = Field(default=False, alias="RAPHAEL_ENABLE_ML")

    @field_validator("log_level")
    @classmethod
    def _norm_log_level(cls, v: str) -> str:
        return v.upper()

    @field_validator("brain_db")
    @classmethod
    def _norm_brain_db(cls, v: str) -> str:
        # Ensure parent directory exists; create lazily on access.
        p = Path(v).expanduser().resolve()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Fall back to a local data dir so dev/test still works.
            p = Path("/tmp/brain.db")
        return str(p)

    # --- Convenience --------------------------------------------------------
    @property
    def llm_api_key(self) -> Optional[str]:
        """First available LLM API key (OpenAI preferred, OmniRoute fallback)."""
        return self.openai_api_key or self.omniroute_api_key

    @property
    def ml_enabled(self) -> bool:
        return self.raphael_enable_ml

    def health_dict(self) -> dict:
        """Lightweight config snapshot used by /health."""
        return {
            "service": self.service_name,
            "version": self.version,
            "brain_db": self.brain_db,
            "tor_socks": self.tor_socks,
            "sliver_configured": bool(self.sliver_operator_config),
            "kali_tools_url": self.kali_tools_url,
            "neo4j_configured": bool(self.neo4j_uri and self.neo4j_user),
            "llm_configured": bool(self.llm_api_key),
            "llm_base_url": self.openai_base_url,
            "ml_enabled": self.ml_enabled,
            "cost_control": self.raphael_cost_control,
            "max_spend_tokens": self.max_spend_tokens,
            "auth_required": bool(self.brain_api_key),
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton. Tests can call get_settings.cache_clear()."""
    return Settings()


def reload_settings() -> Settings:
    """Force re-read of environment (useful for tests)."""
    get_settings.cache_clear()
    return get_settings()


# Module-level convenience for code paths that don't want to thread settings.
def env_str(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def env_int(key: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (TypeError, ValueError):
        return default


def env_bool(key: str, default: bool = False) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
