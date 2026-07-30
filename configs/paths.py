"""Centralized path configuration for Raphael 2.0."""
from pathlib import Path
import os

# Allow override via environment variable
BASE_DIR = Path(os.environ.get("RAPHAEL_HOME", Path.home() / ".raphael")).resolve()

# Ensure base directories exist
(BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)
(BASE_DIR / "cache").mkdir(parents=True, exist_ok=True)
(BASE_DIR / "data").mkdir(parents=True, exist_ok=True)

def get_base_dir() -> Path:
    """Get the base directory for Raphael 2.0."""
    return BASE_DIR

def get_logs_dir() -> Path:
    return BASE_DIR / "logs"

def get_cache_dir() -> Path:
    return BASE_DIR / "cache"

def get_data_dir() -> Path:
    return BASE_DIR / "data"

def get_tool_registry_path() -> Path:
    return BASE_DIR / "mcp-hub" / "static" / "tool-registry.json"

_scope_cache: dict = {}

def set_scope(scope: dict) -> None:
    """Set operational scope (targets, limits, exclusions)."""
    global _scope_cache
    _scope_cache = scope

# For backward compatibility with existing code
PROJECT_ROOT = Path(__file__).parent.parent
