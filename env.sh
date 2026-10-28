# shellcheck shell=bash
# env.sh — environment for native (non-Docker) Raphael execution.
#
# Ports are NOT defined here. configs/services.json is the single source of
# truth; scripts/gen_env.py turns it into exports. Adding a port literal to this
# file is a build failure (scripts/check_consistency.py rule 3).
#
#   source ./env.sh
#
# Core services (see configs/services.json for the authoritative values):
#   cai · cloak · phishing · brain · kali-tools · raphael-api · c2 · recon · sword · mhddos
# Optional, gated by RAPHAEL_ENABLE_<SVC>=1: tor, sliver, caido, privoxy, neo4j

# ---------------------------------------------------------------- paths
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REPO_ROOT

export RAPHAEL_ROOT="${RAPHAEL_ROOT:-$REPO_ROOT}"
export RAPHAEL_TOOLS="${RAPHAEL_TOOLS:-/home/yaser/raphael-tools}"

# Derived: RAPHAEL_PY, PYTHONPATH, <SERVICE>_PORT, KALI_TOOLS_URL
if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
    export RAPHAEL_PY="${RAPHAEL_PY:-$REPO_ROOT/.venv/bin/python}"
else
    export RAPHAEL_PY="${RAPHAEL_PY:-python3}"
fi
eval "$("$RAPHAEL_PY" "$REPO_ROOT/scripts/gen_env.py" --shell)"

# ---------------------------------------------------------------- runtime dirs
# Repo-local by default: no sudo, no /var permissions, nothing to chown.
export RAPHAEL_LOG_DIR="${RAPHAEL_LOG_DIR:-$REPO_ROOT/runtime/logs}"
export RAPHAEL_RUN_DIR="${RAPHAEL_RUN_DIR:-$REPO_ROOT/runtime/pid}"
mkdir -p "$RAPHAEL_LOG_DIR" "$RAPHAEL_RUN_DIR"

# ---------------------------------------------------------------- tor (optional)
export RAPHAEL_ENABLE_TOR="${RAPHAEL_ENABLE_TOR:-0}"
export TORRC_PATH="${TORRC_PATH:-$REPO_ROOT/docker/tor/torrc}"
export TOR_BIN="${TOR_BIN:-tor}"
export TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-${TOR_PORT}}"
export TOR_CONTROL_PORT="${TOR_CONTROL_PORT:-${TOR_ALT_PORT}}"
# Docker is gone: there is no raphael-net. Tor is consumed over loopback.
# NOTE: do NOT export http_proxy/https_proxy/ALL_PROXY here. httpx, requests and
# curl honour them implicitly, which would route local health probes through
# Tor and make every service look Down. Egress is opt-in per call:
#   httpx.AsyncClient(proxy="$RAPHAEL_PROXY_URL")  /  curl --proxy ...
export RAPHAEL_PROXY_URL="${RAPHAEL_PROXY_URL:-socks5h://127.0.0.1:${TOR_PORT}}"

# ---------------------------------------------------------------- optional services
export RAPHAEL_ENABLE_NEO4J="${RAPHAEL_ENABLE_NEO4J:-0}"
export RAPHAEL_ENABLE_CAIDO="${RAPHAEL_ENABLE_CAIDO:-0}"
export RAPHAEL_ENABLE_SLIVER="${RAPHAEL_ENABLE_SLIVER:-0}"
export RAPHAEL_ENABLE_PRIVOXY="${RAPHAEL_ENABLE_PRIVOXY:-0}"

# ---------------------------------------------------------------- LLM / external
export RAPHAEL_LLM_BACKEND="${RAPHAEL_LLM_BACKEND:-none}"
export RAPHAEL_LLM_API_BASE="${RAPHAEL_LLM_API_BASE:-}"
export RAPHAEL_LLM_API_KEY="${RAPHAEL_LLM_API_KEY:-}"
export RAPHAEL_LLM_MODEL="${RAPHAEL_LLM_MODEL:-gpt-4o-mini}"

# ---------------------------------------------------------------- tools
export RAPHAEL_TOOLS_MANAGER="${RAPHAEL_TOOLS_MANAGER:-$REPO_ROOT/scripts/local_tools_manager.py}"
export HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-3}"

# ---------------------------------------------------------------- anti-forensics
# Dry-run unless both this and the explicit confirm token are supplied.
export RAPHAEL_AF_EXECUTE="${RAPHAEL_AF_EXECUTE:-0}"
