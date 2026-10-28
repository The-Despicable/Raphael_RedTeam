# shellcheck shell=bash
# env.sh — OS-level environment for native (non-Docker) Raphael execution.
#
# Source from any script:  source ./env.sh
# Override any value before sourcing to pin a different layout.
#
# CORE services (must run native, exact ports, deterministic health checks):
#   cai          127.0.0.1:3201  /health -> status: ok
#   cloak        127.0.0.1:3401  /health -> status: ok
#   phishing     127.0.0.1:3502  /health -> status: ok
#   brain        127.0.0.1:3700  /health -> status: ok
#   kali-tools   127.0.0.1:3800  /health -> status: ok
#   raphael-api  127.0.0.1:3900  /health -> status: ok
#
# OPTIONAL services (env-gated, started only when RAPHAEL_ENABLE_<svc>=1):
#   tor, sliver, caido, neo4j, privisy

# ---------------------------------------------------------------- paths
export RAPHAEL_ROOT="${RAPHAEL_ROOT:-/home/yaser/raphael-redteam}"
export RAPHAEL_TOOLS="${RAPHAEL_TOOLS:-/home/yaser/raphael-tools}"
export PYTHONPATH="${RAPHAEL_ROOT}:${RAPHAEL_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

export RAPHAEL_LOG_DIR="${RAPHAEL_LOG_DIR:-/var/log/raphael}"
export RAPHAEL_RUN_DIR="${RAPHAEL_RUN_DIR:-/var/run/raphael}"
mkdir -p "$RAPHAEL_LOG_DIR" "$RAPHAEL_RUN_DIR" 2>/dev/null || sudo mkdir -p "$RAPHAEL_LOG_DIR" "$RAPHAEL_RUN_DIR"

# ---------------------------------------------------------------- tor (optional, env-gated)
export RAPHAEL_ENABLE_TOR="${RAPHAEL_ENABLE_TOR:-0}"
export TORRC_PATH="${TORRC_PATH:-${RAPHAEL_ROOT}/docker/tor/torrc}"
export TOR_BIN="${TOR_BIN:-tor}"
export TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"
export TOR_CONTROL_PORT="${TOR_CONTROL_PORT:-9051}"
# With Docker gone, the raphael-net overlay is DEAD. Tor is consumed natively:
# proxy URL form socks5h:// (DNS through Tor, never local resolve).
export RAPHAEL_PROXY_URL="${RAPHAEL_PROXY_URL:-socks5h://127.0.0.1:9050}"
# Tools that take a proxy flag consume these:
export ALL_PROXY="${ALL_PROXY:-socks5h://127.0.0.1:${TOR_SOCKS_PORT}}"
export http_proxy="${http_proxy:-socks5h://127.0.0.1:${TOR_SOCKS_PORT}}"
export https_proxy="${https_proxy:-socks5h://127.0.0.1:${TOR_SOCKS_PORT}}"

# ---------------------------------------------------------------- core service ports (fixed, deterministic health checks)
export CAI_PORT=3201
export CLOAK_PORT=3401
export PHISHING_PORT=3502
export BRAIN_PORT=3700
export KALI_TOOLS_PORT=3800
export RAPHAEL_API_PORT=3900

# ---------------------------------------------------------------- legacy shim
# Backwards compatibility: existing code that pointed at the compose kali-tools
# container keeps working after compose is deleted. Anything reading
# KALI_TOOLS_URL now hits the native uvicorn service on 3800.
export KALI_TOOLS_URL="${KALI_TOOLS_URL:-http://127.0.0.1:3800}"

# ---------------------------------------------------------------- uvicorn module paths (override per-tree)
export KALI_TOOLS_MODULE="${KALI_TOOLS_MODULE:-server:app}"
export BRAIN_MODULE="${BRAIN_MODULE:-brain.main:app}"
export CAI_MODULE="${CAI_MODULE:-src.cai-service.main:app}"
export CLOAK_MODULE="${CLOAK_MODULE:-src.cloak.main:app}"
export PHISHING_MODULE="${PHISHING_MODULE:-src.phishing.main:app}"
export RAPHAEL_API_MODULE="${RAPHAEL_API_MODULE:-orchestrator.main:app}"

# ---------------------------------------------------------------- optional services (env-gated, default off)
export RAPHAEL_ENABLE_NEO4J="${RAPHAEL_ENABLE_NEO4J:-0}"
export RAPHAEL_ENABLE_CAIDO="${RAPHAEL_ENABLE_CAIDO:-0}"
export RAPHAEL_ENABLE_SLIVER="${RAPHAEL_ENABLE_SLIVER:-0}"
export RAPHAEL_ENABLE_PRIVOXY="${RAPHAEL_ENABLE_PRIVOXY:-0}"

# ---------------------------------------------------------------- LLM / external
export RAPHAEL_LLM_BACKEND="${RAPHAEL_LLM_BACKEND:-none}"
export RAPHAEL_LLM_API_BASE="${RAPHAEL_LLM_API_BASE:-}"
export RAPHAEL_LLM_API_KEY="${RAPHAEL_LLM_API_KEY:-}"
export RAPHAEL_LLM_MODEL="${RAPHAEL_LLM_MODEL:-gpt-4o-mini}"

# ---------------------------------------------------------------- tools manager
export RAPHAEL_TOOLS_MANAGER="${RAPHAEL_TOOLS_MANAGER:-${RAPHAEL_ROOT}/scripts/local_tools_manager.py}"
export HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-3}"
