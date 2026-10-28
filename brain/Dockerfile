# Autonomous Brain — Dockerfile
# Raphael 2.0 offensive-security platform.
#
# Image: python:3.11-slim. Service runs FastAPI on port 3700.
# Optional systems (Tor / Sliver / Neo4j / LLM) degrade gracefully if missing.

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SERVICE_NAME=autonomous-brain \
    PORT=3700 \
    LOG_LEVEL=INFO

# System deps: curl for healthcheck, sqlite3 for debugging, build-essential for
# any C-extension fallbacks (e.g. cryptography wheels).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        sqlite3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for layer caching.
COPY brain/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application code.
COPY brain/ /app/brain/
COPY orchestrator/ /app/orchestrator/

# Ensure the data directory exists (mounted as a volume at runtime).
RUN mkdir -p /data /sliver-config

# Smoke test on build so a broken import fails fast.
RUN python -c "import sys; sys.path.insert(0, '/app'); import brain.main; print('brain import OK')"

EXPOSE 3700

# Healthcheck: hit /health every 30s, timeout 5s, 3 retries.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD curl -fsS http://localhost:3700/health || exit 1

# Run as non-root for defense-in-depth.
RUN useradd -r -u 1000 -g root brain && chown -R brain:root /app /data /sliver-config
USER brain

CMD ["python", "-m", "uvicorn", "brain.main:app", "--host", "0.0.0.0", "--port", "3700", "--workers", "1"]
