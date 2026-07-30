FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY schema.sql .
COPY case_store.py .
COPY case_api.py .
COPY stale_recovery.py .
COPY __init__.py .
COPY producers/ ./producers/

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser

USER 1000:1000

EXPOSE 3503

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3503"]
