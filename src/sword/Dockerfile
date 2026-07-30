FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./sword/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./sword ./sword
COPY ./orchestrator /raphael/orchestrator

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser

USER 1000:1000

EXPOSE 3600

CMD ["uvicorn", "sword.api:app", "--host", "0.0.0.0", "--port", "3600"]
