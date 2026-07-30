FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi uvicorn httpx pywinrm paramiko neo4j sliver-py

COPY main.py .

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser

USER 1000:1000

EXPOSE 3501

CMD ["python", "main.py"]
