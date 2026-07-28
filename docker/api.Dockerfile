FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --default-timeout=300 -r /tmp/requirements.txt

COPY ./orchestrator /raphael/orchestrator
COPY ./cli /raphael/cli

ENV PYTHONPATH=/raphael:/raphael/orchestrator
ENV CI_API_PORT=3900
ENV RAPHAEL_API_KEY=""

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /home/appuser appuser && \
    mkdir -p /home/appuser /data && \
    chown -R appuser:appuser /home/appuser /raphael /data

USER 1000:1000

EXPOSE 3900

CMD ["python", "-m", "orchestrator.api.main"]
