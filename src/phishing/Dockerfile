FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates golang-go git build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx pydantic aiosmtplib beautifulsoup4

RUN mkdir -p /app/templates

# GoPhish binary for campaign management
RUN curl -Lo /tmp/gophish.zip \
    https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip \
    && unzip -o /tmp/gophish.zip -d /opt/gophish \
    && chmod +x /opt/gophish/gophish \
    && rm /tmp/gophish.zip

# EvilGinx2 MITM phishing proxy
RUN git clone --depth 1 https://github.com/kgretzky/evilginx2 /tmp/evilginx2 \
    && cd /tmp/evilginx2 && make && \
    cp /tmp/evilginx2/build/evilginx /usr/local/bin/evilginx2 \
    && chmod +x /usr/local/bin/evilginx2 \
    && ln -sf /usr/local/bin/evilginx2 /usr/local/bin/evilginx \
    && rm -rf /tmp/evilginx2

COPY main.py .
COPY entrypoint.sh /app/entrypoint.sh

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser

RUN chown -R 1000:1000 /opt/gophish && chmod +x /app/entrypoint.sh

USER 1000:1000

EXPOSE 3502

ENTRYPOINT ["/app/entrypoint.sh"]
CMD []
