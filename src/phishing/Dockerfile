FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
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

COPY main.py .

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser

USER 1000:1000

EXPOSE 3502

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3502"]
