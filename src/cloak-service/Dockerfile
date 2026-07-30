FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
    && rm -rf /var/lib/apt/lists/*

ENV CLOAKBROWSER_CACHE_DIR=/app/.cloakbrowser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -m cloakbrowser install

COPY main.py .

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /app appuser && \
    chown -R appuser:appuser /app

USER 1000:1000

CMD uvicorn main:app --host 0.0.0.0 --port 3400
