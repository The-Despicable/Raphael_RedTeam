FROM python:3.11-slim

RUN pip install --no-cache-dir fastapi uvicorn httpx

WORKDIR /app

COPY main.py .

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser

USER 1000:1000

EXPOSE 3300

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3300"]
