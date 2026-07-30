FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -s /bin/false mcpuser && chown -R mcpuser:mcpuser /app/logs /app/static
USER mcpuser

EXPOSE 8000

CMD ["uvicorn", "main:create_app", "--host", "0.0.0.0", "--port", "8000", "--factory"]
