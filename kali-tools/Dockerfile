FROM python:3.11-slim

# Install packages available in Debian Bookworm repos
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    sqlmap \
    nmap \
    dirb \
    curl \
    wget \
    netcat-openbsd \
    openssh-client \
    hydra \
    unzip \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install tools not in Debian repos via git/other sources
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    git clone --depth 1 https://github.com/urbanadventurer/WhatWeb /opt/whatweb && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    rm -rf /opt/nikto/.git /opt/whatweb/.git

# Install Go-based tools (nuclei, httpx, ffuf, gobuster) from pre-built releases
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei/ && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei 2>/dev/null || echo "nuclei download failed" && \
    curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /tmp/httpx/ && mv /tmp/httpx/httpx /usr/local/bin/httpx 2>/dev/null || echo "httpx download failed" && \
    curl -sL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz -o /tmp/ffuf.tar.gz && \
    tar xzf /tmp/ffuf.tar.gz -C /tmp/ 2>/dev/null; mv /tmp/ffuf /usr/local/bin/ffuf 2>/dev/null || echo "ffuf download failed" && \
    curl -sL https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz -o /tmp/gobuster.tar.gz && \
    tar xzf /tmp/gobuster.tar.gz -C /tmp/ 2>/dev/null; mv /tmp/gobuster /usr/local/bin/gobuster 2>/dev/null || echo "gobuster download failed" && \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx /usr/local/bin/ffuf /usr/local/bin/gobuster 2>/dev/null || true && \
    rm -rf /tmp/nuclei* /tmp/httpx* /tmp/ffuf* /tmp/gobuster*

# Install Python tools
RUN pip3 install --no-cache-dir cmsmap droopescan fastapi uvicorn httpx pydantic

WORKDIR /app
COPY server.py /app/server.py

ENV TOOLS_PORT=3800
ENV PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"

EXPOSE 3800

CMD ["python3", "/app/server.py"]