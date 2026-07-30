FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Recon
    nmap masscan dnsutils whois netcat-openbsd \
    enum4linux smbclient smbmap \
    # Web
    gobuster ffuf dirb nikto wfuzz whatweb wapiti \
    hydra \
    # Exploitation
    sqlmap metasploit-framework \
    # AD / Windows
    impacket-scripts bloodhound.py certipy-ad \
    kerberoast krb5-user \
    # Cracking
    hashcat john \
    # Post-exploitation
    netcat-traditional socat \
    # Utilities
    python3 python3-pip curl wget git jq unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages \
    fastapi uvicorn[standard] httpx \
    pyyaml aiofiles

RUN curl -Lo /tmp/nuclei.zip \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_amd64.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

RUN curl -Lo /usr/local/bin/kerbrute \
    https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 \
    && chmod +x /usr/local/bin/kerbrute

RUN curl -Lo /usr/local/bin/pspy64 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 \
    && chmod +x /usr/local/bin/pspy64

COPY server.py /app/server.py
WORKDIR /app
EXPOSE 3800

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "3800"]
