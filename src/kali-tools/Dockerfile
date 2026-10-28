# Incremental layer on top of the existing kali-tools image.
FROM raphael/kali-tools:latest

# GAP-006: ship a Python 3.11 runtime (Pupy needs <=3.11) + Pupy C2.
# The base Kali image only provides Python 3.13, which breaks Pupy deps.
RUN curl -sL https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.11.18%2B20261026-x86_64-unknown-linux-gnu-install_only.tar.gz -o /tmp/py311.tgz && \
    mkdir -p /opt/python3.11 && tar xzf /tmp/py311.tgz -C /opt/python3.11 --strip-components=1 && rm -f /tmp/py311.tgz

RUN /opt/python3.11/bin/python3 -m pip install --no-cache-dir 'git+https://github.com/n1nj4sec/pupy@nextgen' --no-deps && \
    /opt/python3.11/bin/python3 -m pip install --no-cache-dir netaddr xattr rsa pyaes pycryptodome hexdump 'tinyec @ https://github.com/alxchk/tinyec/archive/master.zip' pyelftools && \
    rm -rf /opt/http-parser-src && git clone --depth 1 https://github.com/benoitc/http-parser /opt/http-parser-src && \
    cp -r /opt/http-parser-src/http_parser /opt/python3.11/lib/python3.11/site-packages/ && \
    ln -sf /opt/python3.11/bin/pupysh /usr/local/bin/pupy && \
    chmod +x /usr/local/bin/pupy /opt/python3.11/bin/pupysh

# Ensure BloodHound Python ingestor is present (no-op if already installed).
RUN /usr/bin/python3 -m pip install --no-cache-dir --break-system-packages bloodhound >/dev/null 2>&1 || true
