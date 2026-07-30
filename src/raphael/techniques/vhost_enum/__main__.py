from __future__ import annotations

import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from raphael.techniques.vhost_enum.types import EnumConfig, EnumMethod, VHOSTTarget
from raphael.techniques.vhost_enum.enumerators import (
    DNSBruteEnumerator,
    CTLogsEnumerator,
    HostFuzzEnumerator,
    SSLSANEnumerator,
)


async def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print("Usage: python -m raphael.techniques.vhost_enum <target_ip> [target_hostname] [--port PORT] [--ssl]")
        print("Example: python -m raphael.techniques.vhost_enum 10.129.41.98 research.bedside.htb --port 80")
        sys.exit(0 if sys.argv[1] in ('-h', '--help') else 1)

    target_ip = sys.argv[1]
    target_hostname = None
    port = 80
    ssl = False
    
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--port' and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif arg == '--ssl':
            ssl = True
            i += 1
        elif not arg.startswith('--') and target_hostname is None:
            target_hostname = arg
            i += 1
        else:
            i += 1

    target = VHOSTTarget(
        ip=target_ip,
        port=port,
        hostname=target_hostname,
        ssl=ssl,
    )

    enum_config = EnumConfig(
        target=target,
        methods=[
            EnumMethod.DNS_BRUTE,
            EnumMethod.CT_LOGS,
            EnumMethod.HOST_FUZZ,
            EnumMethod.SSL_SAN,
        ],
        recursive=True,
        recursive_depth=2,
        threads=10,
        timeout=10,
        rate_limit=50,
    )

    all_discovered = []

    methods = [
        (EnumMethod.DNS_BRUTE, DNSBruteEnumerator),
        (EnumMethod.CT_LOGS, CTLogsEnumerator),
        (EnumMethod.HOST_FUZZ, HostFuzzEnumerator),
        (EnumMethod.SSL_SAN, SSLSANEnumerator),
    ]

    for method, enum_class in methods:
        if method not in enum_config.methods:
            continue
        print(f"Running {method.value}...", file=sys.stderr)
        enum = enum_class(enum_config)
        discovered = await enum.enumerate(target)
        all_discovered.extend(discovered)
        await enum.close()
        print(f"  Found {len(discovered)} hosts", file=sys.stderr)

    seen_hashes = set()
    unique = []
    for h in all_discovered:
        key = (h.host, h.content_hash)
        if key not in seen_hashes:
            seen_hashes.add(key)
            unique.append(h)

    result = {
        "target_ip": target_ip,
        "target_hostname": target_hostname,
        "port": port,
        "ssl": ssl,
        "discovered_count": len(unique),
        "hosts": [
            {
                "host": h.host,
                "ip": h.ip,
                "port": h.port,
                "method": h.method.value,
                "status_code": h.status_code,
                "content_length": h.content_length,
                "content_hash": h.content_hash,
                "confidence": h.confidence,
            }
            for h in unique
        ],
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())