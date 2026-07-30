import socket, concurrent.futures, shutil, subprocess
from typing import Optional

INTRA_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 88: "kerberos",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 389: "ldap",
    443: "https", 445: "smb", 464: "kpasswd", 593: "http-rpc-epmap",
    636: "ldaps", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5985: "winrm-http", 5986: "winrm-https", 6379: "redis", 8443: "https-alt",
    9389: "adws", 49152: "winrm-v5",
}

class LadonScanner:
    def __init__(self):
        self._binary = shutil.which("ladon")

    @property
    def available(self) -> bool:
        return True  # pure Python socket fallback always works

    def scan(self, network: str, ports: list = None, rate: int = 200) -> dict:
        targets = self._expand_network(network)
        if len(targets) > 16:
            return self._fast_scan(network, ports)

        port_list = ports or list(INTRA_PORTS.keys())[:8]
        results = []

        def scan_host(ip):
            host_ports = []
            for p in port_list:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    r = s.connect_ex((ip, p))
                    s.close()
                    if r == 0:
                        host_ports.append({
                            "port": p,
                            "service": INTRA_PORTS.get(p, "unknown"),
                        })
                except (socket.timeout, OSError):
                    pass
            if host_ports:
                return {"ip": ip, "ports": host_ports, "port_count": len(host_ports)}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=rate) as ex:
            for result in ex.map(scan_host, targets, timeout=30):
                if result:
                    results.append(result)

        return {"network": network, "hosts": results, "host_count": len(results)}

    def _expand_network(self, network: str) -> list:
        import ipaddress
        try:
            return [str(ip) for ip in ipaddress.IPv4Network(network, strict=False)]
        except (ValueError, TypeError):
            return [network]

    def _fast_scan(self, network: str, ports: list) -> dict:
        return {
            "network": network,
            "note": "Network too large for inline scan. Install Ladon for full intranet scanning.",
            "alternative": "Use python3 app.py exploit <target> for targeted exploitation",
        }
