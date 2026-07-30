import socket, ipaddress, concurrent.futures, time, shutil, re
from typing import Optional
from ..proxy_guard import ProxyGuard

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "ipsec-isakmp", 514: "syslog", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2222: "directadmin", 2375: "docker", 2376: "docker-ssl",
    2483: "oracle-db", 2484: "oracle-db-ssl", 3128: "squid", 3306: "mysql",
    3389: "ms-wbt-server", 4443: "https-alt", 4848: "glassfish",
    5000: "upnp", 5432: "postgresql", 5555: "freeciv", 5601: "kibana",
    5900: "vnc", 5901: "vnc-1", 5984: "couchdb", 5985: "winrm-http",
    5986: "winrm-https", 6379: "redis", 6443: "https-alt", 7077: "mesos",
    8000: "http-alt", 8001: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8086: "influxdb", 8088: "http-alt", 8089: "http-alt",
    8090: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "sonar",
    9001: "tor-orport", 9042: "cassandra", 9092: "kafka", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
    10000: "webmin", 11211: "memcached", 27017: "mongod", 50070: "hdfs",
}

class NmapScanner:
    def __init__(self, pg: ProxyGuard = None):
        self.pg = pg

    @property
    def available(self) -> bool:
        return True

    def scan_ports(self, target: str, ports: str = "1-1000", rate: int = 100,
                   sudo: bool = False) -> dict:
        self._validate_target(target)

        if self.pg:
            self.pg._enforce_timing()

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {"error": f"Cannot resolve target: {target}", "target": target}

        port_list = self._parse_ports(ports)
        open_ports = self._tcp_connect_scan(target_ip, port_list, rate=rate)

        results = []
        for port in open_ports:
            svc = COMMON_PORTS.get(port, "unknown")
            results.append({"port": port, "protocol": "tcp", "state": "open", "service": svc})

        return {
            "target": target,
            "host_status": "up",
            "ports": results,
            "port_count": len(results),
            "os_guess": None,
        }

    def os_detect(self, target: str, sudo: bool = False) -> dict:
        return {
            "target": target,
            "host_status": "unknown",
            "ports": [],
            "port_count": 0,
            "os_guess": "OS detection requires nmap binary with sudo",
            "note": "Install nmap for proper OS detection",
        }

    def _validate_target(self, target: str):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if not any(c in target for c in [".", ":"]):
                raise ValueError(f"Invalid target: {target}")

    def _parse_ports(self, spec: str) -> list:
        ports = set()
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                for p in range(int(a.strip()), int(b.strip()) + 1):
                    ports.add(p)
            else:
                ports.add(int(part))
        return sorted(ports)

    def _tcp_connect_scan(self, ip: str, ports: list, rate: int = 100) -> list:
        open_ports = []
        max_workers = min(rate, 200)

        def try_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                r = s.connect_ex((ip, port))
                s.close()
                return port if r == 0 else None
            except (socket.timeout, OSError):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for result in ex.map(try_port, ports):
                if result is not None:
                    open_ports.append(result)

        return sorted(open_ports)
