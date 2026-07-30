"""
Cloud Service Enumeration (P2 - FORGE Phase 2)

Enumerates cloud provider services and resources across AWS, GCP, and Azure.
Detects accessible services, open ports, storage buckets, databases,
and compute resources.

FORGE Rule 3 (import map): boto3, google-cloud, azure imports guarded.
FORGE Rule 4 (subprocess): no subprocess calls.
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
from pathlib import Path

logger = logging.getLogger(__name__)

# Guarded imports
_HAS_BOTO3 = True
_HAS_GOOGLE = True
_HAS_AZURE = True

try:
    import boto3
except ImportError:
    _HAS_BOTO3 = False

try:
    from google.cloud import storage as gcs
except ImportError:
    _HAS_GOOGLE = False

try:
    from azure.storage.blob import BlobServiceClient
except ImportError:
    _HAS_AZURE = False


class CloudProvider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    UNKNOWN = "unknown"


class ServiceType(Enum):
    STORAGE = "storage"
    COMPUTE = "compute"
    DATABASE = "database"
    NETWORKING = "networking"
    IDENTITY = "identity"
    CONTAINER = "container"
    ML = "machine_learning"
    DNS = "dns"
    CDN = "cdn"
    EMAIL = "email"
    MONITORING = "monitoring"
    SECRETS = "secrets"
    UNKNOWN = "unknown"


@dataclass
class ServiceInfo:
    """Information about a discovered cloud service."""
    provider: CloudProvider
    service_type: ServiceType
    name: str
    endpoint: str = ""
    region: str = ""
    accessible: bool = False
    requires_auth: bool = True
    public: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider.value,
            "service_type": self.service_type.value,
            "name": self.name,
            "endpoint": self.endpoint,
            "region": self.region,
            "accessible": self.accessible,
            "requires_auth": self.requires_auth,
            "public": self.public,
            "details": self.details,
        }


@dataclass
class CloudEnumResult:
    """Result of cloud enumeration."""
    services: list[ServiceInfo] = field(default_factory=list)
    accessible_services: list[ServiceInfo] = field(default_factory=list)
    public_resources: list[ServiceInfo] = field(default_factory=list)
    credentials_found: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "total_services": len(self.services),
            "accessible": len(self.accessible_services),
            "public_resources": len(self.public_resources),
            "credentials_found": self.credentials_found,
            "services": [s.to_dict() for s in self.services],
            "summary": self.summary,
        }


class CloudEnumerator:
    """Enumerates cloud provider services and resources.

    Uses available credentials (env vars, metadata) to discover accessible
    services. Falls back to anonymous/public access checks when no creds.
    """

    # Well-known endpoints for public cloud service discovery
    PUBLIC_ENDPOINTS: dict[CloudProvider, list[dict]] = {
        CloudProvider.AWS: [
            {"endpoint": "https://s3.amazonaws.com", "service": "S3", "type": ServiceType.STORAGE},
            {"endpoint": "https://ec2.amazonaws.com", "service": "EC2", "type": ServiceType.COMPUTE},
            {"endpoint": "https://lambda.amazonaws.com", "service": "Lambda", "type": ServiceType.COMPUTE},
            {"endpoint": "https://iam.amazonaws.com", "service": "IAM", "type": ServiceType.IDENTITY},
            {"endpoint": "https://sts.amazonaws.com", "service": "STS", "type": ServiceType.IDENTITY},
        ],
        CloudProvider.GCP: [
            {"endpoint": "https://storage.googleapis.com", "service": "Cloud Storage", "type": ServiceType.STORAGE},
            {"endpoint": "https://compute.googleapis.com", "service": "Compute Engine", "type": ServiceType.COMPUTE},
            {"endpoint": "https://iam.googleapis.com", "service": "IAM", "type": ServiceType.IDENTITY},
            {"endpoint": "https://cloudresourcemanager.googleapis.com", "service": "Cloud Resource Manager", "type": ServiceType.IDENTITY},
        ],
        CloudProvider.AZURE: [
            {"endpoint": "https://management.azure.com", "service": "Azure Resource Manager", "type": ServiceType.IDENTITY},
            {"endpoint": "https://login.microsoftonline.com", "service": "Azure AD", "type": ServiceType.IDENTITY},
            {"endpoint": "https://graph.microsoft.com", "service": "Microsoft Graph", "type": ServiceType.IDENTITY},
        ],
    }

    # Common public cloud storage bucket patterns
    STORAGE_PATTERNS = {
        CloudProvider.AWS: r"^[a-z0-9.-]{3,63}\.s3\.amazonaws\.com$",
        CloudProvider.GCP: r"^[a-z0-9._-]{3,63}\.storage\.googleapis\.com$",
        CloudProvider.AZURE: r"^[a-z0-9]{3,24}\.blob\.core\.windows\.net$",
    }

    def __init__(self):
        self._session_id = datetime.utcnow().isoformat()
        self._credentials_cache: dict[str, bool] = {}

    def enumerate_all(self) -> CloudEnumResult:
        """Enumerate all cloud services using available credentials."""
        result = CloudEnumResult()

        # Check for cloud credentials in environment
        creds = self._detect_credentials()
        result.credentials_found = creds

        # Enumerate each provider
        for provider in CloudProvider:
            if provider == CloudProvider.UNKNOWN:
                continue
            services = self.enumerate_provider(provider)
            result.services.extend(services)
            result.accessible_services.extend([s for s in services if s.accessible])
            result.public_resources.extend([s for s in services if s.public])

        # Check public endpoints
        public_services = self._check_public_endpoints()
        for s in public_services:
            if s not in result.services:
                result.services.append(s)
                if s.public:
                    result.public_resources.append(s)

        result.summary = (
            f"Enumerated {len(result.services)} services "
            f"({len(result.accessible_services)} accessible, "
            f"{len(result.public_resources)} public)"
        )
        return result

    def enumerate_provider(self, provider: CloudProvider) -> list[ServiceInfo]:
        """Enumerate services for a specific cloud provider."""
        handlers = {
            CloudProvider.AWS: self._enumerate_aws,
            CloudProvider.GCP: self._enumerate_gcp,
            CloudProvider.AZURE: self._enumerate_azure,
        }
        handler = handlers.get(provider)
        if handler:
            return handler()
        return []

    def _detect_credentials(self) -> list[str]:
        """Detect available cloud credentials from environment."""
        creds = []

        # AWS
        if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
            creds.append("AWS")
        if os.path.exists(os.path.expanduser("~/.aws/credentials")):
            creds.append("AWS_credentials_file")

        # GCP
        if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            creds.append("GCP")
        if os.path.exists(os.path.expanduser("~/.config/gcloud/application_default_credentials.json")):
            creds.append("GCP_ADC")

        # Azure
        if os.environ.get("AZURE_CLIENT_ID") or os.environ.get("AZURE_TENANT_ID"):
            creds.append("Azure")
        if os.path.exists(os.path.expanduser("~/.azure/azureProfile.json")):
            creds.append("Azure_profile")

        return creds

    def _enumerate_aws(self) -> list[ServiceInfo]:
        """Enumerate AWS services using boto3."""
        services = []
        if not _HAS_BOTO3:
            logger.warning("boto3 not available — AWS enumeration limited")
            # Fallback: check public endpoints
            for ep in self.PUBLIC_ENDPOINTS[CloudProvider.AWS]:
                accessible = self._check_endpoint_accessible(ep["endpoint"])
                services.append(ServiceInfo(
                    provider=CloudProvider.AWS,
                    service_type=ep["type"],
                    name=ep["service"],
                    endpoint=ep["endpoint"],
                    accessible=accessible,
                    requires_auth=True,
                    public=accessible,
                ))
            return services

        try:
            # Try to get caller identity
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity.get("Account", "unknown")

            services.append(ServiceInfo(
                provider=CloudProvider.AWS,
                service_type=ServiceType.IDENTITY,
                name="STS Caller Identity",
                endpoint=f"arn:aws:iam::{account_id}:user/current",
                accessible=True,
                requires_auth=True,
                details={"account_id": account_id, "arn": identity.get("Arn", "")},
            ))

            # List S3 buckets
            try:
                s3 = boto3.client("s3")
                response = s3.list_buckets()
                for bucket in response.get("Buckets", []):
                    services.append(ServiceInfo(
                        provider=CloudProvider.AWS,
                        service_type=ServiceType.STORAGE,
                        name=f"S3 Bucket: {bucket['Name']}",
                        endpoint=f"https://{bucket['Name']}.s3.amazonaws.com",
                        accessible=True,
                        requires_auth=True,
                        details={"created": str(bucket.get("CreationDate", "")), "name": bucket["Name"]},
                    ))
            except Exception:
                logger.debug("S3 list failed (no permissions)")

            # List IAM roles
            try:
                iam = boto3.client("iam")
                roles = iam.list_roles(MaxItems=20)
                for role in roles.get("Roles", []):
                    services.append(ServiceInfo(
                        provider=CloudProvider.AWS,
                        service_type=ServiceType.IDENTITY,
                        name=f"IAM Role: {role['RoleName']}",
                        accessible=True,
                        requires_auth=True,
                        details={"role_name": role["RoleName"], "arn": role.get("Arn", "")},
                    ))
            except Exception:
                logger.debug("IAM list roles failed (no permissions)")

            # List Lambda functions
            try:
                lam = boto3.client("lambda")
                functions = lam.list_functions(MaxItems=20)
                for fn in functions.get("Functions", []):
                    services.append(ServiceInfo(
                        provider=CloudProvider.AWS,
                        service_type=ServiceType.COMPUTE,
                        name=f"Lambda: {fn['FunctionName']}",
                        accessible=True,
                        requires_auth=True,
                        details={"function_name": fn["FunctionName"], "runtime": fn.get("Runtime", "")},
                    ))
            except Exception:
                logger.debug("Lambda list failed (no permissions)")

        except Exception as e:
            logger.warning(f"AWS enumeration failed: {e}")

        return services

    def _enumerate_gcp(self) -> list[ServiceInfo]:
        """Enumerate GCP services."""
        services = []

        if not _HAS_GOOGLE:
            logger.warning("google-cloud not available — GCP enumeration limited")
            for ep in self.PUBLIC_ENDPOINTS[CloudProvider.GCP]:
                accessible = self._check_endpoint_accessible(ep["endpoint"])
                services.append(ServiceInfo(
                    provider=CloudProvider.GCP,
                    service_type=ep["type"],
                    name=ep["service"],
                    endpoint=ep["endpoint"],
                    accessible=accessible,
                    requires_auth=True,
                    public=accessible,
                ))
            return services

        try:
            # Try to list GCS buckets
            client = gcs.Client()
            buckets = list(client.list_buckets())
            for bucket in buckets:
                services.append(ServiceInfo(
                    provider=CloudProvider.GCP,
                    service_type=ServiceType.STORAGE,
                    name=f"GCS Bucket: {bucket.name}",
                    endpoint=f"https://{bucket.name}.storage.googleapis.com",
                    accessible=True,
                    requires_auth=True,
                    details={"name": bucket.name, "created": str(bucket.time_created) if bucket.time_created else ""},
                ))
        except Exception as e:
            logger.debug(f"GCP enumeration failed: {e}")

        return services

    def _enumerate_azure(self) -> list[ServiceInfo]:
        """Enumerate Azure services."""
        services = []

        if not _HAS_AZURE:
            logger.warning("azure SDK not available — Azure enumeration limited")
            for ep in self.PUBLIC_ENDPOINTS[CloudProvider.AZURE]:
                accessible = self._check_endpoint_accessible(ep["endpoint"])
                services.append(ServiceInfo(
                    provider=CloudProvider.AZURE,
                    service_type=ep["type"],
                    name=ep["service"],
                    endpoint=ep["endpoint"],
                    accessible=accessible,
                    requires_auth=True,
                    public=accessible,
                ))
            return services

        try:
            # Check Azure storage with connection string from env
            conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
            if conn_str:
                client = BlobServiceClient.from_connection_string(conn_str)
                # List containers
                containers = client.list_containers()
                for container in containers:
                    services.append(ServiceInfo(
                        provider=CloudProvider.AZURE,
                        service_type=ServiceType.STORAGE,
                        name=f"Blob Container: {container.name}",
                        endpoint=f"https://{container.name}.blob.core.windows.net",
                        accessible=True,
                        requires_auth=True,
                        details={"name": container.name},
                    ))
        except Exception as e:
            logger.debug(f"Azure enumeration failed: {e}")

        return services

    def _check_public_endpoints(self) -> list[ServiceInfo]:
        """Check public cloud service endpoints for accessibility."""
        services = []
        for provider, endpoints in self.PUBLIC_ENDPOINTS.items():
            for ep in endpoints:
                accessible = self._check_endpoint_accessible(ep["endpoint"])
                services.append(ServiceInfo(
                    provider=provider,
                    service_type=ep["type"],
                    name=ep["service"],
                    endpoint=ep["endpoint"],
                    accessible=accessible,
                    requires_auth=True,
                    public=accessible,
                    details={"check_type": "public_endpoint"},
                ))
        return services

    def _check_endpoint_accessible(self, url: str) -> bool:
        """Check if a cloud endpoint is reachable."""
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            try:
                # Fallback: try DNS resolution
                host = url.split("/")[2] if "//" in url else url.split("/")[0]
                socket.getaddrinfo(host, 443)
                return True
            except (socket.gaierror, OSError):
                return False

    def check_bucket_public_access(self, bucket_name: str, provider: CloudProvider) -> ServiceInfo:
        """Check if a cloud storage bucket is publicly accessible."""
        endpoints = {
            CloudProvider.AWS: f"https://{bucket_name}.s3.amazonaws.com",
            CloudProvider.GCP: f"https://{bucket_name}.storage.googleapis.com",
            CloudProvider.AZURE: f"https://{bucket_name}.blob.core.windows.net",
        }
        url = endpoints.get(provider)
        if not url:
            raise ValueError(f"Unknown provider: {provider}")

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                public = resp.status == 200
                return ServiceInfo(
                    provider=provider,
                    service_type=ServiceType.STORAGE,
                    name=f"Bucket: {bucket_name}",
                    endpoint=url,
                    accessible=True,
                    requires_auth=False,
                    public=public,
                    details={"status_code": resp.status, "public": public},
                )
        except urllib.error.HTTPError as e:
            return ServiceInfo(
                provider=provider,
                service_type=ServiceType.STORAGE,
                name=f"Bucket: {bucket_name}",
                endpoint=url,
                accessible=False,
                requires_auth=e.code in (401, 403),
                public=False,
                details={"status_code": e.code},
            )
        except Exception as e:
            return ServiceInfo(
                provider=provider,
                service_type=ServiceType.STORAGE,
                name=f"Bucket: {bucket_name}",
                endpoint=url,
                accessible=False,
                requires_auth=True,
                public=False,
                details={"error": str(e)},
            )

    def summary(self) -> dict:
        return {
            "enumerator": "CloudEnumerator",
            "version": "0.1.0",
            "providers": [p.value for p in CloudProvider if p != CloudProvider.UNKNOWN],
            "has_boto3": _HAS_BOTO3,
            "has_google_cloud": _HAS_GOOGLE,
            "has_azure_sdk": _HAS_AZURE,
        }


def enumerate_cloud() -> dict:
    """Convenience function to enumerate all cloud services."""
    enumerator = CloudEnumerator()
    result = enumerator.enumerate_all()
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    enumerator = CloudEnumerator()

    if cmd == "all":
        result = enumerator.enumerate_all()
        print(json.dumps(result.to_dict(), indent=2, default=str))
    elif cmd == "provider" and len(sys.argv) > 2:
        provider = CloudProvider(sys.argv[2])
        services = enumerator.enumerate_provider(provider)
        print(json.dumps([s.to_dict() for s in services], indent=2, default=str))
    elif cmd == "check-bucket" and len(sys.argv) > 3:
        result = enumerator.check_bucket_public_access(sys.argv[2], CloudProvider(sys.argv[3]))
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        print("Usage:")
        print("  python cloud_enum.py all")
        print("  python cloud_enum.py provider aws|gcp|azure")
        print("  python cloud_enum.py check-bucket <name> aws|gcp|azure")
