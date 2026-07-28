"""
Cloud API Abuse Module (P2 - FORGE Phase 2)

Exploitation of cloud provider APIs and services.
Provides cloud enumeration, IAM pathfinding, metadata service abuse,
and API gateway exploitation for AWS, GCP, and Azure.

Modules:
- cloud_enum: Cloud provider and service enumeration
- iam_pathfinder: IAM role analysis and privilege escalation pathfinding
- metadata_abuse: Cloud metadata service (IMDS) abuse
- api_gateway_exploit: Cloud API gateway exploitation
"""

from .cloud_enum import CloudEnumerator, CloudProvider, ServiceInfo
from .iam_pathfinder import IAMPathfinder, IAMRole, PolicyDocument
from .metadata_abuse import MetadataAbuser, IMDSResponse
from .api_gateway_exploit import APIGatewayExploiter, GatewayEndpoint

__all__ = [
    "CloudEnumerator", "CloudProvider", "ServiceInfo",
    "IAMPathfinder", "IAMRole", "PolicyDocument",
    "MetadataAbuser", "IMDSResponse",
    "APIGatewayExploiter", "GatewayEndpoint",
]

__version__ = "0.1.0"
