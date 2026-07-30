"""
IAM Pathfinder (P2 - FORGE Phase 2)

Analyzes IAM configurations to identify privilege escalation paths
across AWS, GCP, and Azure. Maps roles, policies, and trust relationships
to find attack chains from low-privilege to admin access.

FORGE Rule 3 (import map): boto3 import guarded.
FORGE Rule 4 (subprocess): no subprocess calls.
"""

from __future__ import annotations

import os
import re
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)

_HAS_BOTO3 = True
try:
    import boto3
except ImportError:
    _HAS_BOTO3 = False


class CloudProvider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class EscalationTechnique(Enum):
    """Known IAM privilege escalation techniques."""
    CREATE_USER_KEYS = "create_user_keys"
    CREATE_NEW_USER = "create_new_user"
    UPDATE_ASSUME_ROLE_POLICY = "update_assume_role_policy"
    CREATE_NEW_ROLE = "create_new_role"
    PASS_ROLE_TO_SERVICE = "pass_role_to_service"
    LAMBDA_INVOKE_WITH_ROLE = "lambda_invoke_with_role"
    EC2_ASSUME_ROLE = "ec2_assume_role"
    ATTACH_USER_POLICY = "attach_user_policy"
    ATTACH_ROLE_POLICY = "attach_role_policy"
    CREATE_POLICY_VERSION = "create_policy_version"
    SET_DEFAULT_POLICY_VERSION = "set_default_policy_version"
    IMPERSONATE_SERVICE_ACCOUNT = "impersonate_service_account"
    PRIVILEGED_ACCESS_GROUP = "privileged_access_group"
    CUSTOM_ROLE_CREATION = "custom_role_creation"
    UNKNOWN = "unknown"


# Known AWS IAM privilege escalation paths
KNOWN_ESCALATION_PATHS: dict[str, dict] = {
    "CreateUserKeys": {
        "technique": EscalationTechnique.CREATE_USER_KEYS,
        "required_permissions": ["iam:CreateAccessKey"],
        "target": "any IAM user",
        "description": "Create access keys for any existing IAM user to gain their privileges",
        "risk": "CRITICAL",
    },
    "CreateNewUser": {
        "technique": EscalationTechnique.CREATE_NEW_USER,
        "required_permissions": ["iam:CreateUser", "iam:PutUserPolicy"],
        "target": "new user with admin policy",
        "description": "Create a new IAM user with an attached administrator policy",
        "risk": "CRITICAL",
    },
    "UpdateAssumeRolePolicy": {
        "technique": EscalationTechnique.UPDATE_ASSUME_ROLE_POLICY,
        "required_permissions": ["iam:UpdateAssumeRolePolicy"],
        "target": "any IAM role",
        "description": "Modify a role's trust policy to allow sts:AssumeRole from your user",
        "risk": "CRITICAL",
    },
    "CreateNewRole": {
        "technique": EscalationTechnique.CREATE_NEW_ROLE,
        "required_permissions": ["iam:CreateRole", "iam:PutRolePolicy"],
        "target": "new admin role",
        "description": "Create a new role with admin privileges that your user can assume",
        "risk": "CRITICAL",
    },
    "PassRole": {
        "technique": EscalationTechnique.PASS_ROLE_TO_SERVICE,
        "required_permissions": ["iam:PassRole", "ec2:RunInstances"],
        "target": "EC2 instance with role",
        "description": "Pass an existing role to a new EC2 instance and access its instance metadata",
        "risk": "CRITICAL",
    },
    "LambdaInvokeWithRole": {
        "technique": EscalationTechnique.LAMBDA_INVOKE_WITH_ROLE,
        "required_permissions": ["iam:PassRole", "lambda:CreateFunction"],
        "target": "Lambda with role",
        "description": "Create a Lambda function with an existing role, invoke it to execute with the role's permissions",
        "risk": "CRITICAL",
    },
    "AttachUserPolicy": {
        "technique": EscalationTechnique.ATTACH_USER_POLICY,
        "required_permissions": ["iam:AttachUserPolicy"],
        "target": "any IAM user",
        "description": "Attach an existing administrator policy to a user you control",
        "risk": "HIGH",
    },
    "CreatePolicyVersion": {
        "technique": EscalationTechnique.CREATE_POLICY_VERSION,
        "required_permissions": ["iam:CreatePolicyVersion"],
        "target": "any IAM policy",
        "description": "Create a new version of an existing policy with admin permissions",
        "risk": "CRITICAL",
    },
    "SetDefaultPolicyVersion": {
        "technique": EscalationTechnique.SET_DEFAULT_POLICY_VERSION,
        "required_permissions": ["iam:SetDefaultPolicyVersion"],
        "target": "any IAM policy",
        "description": "Set a non-default version of an existing policy as the default",
        "risk": "CRITICAL",
    },
}


@dataclass
class PolicyDocument:
    """An IAM policy document."""
    effect: str = "Allow"  # Allow | Deny
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    conditions: dict = field(default_factory=dict)
    raw: str = ""

    @classmethod
    def from_aws_policy(cls, statements: list[dict]) -> list["PolicyDocument"]:
        policies = []
        for stmt in statements:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            policies.append(cls(
                effect=stmt.get("Effect", "Allow"),
                actions=actions,
                resources=resources,
                conditions=stmt.get("Condition", {}),
                raw=json.dumps(stmt),
            ))
        return policies

    def allows_action(self, action: str) -> bool:
        """Check if this policy allows a specific action."""
        if self.effect != "Allow":
            return False
        for a in self.actions:
            if a == "*" or a == action:
                return True
            if a.endswith("*"):
                prefix = a[:-1]
                if action.startswith(prefix):
                    return True
        return False

    def allows_any_action(self, actions: list[str]) -> bool:
        return any(self.allows_action(a) for a in actions)

    def to_dict(self) -> dict:
        return {
            "effect": self.effect,
            "actions": self.actions,
            "resources": self.resources,
            "conditions": self.conditions,
        }


@dataclass
class IAMRole:
    """An IAM role with its trust and permission policies."""
    provider: CloudProvider
    name: str
    arn: str = ""
    trust_policy: list[PolicyDocument] = field(default_factory=list)
    permission_policies: list[PolicyDocument] = field(default_factory=list)
    attached_managed_policies: list[str] = field(default_factory=list)
    is_service_role: bool = False
    can_be_assumed: bool = False
    risk_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "provider": self.provider.value if self.provider else "",
            "name": self.name,
            "arn": self.arn,
            "trust_policy": [p.to_dict() for p in self.trust_policy],
            "permission_policies": [p.to_dict() for p in self.permission_policies],
            "attached_managed_policies": self.attached_managed_policies,
            "is_service_role": self.is_service_role,
            "can_be_assumed": self.can_be_assumed,
            "risk_score": self.risk_score,
        }


@dataclass
class EscalationPath:
    """A discovered privilege escalation path."""
    technique: EscalationTechnique
    source: str
    target: str
    provider: CloudProvider
    actions_required: list[str] = field(default_factory=list)
    description: str = ""
    risk: str = "MEDIUM"
    steps: list[str] = field(default_factory=list)
    requires_external_service: bool = False

    def to_dict(self) -> dict:
        return {
            "technique": self.technique.value,
            "source": self.source,
            "target": self.target,
            "provider": self.provider.value if self.provider else "",
            "actions_required": self.actions_required,
            "description": self.description,
            "risk": self.risk,
            "steps": self.steps,
            "requires_external_service": self.requires_external_service,
        }


@dataclass
class IAMAnalysisResult:
    """Result of IAM analysis."""
    roles: list[IAMRole] = field(default_factory=list)
    escalation_paths: list[EscalationPath] = field(default_factory=list)
    high_risk_roles: list[IAMRole] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "total_roles": len(self.roles),
            "escalation_paths": len(self.escalation_paths),
            "high_risk_roles": len(self.high_risk_roles),
            "roles": [r.to_dict() for r in self.roles[:10]],  # limit output
            "escalation_paths": [p.to_dict() for p in self.escalation_paths],
            "summary": self.summary,
        }


class IAMPathfinder:
    """Analyzes IAM configurations for privilege escalation paths.

    Identifies roles, policies, and trust relationships that can be exploited
    to escalate from low-privilege access to administrative access.
    """

    def __init__(self):
        self._session_id = datetime.utcnow().isoformat()

    def analyze_aws(self) -> IAMAnalysisResult:
        """Analyze AWS IAM for privilege escalation paths."""
        result = IAMAnalysisResult()
        if not _HAS_BOTO3:
            result.summary = "boto3 not available — AWS IAM analysis disabled"
            return result

        try:
            iam = boto3.client("iam")

            # List all roles
            roles_response = iam.list_roles()
            for role_data in roles_response.get("Roles", []):
                role = self._parse_aws_role(role_data, iam)
                result.roles.append(role)

            # List all users
            users_response = iam.list_users()
            for user_data in users_response.get("Users", []):
                # Get user policies
                username = user_data["UserName"]
                user_policies = self._get_aws_user_policies(username, iam)
                role = IAMRole(
                    provider=CloudProvider.AWS,
                    name=f"user:{username}",
                    arn=user_data.get("Arn", ""),
                    permission_policies=user_policies,
                )
                result.roles.append(role)

            # Find escalation paths
            for role in result.roles:
                paths = self._find_aws_escalation_paths(role)
                result.escalation_paths.extend(paths)

            # Identify high-risk roles
            result.high_risk_roles = [r for r in result.roles if r.risk_score >= 5.0]

            result.summary = (
                f"AWS IAM analysis: {len(result.roles)} roles/users, "
                f"{len(result.escalation_paths)} escalation paths, "
                f"{len(result.high_risk_roles)} high-risk roles"
            )

        except Exception as e:
            logger.warning(f"AWS IAM analysis failed: {e}")
            result.summary = f"AWS IAM analysis error: {e}"

        return result

    def _parse_aws_role(self, role_data: dict, iam: Any) -> IAMRole:
        """Parse an AWS IAM role from API response."""
        role_name = role_data["RoleName"]

        # Parse trust policy
        trust_doc = role_data.get("AssumeRolePolicyDocument", {})
        trust_policies = PolicyDocument.from_aws_policy(
            trust_doc.get("Statement", []) if isinstance(trust_doc, dict) else []
        )

        # Get attached managed policies
        managed_policies = []
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)
            managed_policies = [p["PolicyArn"] for p in attached.get("AttachedPolicies", [])]
        except Exception:
            pass

        # Get inline policies
        permission_policies = []
        try:
            inline = iam.list_role_policies(RoleName=role_name)
            for policy_name in inline.get("PolicyNames", []):
                policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                statements = policy_doc.get("PolicyDocument", {}).get("Statement", [])
                permission_policies.extend(PolicyDocument.from_aws_policy(statements))
        except Exception:
            pass

        # Get managed policy documents
        for policy_arn in managed_policies:
            try:
                policy = iam.get_policy(PolicyArn=policy_arn)
                policy_version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy["Policy"]["DefaultVersionId"],
                )
                statements = policy_version.get("PolicyVersion", {}).get("Document", {}).get("Statement", [])
                permission_policies.extend(PolicyDocument.from_aws_policy(statements))
            except Exception:
                pass

        # Determine if role can be assumed by any principal
        can_be_assumed = any(
            p.allows_any_action(["sts:AssumeRole"])
            for p in trust_policies
        )

        # Risk scoring
        risk_score = self._score_role_risk(role_name, trust_policies, permission_policies)

        return IAMRole(
            provider=CloudProvider.AWS,
            name=role_name,
            arn=role_data.get("Arn", ""),
            trust_policy=trust_policies,
            permission_policies=permission_policies,
            attached_managed_policies=managed_policies,
            is_service_role="/service-role/" in role_data.get("Path", ""),
            can_be_assumed=can_be_assumed,
            risk_score=risk_score,
        )

    def _get_aws_user_policies(self, username: str, iam: Any) -> list[PolicyDocument]:
        """Get all policies attached to an IAM user."""
        policies = []

        # Inline user policies
        try:
            inline = iam.list_user_policies(UserName=username)
            for policy_name in inline.get("PolicyNames", []):
                doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                statements = doc.get("PolicyDocument", {}).get("Statement", [])
                policies.extend(PolicyDocument.from_aws_policy(statements))
        except Exception:
            pass

        # Attached managed policies
        try:
            attached = iam.list_attached_user_policies(UserName=username)
            for policy_data in attached.get("AttachedPolicies", []):
                arn = policy_data["PolicyArn"]
                policy = iam.get_policy(PolicyArn=arn)
                version = iam.get_policy_version(PolicyArn=arn, VersionId=policy["Policy"]["DefaultVersionId"])
                statements = version.get("PolicyVersion", {}).get("Document", {}).get("Statement", [])
                policies.extend(PolicyDocument.from_aws_policy(statements))
        except Exception:
            pass

        return policies

    def _find_aws_escalation_paths(self, role: IAMRole) -> list[EscalationPath]:
        """Find privilege escalation paths for a role/user."""
        paths = []

        for path_name, path_info in KNOWN_ESCALATION_PATHS.items():
            required = path_info["required_permissions"]
            # Check if any policy allows ALL required actions
            has_perms = any(
                p.allows_any_action(required)
                for p in role.permission_policies
            )
            if has_perms:
                source = role.arn if role.arn else role.name
                paths.append(EscalationPath(
                    technique=path_info["technique"],
                    source=source,
                    target=path_info["target"],
                    provider=CloudProvider.AWS,
                    actions_required=required,
                    description=path_info["description"],
                    risk=path_info["risk"],
                    steps=[
                        f"1. Use {', '.join(required)} permissions",
                        f"2. {path_info['description']}",
                        f"3. Assume the new role/user to gain elevated privileges",
                    ],
                ))

        return paths

    def _score_role_risk(self, name: str, trust: list[PolicyDocument], permissions: list[PolicyDocument]) -> float:
        """Calculate risk score for a role (0-10)."""
        score = 0.0

        # Check for wildcard permissions
        admin = any(
            p.allows_action("*") for p in permissions
        )
        if admin:
            score += 4.0

        # Check for iam:* permissions
        iam_admin = any(
            p.allows_any_action(["iam:*", "iam:CreateUser", "iam:CreateRole", "iam:PutUserPolicy"])
            for p in permissions
        )
        if iam_admin:
            score += 3.0

        # Check trust policy allows broad access
        broad_trust = any(
            p.allows_any_action(["sts:AssumeRole"])
            and ("*" in p.resources or "Principal" in str(p.raw))
            for p in trust
        )
        if broad_trust:
            score += 2.0

        # Service roles that can be passed
        if name.startswith("ec2") or name.startswith("lambda"):
            score += 1.0

        return min(score, 10.0)

    def analyze_gcp(self) -> IAMAnalysisResult:
        """Analyze GCP IAM (placeholder — requires google-cloud SDK)."""
        result = IAMAnalysisResult()
        result.summary = "GCP IAM analysis requires google-cloud-iam SDK"
        return result

    def analyze_azure(self) -> IAMAnalysisResult:
        """Analyze Azure IAM (placeholder — requires azure-identity SDK)."""
        result = IAMAnalysisResult()
        result.summary = "Azure IAM analysis requires azure-identity SDK"
        return result

    def summary(self) -> dict:
        return {
            "pathfinder": "IAMPathfinder",
            "version": "0.1.0",
            "has_boto3": _HAS_BOTO3,
            "known_escalation_paths": len(KNOWN_ESCALATION_PATHS),
            "providers": ["aws"],
        }


def find_aws_escalation_paths() -> dict:
    """Convenience function to find AWS IAM escalation paths."""
    pathfinder = IAMPathfinder()
    result = pathfinder.analyze_aws()
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    cmd = sys.argv[1] if len(sys.argv) > 1 else "aws"
    pathfinder = IAMPathfinder()

    if cmd == "aws":
        result = pathfinder.analyze_aws()
        print(json.dumps(result.to_dict(), indent=2, default=str))
    elif cmd == "paths":
        print(json.dumps({k: {"risk": v["risk"], "description": v["description"]}
                          for k, v in KNOWN_ESCALATION_PATHS.items()}, indent=2, default=str))
    else:
        print("Usage: python iam_pathfinder.py aws|paths")
