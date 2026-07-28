"""
CI/CD Workflow Parser (P0 - FORGE Phase 0)

Parses GitHub Actions, GitLab CI, and Azure Pipelines workflow files.
Extracts: jobs, steps, triggers, secrets usage, runners, permissions, artifacts, caches.
"""

from __future__ import annotations

import yaml
import re
import os
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class CIProvider(Enum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    AZURE_PIPELINES = "azure_pipelines"
    UNKNOWN = "unknown"


class TriggerType(Enum):
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    SCHEDULE = "schedule"
    WORKFLOW_DISPATCH = "workflow_dispatch"
    REPOSITORY_DISPATCH = "repository_dispatch"
    RELEASE = "release"
    DEPLOYMENT = "deployment"
    MERGE_GROUP = "merge_group"
    WORKFLOW_CALL = "workflow_call"
    UNKNOWN = "unknown"


class RunnerType(Enum):
    GITHUB_HOSTED = "github_hosted"
    SELF_HOSTED = "self_hosted"
    GITLAB_SHARED = "gitlab_shared"
    GITLAB_SPECIFIC = "gitlab_specific"
    GITLAB_GROUP = "gitlab_group"
    GITLAB_PROJECT = "gitlab_project"
    AZURE_HOSTED = "azure_hosted"
    AZURE_SELF_HOSTED = "azure_self_hosted"
    UNKNOWN = "unknown"


@dataclass
class Step:
    name: Optional[str] = None
    id: Optional[str] = None
    uses: Optional[str] = None
    run: Optional[str] = None
    shell: Optional[str] = None
    env: dict = field(default_factory=dict)
    with_: dict = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)
    if_condition: Optional[str] = None
    continue_on_error: bool = False
    timeout_minutes: Optional[int] = None
    working_directory: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def extracts_secrets(self) -> list[str]:
        """Extract all secret references from this step."""
        secrets = []
        # From env
        for k, v in self.env.items():
            if isinstance(v, str) and "${{" in v and "secrets." in v:
                matches = re.findall(r"\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", v, re.IGNORECASE)
                secrets.extend(matches)
        # From with
        for k, v in self.with_.items():
            if isinstance(v, str) and "${{" in v and "secrets." in v:
                matches = re.findall(r"\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", v, re.IGNORECASE)
                secrets.extend(matches)
        # From run command
        if self.run:
            matches = re.findall(r"\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", self.run, re.IGNORECASE)
            secrets.extend(matches)
        return list(set(secrets))

    def extracts_tokens(self) -> list[str]:
        """Extract token-like secrets (GITHUB_TOKEN, GITLAB_TOKEN, etc)."""
        tokens = []
        all_secrets = self.extracts_secrets()
        token_patterns = [
            "GITHUB_TOKEN", "GITLAB_TOKEN", "AZURE_PIPELINES_TOKEN",
            "GH_TOKEN", "GL_TOKEN", "AZDO_TOKEN", "SYSTEM_ACCESSTOKEN",
            "NPM_TOKEN", "PYPI_TOKEN", "DOCKER_TOKEN", "GCR_TOKEN",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
        ]
        for secret in all_secrets:
            if any(p in secret.upper() for p in token_patterns):
                tokens.append(secret)
        return tokens

    def uses_action(self) -> bool:
        return bool(self.uses)

    def runs_script(self) -> bool:
        return bool(self.run)

    def is_checkout(self) -> bool:
        return self.uses and "actions/checkout" in self.uses

    def is_setup_language(self) -> bool:
        return self.uses and any(x in self.uses for x in ["actions/setup-", "actions/setup-"])

    def is_upload_artifact(self) -> bool:
        return self.uses and "actions/upload-artifact" in self.uses

    def is_download_artifact(self) -> bool:
        return self.uses and "actions/download-artifact" in self.uses

    def is_cache(self) -> bool:
        return self.uses and "actions/cache" in self.uses


@dataclass
class Job:
    id: str
    name: Optional[str] = None
    needs: list[str] = field(default_factory=list)
    runs_on: list[str] = field(default_factory=list)
    runs_on_labels: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    env: dict = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)
    permissions: dict = field(default_factory=dict)
    timeout_minutes: Optional[int] = None
    if_condition: Optional[str] = None
    container: Optional[dict] = None
    services: dict = field(default_factory=dict)
    defaults: dict = field(default_factory=dict)
    strategy: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    def get_runner_type(self) -> RunnerType:
        if not self.runs_on:
            return RunnerType.UNKNOWN
        runs_on_str = " ".join(self.runs_on).lower()
        if "self-hosted" in runs_on_str:
            return RunnerType.SELF_HOSTED
        if "ubuntu" in runs_on_str or "windows" in runs_on_str or "macos" in runs_on_str:
            return RunnerType.GITHUB_HOSTED
        if "gitlab" in runs_on_str:
            if "shared" in runs_on_str:
                return RunnerType.GITLAB_SHARED
            if "group" in runs_on_str:
                return RunnerType.GITLAB_GROUP
            if "project" in runs_on_str:
                return RunnerType.GITLAB_PROJECT
            return RunnerType.GITLAB_SPECIFIC
        if "azure" in runs_on_str:
            if "self-hosted" in runs_on_str:
                return RunnerType.AZURE_SELF_HOSTED
            return RunnerType.AZURE_HOSTED
        return RunnerType.UNKNOWN

    def is_self_hosted(self) -> bool:
        return self.get_runner_type() in (RunnerType.SELF_HOSTED, RunnerType.GITLAB_SPECIFIC,
                                           RunnerType.GITLAB_GROUP, RunnerType.GITLAB_PROJECT,
                                           RunnerType.AZURE_SELF_HOSTED)

    def extracts_secrets(self) -> list[str]:
        secrets = set(self.secrets)
        for step in self.steps:
            secrets.update(step.extracts_secrets())
        return list(secrets)

    def extracts_tokens(self) -> list[str]:
        tokens = []
        for step in self.steps:
            tokens.extend(step.extracts_tokens())
        return list(set(tokens))

    def has_checkout(self) -> bool:
        return any(s.is_checkout() for s in self.steps)

    def has_upload_artifact(self) -> bool:
        return any(s.is_upload_artifact() for s in self.steps)

    def has_download_artifact(self) -> bool:
        return any(s.is_download_artifact() for s in self.steps)

    def has_cache(self) -> bool:
        return any(s.is_cache() for s in self.steps)

    def get_actions_used(self) -> list[str]:
        return [s.uses for s in self.steps if s.uses]


@dataclass
class Workflow:
    path: str
    provider: CIProvider
    name: Optional[str] = None
    on: dict = field(default_factory=dict)
    triggers: list[TriggerType] = field(default_factory=list)
    jobs: dict[str, Job] = field(default_factory=dict)
    env: dict = field(default_factory=dict)
    permissions: dict = field(default_factory=dict)
    concurrency: Optional[dict] = None
    raw: dict = field(default_factory=dict)

    def get_all_secrets(self) -> list[str]:
        secrets = set()
        for job in self.jobs.values():
            secrets.update(job.extracts_secrets())
        return list(secrets)

    def get_all_tokens(self) -> list[str]:
        tokens = set()
        for job in self.jobs.values():
            tokens.update(job.extracts_tokens())
        return list(tokens)

    def get_self_hosted_jobs(self) -> list[Job]:
        return [j for j in self.jobs.values() if j.is_self_hosted()]

    def get_trigger_types(self) -> list[TriggerType]:
        if not self.triggers:
            self._parse_triggers()
        return self.triggers

    def _parse_triggers(self):
        if not self.on:
            return
        if isinstance(self.on, str):
            self.triggers.append(TriggerType(self.on) if self.on in [t.value for t in TriggerType] else TriggerType.UNKNOWN)
        elif isinstance(self.on, list):
            for t in self.on:
                self.triggers.append(TriggerType(t) if t in [tt.value for tt in TriggerType] else TriggerType.UNKNOWN)
        elif isinstance(self.on, dict):
            for k in self.on.keys():
                self.triggers.append(TriggerType(k) if k in [tt.value for tt in TriggerType] else TriggerType.UNKNOWN)

    def has_schedule_trigger(self) -> bool:
        return TriggerType.SCHEDULE in self.get_trigger_types()

    def has_workflow_dispatch(self) -> bool:
        return TriggerType.WORKFLOW_DISPATCH in self.get_trigger_types()

    def has_pull_request_trigger(self) -> bool:
        return TriggerType.PULL_REQUEST in self.get_trigger_types()

    def is_reusable_workflow(self) -> bool:
        return TriggerType.WORKFLOW_CALL in self.get_trigger_types()


class WorkflowParser:
    """Parses CI/CD workflow files from GitHub Actions, GitLab CI, Azure Pipelines."""

    GITHUB_ACTIONS_PATTERNS = [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ]
    GITLAB_CI_PATTERNS = [
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        ".gitlab/**/*.yml",
        ".gitlab/**/*.yaml",
    ]
    AZURE_PIPELINES_PATTERNS = [
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        "pipelines/*.yml",
        "pipelines/*.yaml",
    ]

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path).resolve()
        self.workflows: list[Workflow] = []
        self._parsed_paths: set[str] = set()

    def discover_workflows(self) -> list[Path]:
        """Discover all CI/CD workflow files in the repository."""
        workflows = []
        for pattern in self.GITHUB_ACTIONS_PATTERNS:
            workflows.extend(self.repo_path.glob(pattern))
        for pattern in self.GITLAB_CI_PATTERNS:
            workflows.extend(self.repo_path.glob(pattern))
        for pattern in self.AZURE_PIPELINES_PATTERNS:
            workflows.extend(self.repo_path.glob(pattern))
        return sorted(set(workflows))

    def parse_all(self) -> list[Workflow]:
        """Parse all discovered workflow files."""
        self.workflows = []
        self._parsed_paths = set()
        for path in self.discover_workflows():
            try:
                wf = self.parse_file(path)
                if wf:
                    self.workflows.append(wf)
                    self._parsed_paths.add(str(path))
            except Exception as e:
                logger.warning(f"Failed to parse {path}: {e}")
        return self.workflows

    def parse_file(self, path: Path) -> Optional[Workflow]:
        """Parse a single workflow file."""
        if str(path) in self._parsed_paths:
            return None

        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if not data:
                return None
        except Exception as e:
            logger.warning(f"Failed to load {path}: {e}")
            return None

        provider = self._detect_provider(path, data)
        if provider == CIProvider.UNKNOWN:
            logger.warning(f"Unknown CI provider for {path}")
            return None

        if provider == CIProvider.GITHUB_ACTIONS:
            return self._parse_github_actions(path, data)
        elif provider == CIProvider.GITLAB_CI:
            return self._parse_gitlab_ci(path, data)
        elif provider == CIProvider.AZURE_PIPELINES:
            return self._parse_azure_pipelines(path, data)
        return None

    def _detect_provider(self, path: Path, data: dict) -> CIProvider:
        path_str = str(path).lower()
        if ".github/workflows" in path_str:
            return CIProvider.GITHUB_ACTIONS
        if ".gitlab-ci" in path_str or ".gitlab/" in path_str:
            return CIProvider.GITLAB_CI
        if "azure-pipelines" in path_str or "pipelines/" in path_str:
            return CIProvider.AZURE_PIPELINES
        # Heuristic from content
        if "jobs:" in data and "on:" in data:
            return CIProvider.GITHUB_ACTIONS
        if "stages:" in data and "variables:" in data:
            return CIProvider.GITLAB_CI
        if "trigger:" in data and "pool:" in data:
            return CIProvider.AZURE_PIPELINES
        return CIProvider.UNKNOWN

    def _parse_github_actions(self, path: Path, data: dict) -> Workflow:
        wf = Workflow(
            path=str(path.relative_to(self.repo_path)),
            provider=CIProvider.GITHUB_ACTIONS,
            name=data.get("name"),
            on=data.get("on", {}),
            env=data.get("env", {}),
            permissions=data.get("permissions", {}),
            concurrency=data.get("concurrency"),
            raw=data,
        )
        wf._parse_triggers()

        jobs_data = data.get("jobs", {})
        for job_id, job_data in jobs_data.items():
            if not isinstance(job_data, dict):
                continue
            job = self._parse_gh_job(job_id, job_data)
            wf.jobs[job_id] = job

        return wf

    def _parse_gh_job(self, job_id: str, data: dict) -> Job:
        steps_data = data.get("steps", [])
        steps = [self._parse_gh_step(s) for s in steps_data if isinstance(s, dict)]

        runs_on = data.get("runs-on", [])
        if isinstance(runs_on, str):
            runs_on = [runs_on]

        runs_on_labels = []
        for r in runs_on:
            if isinstance(r, str) and "self-hosted" in r.lower():
                parts = r.split(",")
                runs_on_labels.extend([p.strip() for p in parts if "self-hosted" not in p.lower()])

        return Job(
            id=job_id,
            name=data.get("name"),
            needs=data.get("needs", []) if isinstance(data.get("needs"), list) else [data.get("needs")] if data.get("needs") else [],
            runs_on=runs_on,
            runs_on_labels=runs_on_labels,
            steps=steps,
            env=data.get("env", {}),
            secrets=self._extract_job_secrets(data),
            permissions=data.get("permissions", {}),
            timeout_minutes=data.get("timeout-minutes"),
            if_condition=data.get("if"),
            container=data.get("container"),
            services=data.get("services", {}),
            defaults=data.get("defaults", {}),
            strategy=data.get("strategy", {}),
            raw=data,
        )

    def _parse_gh_step(self, data: dict) -> Step:
        step = Step(
            name=data.get("name"),
            id=data.get("id"),
            uses=data.get("uses"),
            run=data.get("run"),
            shell=data.get("shell"),
            env=data.get("env", {}),
            with_=data.get("with", {}),
            if_condition=data.get("if"),
            continue_on_error=data.get("continue-on-error", False),
            timeout_minutes=data.get("timeout-minutes"),
            working_directory=data.get("working-directory"),
            raw=data,
        )
        step.secrets = step.extracts_secrets()
        return step

    def _extract_job_secrets(self, data: dict) -> list[str]:
        secrets = []
        # From job-level env
        for v in data.get("env", {}).values():
            if isinstance(v, str):
                matches = re.findall(r"\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", v, re.IGNORECASE)
                secrets.extend(matches)
        return list(set(secrets))

    def _parse_gitlab_ci(self, path: Path, data: dict) -> Workflow:
        wf = Workflow(
            path=str(path.relative_to(self.repo_path)),
            provider=CIProvider.GITLAB_CI,
            name=data.get("workflow", {}).get("name") if isinstance(data.get("workflow"), dict) else None,
            raw=data,
        )

        # GitLab CI uses stages and jobs at top level
        for key, value in data.items():
            if key in ("stages", "variables", "workflow", "include", "before_script", "after_script", "cache", "default"):
                continue
            if isinstance(value, dict) and ("script" in value or "stage" in value or "image" in value or "tags" in value):
                job = self._parse_gitlab_job(key, value, data)
                wf.jobs[key] = job

        return wf

    def _parse_gitlab_job(self, job_id: str, data: dict, global_data: dict) -> Job:
        scripts = data.get("script", [])
        if isinstance(scripts, str):
            scripts = [scripts]

        steps = []
        for i, script in enumerate(scripts):
            steps.append(Step(
                name=f"script_{i}",
                run=script,
                shell=data.get("shell"),
                env={**global_data.get("variables", {}), **data.get("variables", {})},
                raw={"script": script},
            ))

        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        return Job(
            id=job_id,
            name=data.get("name"),
            needs=[n.get("job") if isinstance(n, dict) else n for n in data.get("needs", [])],
            runs_on=tags,
            runs_on_labels=tags,
            steps=steps,
            env={**global_data.get("variables", {}), **data.get("variables", {})},
            timeout_minutes=data.get("timeout"),
            if_condition=data.get("rules") or data.get("only") or data.get("except"),
            raw=data,
        )

    def _parse_azure_pipelines(self, path: Path, data: dict) -> Workflow:
        wf = Workflow(
            path=str(path.relative_to(self.repo_path)),
            provider=CIProvider.AZURE_PIPELINES,
            name=data.get("name"),
            raw=data,
        )

        # Azure Pipelines can have jobs at top level or in stages
        jobs_data = {}
        if "jobs" in data:
            jobs_data = data["jobs"]
        elif "stages" in data:
            for stage in data["stages"]:
                if isinstance(stage, dict) and "jobs" in stage:
                    jobs_data.update(stage["jobs"])

        for job_id, job_data in jobs_data.items():
            if isinstance(job_data, dict):
                job = self._parse_azure_job(job_id, job_data, data)
                wf.jobs[job_id] = job

        return wf

    def _parse_azure_job(self, job_id: str, data: dict, global_data: dict) -> Job:
        steps_data = data.get("steps", [])
        steps = []
        for s in steps_data:
            if isinstance(s, dict):
                steps.append(Step(
                    name=s.get("displayName") or s.get("name"),
                    id=s.get("name"),
                    uses=s.get("task") or s.get("uses"),
                    run=s.get("script") or s.get("bash") or s.get("pwsh"),
                    env={**global_data.get("variables", {}), **data.get("variables", {}), **s.get("env", {})},
                    raw=s,
                ))

        pool = data.get("pool", global_data.get("pool", {}))
        runs_on = []
        if isinstance(pool, dict):
            vm_image = pool.get("vmImage") or pool.get("vm_image")
            if vm_image:
                runs_on.append(vm_image)
            if pool.get("selfHosted") or pool.get("isHosted") is False:
                runs_on.append("self-hosted")
        elif isinstance(pool, str):
            runs_on.append(pool)

        return Job(
            id=job_id,
            name=data.get("displayName") or data.get("name"),
            needs=data.get("dependsOn", []),
            runs_on=runs_on,
            steps=steps,
            timeout_minutes=data.get("timeoutInMinutes"),
            raw=data,
        )

    def get_workflows_by_provider(self, provider: CIProvider) -> list[Workflow]:
        return [w for w in self.workflows if w.provider == provider]

    def get_all_self_hosted_jobs(self) -> list[Job]:
        jobs = []
        for wf in self.workflows:
            jobs.extend(wf.get_self_hosted_jobs())
        return jobs

    def get_all_secrets(self) -> dict[str, list[str]]:
        """Returns dict of workflow_path -> secrets"""
        return {wf.path: wf.get_all_secrets() for wf in self.workflows}

    def get_all_tokens(self) -> dict[str, list[str]]:
        return {wf.path: wf.get_all_tokens() for wf in self.workflows}

    def summary(self) -> dict:
        return {
            "total_workflows": len(self.workflows),
            "by_provider": {p.value: len(self.get_workflows_by_provider(p)) for p in CIProvider},
            "total_jobs": sum(len(w.jobs) for w in self.workflows),
            "self_hosted_jobs": len(self.get_all_self_hosted_jobs()),
            "workflows_with_tokens": sum(1 for w in self.workflows if w.get_all_tokens()),
            "workflows_with_secrets": sum(1 for w in self.workflows if w.get_all_secrets()),
            "reusable_workflows": sum(1 for w in self.workflows if w.is_reusable_workflow()),
        }


def parse_workflow_file(path: str | Path) -> Optional[Workflow]:
    """Convenience function to parse a single workflow file."""
    parser = WorkflowParser(str(Path(path).parent))
    return parser.parse_file(Path(path))


def parse_repo(repo_path: str = ".") -> list[Workflow]:
    """Convenience function to parse all workflows in a repo."""
    parser = WorkflowParser(repo_path)
    return parser.parse_all()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    workflows = parse_repo(path)
    parser = WorkflowParser(path)
    parser.parse_all()
    print(json.dumps(parser.summary(), indent=2))
    for wf in workflows:
        print(f"\n=== {wf.path} ({wf.provider.value}) ===")
        print(f"  Name: {wf.name}")
        print(f"  Triggers: {[t.value for t in wf.get_trigger_types()]}")
        print(f"  Jobs: {list(wf.jobs.keys())}")
        for job_id, job in wf.jobs.items():
            print(f"    Job: {job_id} (runner: {job.get_runner_type().value})")
            print(f"      Steps: {len(job.steps)}")
            print(f"      Secrets: {job.extracts_secrets()}")
            print(f"      Tokens: {job.extracts_tokens()}")
            print(f"      Actions: {job.get_actions_used()}")