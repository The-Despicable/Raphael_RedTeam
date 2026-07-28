"""
ML Supply Chain Injector (P1 - FORGE Phase 1)

Orchestrates ML supply chain attacks by combining payload generation,
format analysis, and HF Hub interaction into injection strategies.

Attack vectors:
- Model substitution: Replace benign model with backdoored version
- Dependency confusion: Typosquat model package names
- Pipeline injection: Inject malicious steps in ML pipelines
- Training data poisoning: Embed triggers in model weights
- Model card social engineering: Craft convincing model cards
- Update hijack: Upload backdoored version update
"""

from __future__ import annotations

import os
import re
import json
import uuid
import hashlib
import logging
import tempfile
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class InjectionVector(Enum):
    """Types of ML supply chain injection vectors."""
    MODEL_SUBSTITUTION = "model_substitution"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    PIPELINE_INJECTION = "pipeline_injection"
    WEIGHT_POISONING = "weight_poisoning"
    MODEL_CARD_SOCIAL = "model_card_social"
    UPDATE_HIJACK = "update_hijack"
    DATASET_POISONING = "dataset_poisoning"
    REPO_TAKEOVER = "repo_takeover"


class AttackStage(Enum):
    """Stages of a supply chain attack."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    PERSISTENCE = "persistence"


@dataclass
class InjectionPlan:
    """A complete plan for a supply chain injection attack."""
    name: str
    vector: InjectionVector
    target_model: str
    payload_name: str = ""
    description: str = ""
    stages: list[AttackStage] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)
    estimated_success_rate: float = 0.5
    detection_risk: float = 0.3
    steps: list[str] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    cleanup_steps: list[str] = field(default_factory=list)
    completed_stages: list[str] = field(default_factory=list)
    status: str = "planned"  # planned, in_progress, completed, failed

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vector": self.vector.value,
            "target_model": self.target_model,
            "payload_name": self.payload_name,
            "description": self.description,
            "stages": [s.value for s in self.stages],
            "requirements": self.requirements,
            "estimated_success_rate": self.estimated_success_rate,
            "detection_risk": self.detection_risk,
            "steps": self.steps,
            "artifact_count": len(self.artifacts),
            "cleanup_steps": self.cleanup_steps,
            "completed_stages": self.completed_stages,
            "status": self.status,
        }


@dataclass
class InjectionResult:
    """Result of an injection operation."""
    success: bool
    vector: InjectionVector
    plan_name: str
    target_model: str
    error: str = ""
    artifacts_created: list[str] = field(default_factory=list)
    details: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "vector": self.vector.value,
            "plan_name": self.plan_name,
            "target_model": self.target_model,
            "error": self.error,
            "artifacts_created": self.artifacts_created,
            "details": self.details,
            "timestamp": self.timestamp or datetime.utcnow().isoformat(),
        }


class SupplyChainInjector:
    """Orchestrates ML supply chain injection attacks.

    FORGE Rule 1 (end-to-end): No encrypt/decrypt needed.
    FORGE Rule 3 (import map): All imports guarded.
    FORGE Rule 4 (subprocess): No subprocess calls.
    FORGE Rule 5 (shellcode): No shellcode.

    All operations are dry-run by default. Use --live to execute.
    """

    # Attack templates for common ML supply chain scenarios
    ATTACK_TEMPLATES: dict[str, dict] = {
        "hf_model_backdoor": {
            "vector": InjectionVector.MODEL_SUBSTITUTION,
            "description": "Backdoor a popular HF model by uploading a poisoned version",
            "requirements": ["HF token with write access", "target model ID", "payload factory"],
            "estimated_success_rate": 0.4,
            "detection_risk": 0.7,
            "steps": [
                "1. Identify target model with pickle format and high downloads",
                "2. Download original model weights",
                "3. Generate backdoor payload using PicklePayloadFactory",
                "4. Embed payload into model file",
                "5. Upload as new version with convincing commit message",
                "6. Optionally create model card with fake benchmark results",
            ],
            "cleanup_steps": [
                "Remove uploaded version via HF API",
                "Revoke any exposed tokens",
            ],
        },
        "dependency_confusion": {
            "vector": InjectionVector.DEPENDENCY_CONFUSION,
            "description": "Register malicious package with same name as internal package",
            "requirements": ["PyPI/NPM token", "internal package name knowledge"],
            "estimated_success_rate": 0.6,
            "detection_risk": 0.5,
            "steps": [
                "1. Identify internal package name pattern from CI/CD analysis",
                "2. Check if name is available on public registry",
                "3. Create malicious package with same name + higher version",
                "4. Package includes pickle payload for ML models",
                "5. Upload to public registry",
            ],
            "cleanup_steps": [
                "Remove package version from registry",
                "Revoke registry token",
            ],
        },
        "pipeline_injection": {
            "vector": InjectionVector.PIPELINE_INJECTION,
            "description": "Inject malicious step into ML training pipeline via CI/CD poisoning",
            "requirements": ["CI/CD access", "pipeline repository write access"],
            "estimated_success_rate": 0.5,
            "detection_risk": 0.6,
            "steps": [
                "1. Identify ML pipeline workflow file",
                "2. Inject step that downloads backdoored model",
                "3. Step runs during training with access to model weights and data",
            ],
            "cleanup_steps": [
                "Remove injected step from workflow",
                "Restore from CI/CD backup if available",
            ],
        },
        "model_card_trojan": {
            "vector": InjectionVector.MODEL_CARD_SOCIAL,
            "description": "Create convincing model card to trick users into loading malicious model",
            "requirements": ["HF token", "payload model"],
            "estimated_success_rate": 0.7,
            "detection_risk": 0.4,
            "steps": [
                "1. Create model with benign-sounding name (e.g., 'bert-base-uncased-fixed')",
                "2. Generate professional model card with fake benchmarks",
                "3. Upload with pickle payload embedded",
                "4. Promote via social engineering (comments, issues)",
            ],
            "cleanup_steps": [
                "Delete model from HF Hub",
            ],
        },
    }

    def __init__(self, dry_run: bool = True, output_dir: Optional[str] = None):
        self.dry_run = dry_run
        self.output_dir = Path(output_dir or tempfile.mkdtemp(prefix="raphael_ml_inject_"))
        self.plans: list[InjectionPlan] = []
        self.results: list[InjectionResult] = []

    def create_plan(
        self,
        vector: InjectionVector | str,
        target_model: str,
        payload_name: str = "",
        custom_steps: Optional[list[str]] = None,
    ) -> InjectionPlan:
        """Create an injection plan from a template or custom configuration."""
        if isinstance(vector, str):
            try:
                vector = InjectionVector(vector)
            except ValueError:
                vector = next((v for k, v in InjectionVector.__members__.items()
                               if k.lower() == vector.lower()), InjectionVector.MODEL_SUBSTITUTION)

        plan_name = f"{vector.value}_{target_model.replace('/', '_')}_{uuid.uuid4().hex[:8]}"

        # Load template if available
        template_key = vector.value
        template = self.ATTACK_TEMPLATES.get(template_key, {})

        plan = InjectionPlan(
            name=plan_name,
            vector=vector,
            target_model=target_model,
            payload_name=payload_name or self._default_payload_for_vector(vector),
            description=template.get("description", f"{vector.value} attack on {target_model}"),
            stages=[
                AttackStage.RECONNAISSANCE,
                AttackStage.WEAPONIZATION,
                AttackStage.DELIVERY,
                AttackStage.EXPLOITATION,
            ],
            requirements=template.get("requirements", []),
            estimated_success_rate=template.get("estimated_success_rate", 0.5),
            detection_risk=template.get("detection_risk", 0.5),
            steps=custom_steps or template.get("steps", [f"Execute {vector.value} against {target_model}"]),
            cleanup_steps=template.get("cleanup_steps", []),
        )

        self.plans.append(plan)
        return plan

    def execute_plan(self, plan: InjectionPlan) -> InjectionResult:
        """Execute an injection plan."""
        result = InjectionResult(
            success=False,
            vector=plan.vector,
            plan_name=plan.name,
            target_model=plan.target_model,
            timestamp=datetime.utcnow().isoformat(),
        )

        if self.dry_run:
            result.success = True
            result.details = f"DRY RUN: Would execute {plan.vector.value} against {plan.target_model}"
            result.artifacts_created = [
                f"(dry-run) {step}" for step in plan.steps[:3]
            ]
            self.results.append(result)
            return result

        try:
            # Execute each stage
            for stage in plan.stages:
                stage_result = self._execute_stage(stage, plan)
                if stage_result:
                    plan.completed_stages.append(stage.value)

            plan.status = "completed"
            result.success = True
            result.details = f"Successfully executed {plan.vector.value} against {plan.target_model}"
            result.artifacts_created = self._collect_artifacts(plan)

        except Exception as e:
            plan.status = "failed"
            result.error = str(e)
            result.details = f"Execution failed at stage {len(plan.completed_stages) + 1}: {e}"
            logger.error(f"Injection failed: {e}", exc_info=True)

        self.results.append(result)
        return result

    def _execute_stage(self, stage: AttackStage, plan: InjectionPlan) -> bool:
        """Execute a single attack stage."""
        stage_handlers = {
            AttackStage.RECONNAISSANCE: self._stage_reconnaissance,
            AttackStage.WEAPONIZATION: self._stage_weaponization,
            AttackStage.DELIVERY: self._stage_delivery,
            AttackStage.EXPLOITATION: self._stage_exploitation,
        }
        handler = stage_handlers.get(stage)
        if handler:
            return handler(plan)
        return False

    def _stage_reconnaissance(self, plan: InjectionPlan) -> bool:
        """Reconnaissance stage: gather info about the target."""
        logger.info(f"[RECON] Reconnaissance for {plan.target_model}")
        # This would call HFHubAPIClient in production
        plan.artifacts.append({"stage": "recon", "type": "model_info", "target": plan.target_model})
        return True

    def _stage_weaponization(self, plan: InjectionPlan) -> bool:
        """Weaponization stage: generate the payload."""
        logger.info(f"[WEAPONIZE] Generating payload for {plan.target_model}")
        # This would call PicklePayloadFactory in production
        plan.artifacts.append({
            "stage": "weaponization",
            "type": "payload",
            "name": plan.payload_name,
        })
        return True

    def _stage_delivery(self, plan: InjectionPlan) -> bool:
        """Delivery stage: deliver the payload."""
        logger.info(f"[DELIVER] Delivering payload to {plan.target_model}")
        plan.artifacts.append({"stage": "delivery", "type": "upload", "target": plan.target_model})
        return True

    def _stage_exploitation(self, plan: InjectionPlan) -> bool:
        """Exploitation stage: trigger the payload."""
        logger.info(f"[EXPLOIT] Triggering payload on {plan.target_model}")
        plan.artifacts.append({"stage": "exploit", "type": "trigger", "target": plan.target_model})
        return True

    def _collect_artifacts(self, plan: InjectionPlan) -> list[str]:
        """Collect artifact paths from a plan execution."""
        artifacts = []
        for artifact in plan.artifacts:
            if isinstance(artifact, dict) and "name" in artifact:
                artifacts.append(str(self.output_dir / artifact["name"]))
            elif isinstance(artifact, dict) and "target" in artifact:
                artifacts.append(artifact["target"])
        return artifacts

    def _default_payload_for_vector(self, vector: InjectionVector) -> str:
        """Get default payload name for an injection vector."""
        payloads = {
            InjectionVector.MODEL_SUBSTITUTION: "model_backdoor_reverse_shell",
            InjectionVector.DEPENDENCY_CONFUSION: "dependency_confusion_token_exfil",
            InjectionVector.PIPELINE_INJECTION: "pipeline_credential_exfil",
            InjectionVector.WEIGHT_POISONING: "weight_data_poison",
            InjectionVector.MODEL_CARD_SOCIAL: "model_card_custom_exec",
            InjectionVector.UPDATE_HIJACK: "update_token_exfil",
            InjectionVector.DATASET_POISONING: "dataset_data_poison",
            InjectionVector.REPO_TAKEOVER: "repo_model_theft",
        }
        return payloads.get(vector, "generic_ml_payload")

    def analyze_target(self, model_id: str, format_analysis: dict, hf_info: dict) -> dict:
        """Analyze a potential target and recommend injection vectors."""
        analysis = {
            "model_id": model_id,
            "recommended_vectors": [],
            "risk_assessment": {},
            "feasibility_score": 0.0,
        }

        # Check if model uses pickle (RCE vector)
        has_pickle = format_analysis.get("format") in ("pickle", "torch", "joblib")
        has_dangerous_ops = format_analysis.get("has_dangerous_ops", False)
        downloads = hf_info.get("downloads", 0)
        is_safetensors = hf_info.get("is_safetensors", False)

        # Recommend vectors based on target characteristics
        if has_pickle and not is_safetensors:
            analysis["recommended_vectors"].append({
                "vector": InjectionVector.MODEL_SUBSTITUTION.value,
                "reason": "Model uses pickle format — direct RCE via __reduce__",
                "priority": "HIGH",
            })

        if downloads > 10000 and has_pickle:
            analysis["recommended_vectors"].append({
                "vector": InjectionVector.UPDATE_HIJACK.value,
                "reason": f"Popular model ({downloads} downloads) — high blast radius",
                "priority": "CRITICAL",
            })

        if has_dangerous_ops:
            analysis["recommended_vectors"].append({
                "vector": InjectionVector.MODEL_CARD_SOCIAL.value,
                "reason": "Model already has dangerous ops — likely already a target",
                "priority": "MEDIUM",
            })

        # Feasibility score
        score = 0.0
        if has_pickle:
            score += 3.0
        if downloads > 1000:
            score += 2.0
        if not is_safetensors:
            score += 1.0
        if has_dangerous_ops:
            score += 2.0

        analysis["risk_assessment"] = {
            "has_pickle": has_pickle,
            "has_dangerous_ops": has_dangerous_ops,
            "downloads": downloads,
            "uses_safetensors": is_safetensors,
            "attack_priority": "CRITICAL" if score >= 7.0 else "HIGH" if score >= 4.0 else "MEDIUM",
        }
        analysis["feasibility_score"] = min(score, 10.0)

        return analysis

    def generate_report(self) -> dict:
        """Generate a consolidated report of all plans and results."""
        return {
            "injector": "SupplyChainInjector",
            "version": "0.1.0",
            "dry_run": self.dry_run,
            "output_dir": str(self.output_dir),
            "plans_created": len(self.plans),
            "results": len(self.results),
            "successful": sum(1 for r in self.results if r.success),
            "failed": sum(1 for r in self.results if not r.success),
            "attack_vectors_available": [v.value for v in InjectionVector],
            "attack_templates": list(self.ATTACK_TEMPLATES.keys()),
        }


def analyze_ml_target(model_id: str, format_result: Optional[dict] = None) -> dict:
    """Convenience function to analyze an ML target."""
    injector = SupplyChainInjector(dry_run=True)
    hf_info = {"model_id": model_id, "downloads": 0, "is_safetensors": False}
    fmt_analysis = format_result or {}
    return injector.analyze_target(model_id, fmt_analysis, hf_info)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "plan":
            vector = sys.argv[2] if len(sys.argv) > 2 else "model_substitution"
            target = sys.argv[3] if len(sys.argv) > 3 else "bert-base-uncased"
            injector = SupplyChainInjector(dry_run=True)
            plan = injector.create_plan(vector, target)
            print(json.dumps(plan.to_dict(), indent=2, default=str))
        elif cmd == "execute":
            vector = sys.argv[2] if len(sys.argv) > 2 else "model_substitution"
            target = sys.argv[3] if len(sys.argv) > 3 else "bert-base-uncased"
            dry = "--live" not in sys.argv
            injector = SupplyChainInjector(dry_run=dry)
            plan = injector.create_plan(vector, target)
            result = injector.execute_plan(plan)
            print(json.dumps(result.to_dict(), indent=2, default=str))
        elif cmd == "analyze":
            target = sys.argv[2] if len(sys.argv) > 2 else "bert-base-uncased"
            analysis = analyze_ml_target(target)
            print(json.dumps(analysis, indent=2, default=str))
        elif cmd == "templates":
            print(json.dumps({k: {
                "vector": v["vector"].value if isinstance(v["vector"], InjectionVector) else str(v["vector"]),
                "description": v["description"],
                "success_rate": v["estimated_success_rate"],
            } for k, v in SupplyChainInjector.ATTACK_TEMPLATES.items()}, indent=2, default=str))
        else:
            print("Usage:")
            print("  python supply_chain_injector.py plan <vector> <target>")
            print("  python supply_chain_injector.py execute <vector> <target> [--live]")
            print("  python supply_chain_injector.py analyze <target>")
            print("  python supply_chain_injector.py templates")
    else:
        injector = SupplyChainInjector()
        print(json.dumps(injector.generate_report(), indent=2, default=str))
