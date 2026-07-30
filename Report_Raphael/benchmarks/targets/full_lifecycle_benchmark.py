import asyncio
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("benchmark_runner")


class BenchmarkRunner:
    """Runs full-lifecycle autonomous pentesting benchmarks against
    configured target definitions.

    Each target is a JSON file in targets/ with phase_requirements,
    known_vulnerabilities, and optional flag values.
    """

    def __init__(self, targets_dir: str = None):
        self.targets_dir = Path(targets_dir or
                                 os.getenv("BENCHMARK_TARGETS_DIR",
                                           str(Path(__file__).parent / "targets")))
        self._results = []

    def list_targets(self) -> list[dict]:
        """List all available benchmark targets."""
        targets = []
        if not self.targets_dir.exists():
            return targets
        for fpath in sorted(self.targets_dir.glob("*.json")):
            try:
                data = json.loads(fpath.read_text())
                targets.append({
                    "file": fpath.name,
                    "name": data.get("name", fpath.stem),
                    "difficulty": data.get("difficulty", "unknown"),
                    "phases": data.get("phase_requirements", []),
                    "flags_known": bool(data.get("flags", {}).get("user")) or bool(data.get("flags", {}).get("root")),
                })
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Skipping {fpath.name}: {e}")
        return targets

    async def run_target(self, target_name: str) -> dict:
        """Run a benchmark against a single target."""
        fpath = self.targets_dir / f"{target_name}.json"
        if not fpath.exists():
            # Try matching by name field in files
            for candidate in self.targets_dir.glob("*.json"):
                data = json.loads(candidate.read_text())
                if data.get("name") == target_name:
                    fpath = candidate
                    break
            else:
                return {
                    "target": target_name,
                    "error": f"No target file found for '{target_name}'",
                    "success": False,
                    "total_time": 0,
                }

        config = json.loads(fpath.read_text())
        skip_reason = config.get("skip_reason", "")
        if skip_reason:
            return {
                "target": config["name"],
                "config": config,
                "error": f"Skipped: {skip_reason}",
                "success": False,
                "total_time": 0,
                "skipped": True,
            }

        phases = config.get("phase_requirements", [])
        logger.info(f"Benchmark: running {config['name']} "
                     f"({len(phases)} phases: {', '.join(phases)})")

        t0 = time.time()
        try:
            from orchestrator.modes.autonomous import handle

            result = await handle(config.get("url", config["name"]), phases=phases)
        except Exception as e:
            logger.error(f"Benchmark error for {config['name']}: {e}")
            return {
                "target": config["name"],
                "config": config,
                "error": str(e),
                "success": False,
                "total_time": time.time() - t0,
            }

        total_time = time.time() - t0
        total_findings = result.get("total_findings", 0)

        # Check flag capture
        flags = result.get("flags", {})
        user_flag_captured = bool(flags.get("user_flag_found"))
        root_flag_captured = bool(flags.get("root_flag_found"))
        expected_user = config.get("flags", {}).get("user", "")
        expected_root = config.get("flags", {}).get("root", "")

        user_match = False
        root_match = False
        if expected_user and user_flag_captured:
            actual = flags.get("user_flag", "")
            user_match = actual == expected_user or expected_user in actual
        if expected_root and root_flag_captured:
            actual = flags.get("root_flag", "")
            root_match = actual == expected_root or expected_root in actual

        success = total_findings > 0 or user_flag_captured or root_flag_captured

        entry = {
            "target": config["name"],
            "config": config,
            "success": success,
            "total_time": round(total_time, 1),
            "total_findings": total_findings,
            "phases_completed": list(result.get("phases", {}).keys()),
            "flags": {
                "user_flag_captured": user_flag_captured,
                "root_flag_captured": root_flag_captured,
                "user_flag_match": user_match,
                "root_flag_match": root_match,
            },
            "errors": [
                p.get("error") for p in result.get("phases", {}).values()
                if p.get("error")
            ],
            "memory_episodes": result.get("memory", {}).get("episodes_retrieved", 0),
        }
        self._results.append(entry)
        return entry

    async def run_all(self) -> dict:
        """Run benchmarks against all configured targets."""
        targets = self.list_targets()
        if not targets:
            return {
                "error": "No benchmark targets found",
                "targets_dir": str(self.targets_dir),
                "results": [],
            }

        results = []
        for t in targets:
            entry = await self.run_target(t["name"])
            results.append(entry)

        passed = sum(1 for r in results if r.get("success"))
        failed = sum(1 for r in results if not r.get("success"))

        return {
            "benchmark_timestamp": datetime.utcnow().isoformat(),
            "total_targets": len(targets),
            "passed": passed,
            "failed": failed,
            "pass_rate": round(passed / len(targets), 2) if targets else 0.0,
            "results": results,
        }
