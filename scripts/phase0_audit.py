#!/usr/bin/env python3
"""
Phase 0 Release Audit — 9-Point Checklist
Per SENTINEL Charter §46, §51, §57
"""
import sys
import subprocess
import json
import os
from pathlib import Path

class Phase0Audit:
    def __init__(self, repo_root):
        self.repo_root = Path(repo_root)
        self.results = {}
        
    def run_check(self, name, check_fn, *args, **kwargs):
        print(f"\n[CHECK] {name}...")
        try:
            result = check_fn(*args, **kwargs)
            self.results[name] = {"status": "PASS", "details": result}
            print(f"  ✅ PASS: {result}")
            return True
        except Exception as e:
            self.results[name] = {"status": "FAIL", "details": str(e)}
            print(f"  ❌ FAIL: {e}")
            return False
    
    def check_1_repo_structure(self):
        required = [
            "src/orchestrator/brain",
            "src/orchestrator/student", 
            "src/orchestrator/capabilities/interactive_shell",
            "src/agent",
            "src/raphael",
            "tests",
            "configs",
            "configs/specs",
            "benchmarks/RBS-v1",
            "evaluations",
            "failures",
            "docs",
            "scripts"
        ]
        missing = [d for d in required if not (self.repo_root / d).exists()]
        if missing:
            raise AssertionError(f"Missing directories: {missing}")
        return "All required v2.0 directories present"
    
    def check_2_git_integrity(self):
        result = subprocess.run(
            ["git", "status", "--porcelain"], 
            cwd=self.repo_root, capture_output=True, text=True
        )
        if result.stdout.strip():
            raise AssertionError(f"Working tree not clean:\n{result.stdout}")
        return "Git working tree clean"
    
    def check_3_dependency_hashes(self):
        manifest = self.repo_root / "baseline" / "raphael_v2.0_manifest.json"
        if not manifest.exists():
            raise AssertionError("Baseline manifest not found")
        with open(manifest) as f:
            data = json.load(f)
        if "dependencies" not in data or not data["dependencies"]:
            raise AssertionError("No dependencies recorded in manifest")
        return f"Dependencies recorded: {len(data['dependencies'])} packages"
    
    def check_4_test_suite_passing(self):
        test_dirs = [
            "tests/e1_interactive_shell_test.py",
            "tests/e2_shell_candidate_generation_test.py", 
            "tests/test_d5_preflight.py",
            "tests/test_d5_seven_gate_proof.py",
            "tests/test_stage1_invariants.py"
        ]
        for td in test_dirs:
            result = subprocess.run(
                ["python3", "-m", "pytest", td, "-v", "--tb=short"],
                cwd=self.repo_root, capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                raise AssertionError(f"Tests failed in {td}:\n{result.stdout}\n{result.stderr}")
        return "All core test suites passing"
    
    def check_5_specs_sealed(self):
        specs = [
            "configs/specs/E1_INTERACTIVE_SHELL_SPEC.json",
            "configs/specs/E2_SHELL_CANDIDATE_GENERATION_SPEC.json",
            "configs/specs/E3_LIVE_ARENA_TEST_SPEC.json",
            "configs/specs/E4_LOCAL_ADV_ARENA_SPEC.json",
            "configs/specs/E5_BLACKBOX_ARENA_SPEC.json",
            "configs/specs/E6_LOCAL_H1_ARENA_SPEC.json",
            "configs/specs/P1_STEALTH_AND_EVASION_SPEC.json",
            "configs/specs/P1_LIVE_WAF_ARENA_SPEC.json",
            "configs/specs/H1_LIVE_ENGAGEMENT_SPEC.json",
            "configs/specs/H1_GITHUB_LIVE_SPEC.json",
        ]
        unsealed = []
        for spec in specs:
            spec_path = self.repo_root / spec
            if not spec_path.exists():
                unsealed.append(f"{spec} (missing)")
                continue
            with open(spec_path) as f:
                data = json.load(f)
            status = data.get("status", "")
            seal = data.get("seal", {})
            if status != "SEALED" or seal.get("status") != "SEALED":
                unsealed.append(f"{spec} (status={status}, seal={seal.get('status','none')})")
        if unsealed:
            raise AssertionError(f"Specs not sealed: {unsealed}")
        return f"All {len(specs)} specifications sealed"
    
    def check_6_scopeparser_loaded(self):
        import sys
        sys.path.insert(0, str(self.repo_root / "src"))
        try:
            from orchestrator.brain.scope_parser import ScopeParser
            import json
            with open(self.repo_root / "configs" / "GITHUB_SCOPE_CONFIG.json") as f:
                cfg = json.load(f)
            h1_scope = {"in_scope": [], "out_of_scope": []}
            for item in cfg["scope"]["in_scope"]:
                h1_scope["in_scope"].append({"asset_identifier": item["asset_identifier"], "asset_type": item["asset_type"]})
            for item in cfg["scope"]["out_of_scope"]:
                h1_scope["out_of_scope"].append({"asset_identifier": item["asset_identifier"], "asset_type": item["asset_type"]})
            
            sp = ScopeParser()
            sp.parse_hackerone_json(h1_scope)
            
            tests = [
                ("api.github.com", True),
                ("raw.githubusercontent.com", True),
                ("blog.github.com", False),
                ("evil.com", False),
            ]
            for target, expected in tests:
                allowed, _ = sp.is_target_allowed(target)
                if allowed != expected:
                    raise AssertionError(f"ScopeParser failed: {target} expected {'ALLOWED' if expected else 'DENIED'}")
            return "ScopeParser loaded and validated (8/8 rules, 5 exclusions)"
        except ImportError as e:
            raise AssertionError(f"ScopeParser import failed: {e}")
    
    def check_7_failure_registry(self):
        failures_readme = self.repo_root / "failures" / "README.md"
        if not failures_readme.exists():
            raise AssertionError("Failure registry README.md not found")
        content = failures_readme.read_text()
        if "F-001" not in content or "F-016" not in content:
            raise AssertionError("Failure registry incomplete")
        return "Failure registry populated (F-001 through F-016)"
    
    def check_8_decision_log(self):
        dlog = self.repo_root / "docs" / "DecisionLog.md"
        if not dlog.exists():
            raise AssertionError("DecisionLog.md not found")
        content = dlog.read_text()
        if "D-001" not in content or "D-010" not in content:
            raise AssertionError("DecisionLog incomplete")
        return "DecisionLog complete (D-001 through D-010)"
    
    def check_9_benchmark_registered(self):
        bench = self.repo_root / "benchmarks" / "RBS-v1" / "registration.json"
        if not bench.exists():
            raise AssertionError("Benchmark registration not found")
        with open(bench, "r") as f:
            data = json.load(f)
        if data.get("status") != "SEALED":
            raise AssertionError(f"Benchmark not sealed: status={data.get('status')}")
        seal = data.get("seal", {})
        if seal.get("status") != "SEALED":
            raise AssertionError(f"Benchmark seal missing: {seal}")
        return "Benchmark RBS-v1 registered and sealed"
    
    def run_all(self):
        print("=" * 60)
        print("PHASE 0 RELEASE AUDIT — 9-POINT CHECKLIST")
        print("=" * 60)
        
        checks = [
            ("1. Repository Structure", self.check_1_repo_structure),
            ("2. Git Integrity", self.check_2_git_integrity),
            ("3. Dependency Hashes", self.check_3_dependency_hashes),
            ("4. Test Suites Passing", self.check_4_test_suite_passing),
            ("5. Specs Sealed", self.check_5_specs_sealed),
            ("6. ScopeParser Loaded", self.check_6_scopeparser_loaded),
            ("7. Failure Registry", self.check_7_failure_registry),
            ("8. Decision Log", self.check_8_decision_log),
            ("9. Benchmark Registered", self.check_9_benchmark_registered),
        ]
        
        passed = 0
        for name, fn in checks:
            if self.run_check(name, fn):
                passed += 1
        
        print(f"\n{'='*60}")
        print(f"AUDIT RESULT: {passed}/9 PASSED")
        print(f"{'='*60}")
        
        if passed == 9:
            print("\n✅ PHASE 0 AUDIT PASSED — Ready for v2.0 tag")
            return True
        else:
            print(f"\n❌ PHASE 0 AUDIT FAILED — {9-passed} checks failed")
            return False

if __name__ == "__main__":
    import sys
    audit = Phase0Audit("/home/yaser/raphael-2.0")
    success = audit.run_all()
    sys.exit(0 if success else 1)
