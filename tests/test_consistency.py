"""Structural invariants — delegates to scripts/check_consistency.py."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_consistency_rules_pass():
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "check_consistency.py")],
        capture_output=True, text=True, cwd=REPO, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ALL CHECKS PASSED" in proc.stdout


def test_env_has_no_literal_ports():
    text = (REPO / "env.sh").read_text()
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        assert "3900" not in line and "3800" not in line and "3201" not in line


def test_services_json_matches_ports():
    import json
    data = json.loads((REPO / "configs" / "services.json").read_text())
    ports = {s["name"]: s["port"] for s in data["services"]}
    assert ports["cai-service"] == 3201
    assert ports["cloak-service"] == 3401
    assert ports["mhddos-service"] == 3301
    assert ports["kali-tools"] == 3800
    assert ports["raphael-api"] == 3900
