#!/usr/bin/env python3
"""VulnU-Lab autonomous mode harness — runs exploit scripts through Raphael's pipeline."""
import asyncio
import json
import os
import sys
import time
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from orchestrator.brain.target_state import build_vulnu_state, list_vulnu_services, summarize_target_state
from orchestrator.audit_trail import record_event
from orchestrator.adversary_profiles import build_adversary_context
from orchestrator.evasion_techniques import select_geo_profile, build_geo_context
from orchestrator.brain.neural_memory import store_episodic, store_target_profile
from orchestrator.anti_forensics import full_cleanup_chain

EXPLOITS_DIR = os.path.dirname(os.path.abspath(__file__))

VULNU_PORTS = {
    "www": [8080],
    "www-flask": [8081, 5000],
    "ums": [8082, 5001],
    "nertu": [8083],
}

SERVICE_EXPLOITS = {
    "www": ["exploit_sqli_login.py", "exploit_sqli_search.py", "exploit_lfi.py", "exploit_upload_webshell.py"],
    "www-flask": ["exploit_sqli_login.py", "exploit_sqli_search.py", "exploit_lfi.py", "exploit_upload_webshell.py"],
    "ums": ["exploit_idor.py", "exploit_mass_assignment.py"],
    "nertu": ["exploit_jsp_sqli.py", "exploit_ghostcat.py"],
}

def check_service(ports):
    import socket
    for port in ports:
        s = socket.socket()
        s.settimeout(2)
        try:
            s.connect(("localhost", port))
            s.close()
            return port
        except Exception:
            continue
    return None

def run_exploit(script_name):
    path = os.path.join(EXPLOITS_DIR, script_name)
    if not os.path.exists(path):
        return {"script": script_name, "status": "SKIP", "stdout": "", "stderr": "not found"}
    try:
        r = subprocess.run(["python3", path], capture_output=True, text=True, timeout=30)
        return {
            "script": script_name,
            "status": "PASS" if "PASS" in r.stdout else "MIXED",
            "stdout": r.stdout,
            "stderr": r.stderr[:300] if r.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"script": script_name, "status": "TIMEOUT", "stdout": "", "stderr": "30s timeout"}
    except Exception as e:
        return {"script": script_name, "status": "ERROR", "stdout": "", "stderr": str(e)}

async def run_vulnu_autonomous():
    print("=" * 60)
    print("VulnU-Lab — Raphael 2.0 Autonomous Mode Harness")
    print("=" * 60)

    results = {
        "target": "vulnu-lab (localhost)",
        "timestamp": time.time(),
        "services": {},
        "phases": {},
        "adversary_profile": os.getenv("ADVERSARY_PROFILE", "stealth"),
    }

    adversary_ctx = build_adversary_context(results["adversary_profile"])
    geo_profile = select_geo_profile(5.5)
    geo_ctx = build_geo_context(5.5)

    record_event("engagement_start", target="vulnu-lab", phase="init", verdict="started")

    for service in list_vulnu_services():
        ports = VULNU_PORTS.get(service, [8080])
        print(f"\n{'='*60}")
        print(f"[SERVICE] {service} (ports {ports})")
        print(f"{'='*60}")

        service_state = build_vulnu_state(service)
        store_target_profile(service, {"state": service_state})
        print(summarize_target_state(service))
        print()

        found_port = check_service(ports)
        if not found_port:
            print(f"[SKIP] {service} — none of {ports} reachable. Is docker compose up?")
            results["services"][service] = {"alive": False, "exploits": []}
            record_event("phase:check", target=f"vulnu-lab:{service}", phase="recon", verdict="skip", metadata={"reason": "port_down"})
            continue

        print(f"[OK] Service is alive on port {found_port}")
        os.environ["VULNU_PORT"] = str(found_port)
        results["services"][service] = {"alive": True, "port": found_port, "exploits": []}

        record_event("phase:recon", target=f"vulnu-lab:{service}", phase="recon", verdict="pass")

        store_episodic(
            event_type="recon",
            target=f"vulnu-lab:{service}",
            model="vulnu_harness",
            context="service_check",
            input_data="",
            output_summary=f"Service {service} alive on port {found_port}, {len(SERVICE_EXPLOITS.get(service, []))} exploits to run",
            success=True,
            score=1.0,
            latency=0.0,
        )

        record_event("phase:exploit", target=f"vulnu-lab:{service}", phase="exploit", verdict="started")

        exploits = SERVICE_EXPLOITS.get(service, [])
        phase_results = []
        for script_name in exploits:
            print(f"\n  [EXPLOIT] {script_name} ... ", end="", flush=True)
            result = run_exploit(script_name)
            phase_results.append(result)

            if result["status"] == "PASS":
                print("PASS")
            elif result["status"] == "MIXED":
                print("MIXED")
            else:
                print(f"({result['status']})")

            if result["stdout"]:
                for line in result["stdout"].strip().split("\n"):
                    print(f"    {line}")

        passed = sum(1 for r in phase_results if r["status"] == "PASS")
        mixed = sum(1 for r in phase_results if r["status"] == "MIXED")
        total = len(phase_results)
        exploit_success = (passed + mixed * 0.5) / max(total, 1) > 0.5

        results["services"][service]["exploits"] = phase_results
        results["services"][service]["summary"] = f"{passed}/{total} passed, {mixed}/{total} mixed"

        store_episodic(
            event_type="exploit",
            target=f"vulnu-lab:{service}",
            model="vulnu_harness",
            context="exploit_runner",
            input_data="",
            output_summary=f"{passed}/{total} exploits passed for {service}",
            success=exploit_success,
            score=passed / max(total, 1),
            latency=0.0,
        )

        record_event("phase:exploit", target=f"vulnu-lab:{service}", phase="exploit",
                     verdict="pass" if exploit_success else "fail",
                     metadata={"passed": passed, "total": total})

        print(f"\n  [SUMMARY] {service}: {passed}/{total} passed")

    print(f"\n{'='*60}")
    print("CLEANUP — running anti-forensics chain")
    print(f"{'='*60}")
    cleanup_output = full_cleanup_chain()
    print(cleanup_output)
    results["phases"]["cleanup"] = {"model": "anti_forensics_module", "output": cleanup_output}
    record_event("phase:cleanup", target="vulnu-lab", phase="cleanup", verdict="pass")

    print(f"\n{'='*60}")
    print("FINAL SUMMARY")
    print(f"{'='*60}")
    total_exploits = 0
    total_passed = 0
    for svc, data in results["services"].items():
        status = "UP" if data.get("alive") else "DOWN"
        ex = data.get("exploits", [])
        p = sum(1 for r in ex if r["status"] == "PASS")
        t = len(ex)
        total_exploits += t
        total_passed += p
        print(f"  {svc:12s} [{status}]  {p}/{t} exploits passed")

    print(f"\n  Overall: {total_passed}/{total_exploits} exploits passed")
    results["summary"] = f"{total_passed}/{total_exploits} passed"

    output_path = os.path.join(EXPLOITS_DIR, "vulnu_results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[SAVED] Results to {output_path}")

    return results

def main():
    asyncio.run(run_vulnu_autonomous())

if __name__ == "__main__":
    main()
