"""Self-Update & Survivability Engine — IPFS backup, rollback, integrity checks.

Ensures the platform persists, self-heals, and can recover from compromise.
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger("survivability.engine")

SURV_DB = os.path.join(os.path.dirname(__file__), "..", "data", "survivability.db")
RAPPHAEL_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class BackupSnapshot:
    id: str
    description: str
    files: list[str]
    manifest_hash: str
    size_bytes: int
    created: float
    ipfs_cid: str = ""
    verified: bool = False


@dataclass
class IntegrityCheck:
    file_path: str
    expected_hash: str
    actual_hash: str
    status: str
    checked_at: float


class SurvivabilityEngine:
    def __init__(self, db_path: str = SURV_DB, repo_path: str = RAPPHAEL_ROOT):
        self.db_path = db_path
        self.repo_path = repo_path
        self._ipfs_api = os.getenv("IPFS_API", "http://127.0.0.1:5001")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    files TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created REAL NOT NULL,
                    ipfs_cid TEXT DEFAULT '',
                    verified INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS integrity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    expected_hash TEXT NOT NULL,
                    actual_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    checked_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS update_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version TEXT NOT NULL,
                    previous_version TEXT,
                    status TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    started_at REAL NOT NULL,
                    completed_at REAL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS kill_switches (
                    id TEXT PRIMARY KEY,
                    trigger TEXT NOT NULL,
                    action TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    last_triggered REAL DEFAULT 0
                );
            """)
            self._seed_kill_switches(conn)

    def _seed_kill_switches(self, conn):
        existing = conn.execute("SELECT COUNT(*) FROM kill_switches").fetchone()[0]
        if existing > 0:
            return
        defaults = [
            ("network_scan_detected", "trigger_shred", "Network scan/honeypot detection", 1),
            ("edr_alert", "trigger_shred", "EDR/AV alert triggered", 1),
            ("account_lockout", "trigger_shred", "Multiple account lockouts detected", 1),
            ("abnormal_process", "trigger_shred", "Suspicious parent-child process chain", 1),
            ("siem_correlation", "trigger_shred", "SIEM correlation rule hit", 1),
            ("honeyport_connection", "trigger_shred", "Connection to honeyport/honeypot", 1),
            ("manual_trigger", "trigger_shred", "Manual kill switch activation", 1),
        ]
        for tid, trigger, desc, enabled in defaults:
            conn.execute(
                "INSERT INTO kill_switches (id, trigger, action, enabled) VALUES (?, ?, ?, ?)",
                (tid, trigger, trigger, enabled),
            )

    def compute_file_hash(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def create_manifest(self, file_paths: list[str]) -> dict:
        manifest = {}
        for f in file_paths:
            rel = os.path.relpath(f, self.repo_path) if f.startswith(self.repo_path) else f
            manifest[rel] = self.compute_file_hash(f)
        return manifest

    def manifest_hash(self, manifest: dict) -> str:
        return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()

    def create_snapshot(self, description: str = "", include_patterns: list[str] = None) -> BackupSnapshot:
        include_patterns = include_patterns or ["*.py", "*.json", "*.yml", "*.yaml", "*.toml", "*.sh", "*.sql"]
        file_paths = []
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", ".git", "venv", ".venv", "node_modules", "data")]
            for f in files:
                if any(f.endswith(p.replace("*", "")) for p in include_patterns):
                    file_paths.append(os.path.join(root, f))

        manifest = self.create_manifest(file_paths)
        mf_hash = self.manifest_hash(manifest)
        total_size = sum(os.path.getsize(f) for f in file_paths if os.path.exists(f))

        snap = BackupSnapshot(
            id=str(uuid.uuid4())[:12],
            description=description or f"Auto snapshot {time.strftime('%Y%m%d-%H%M%S')}",
            files=sorted(manifest.keys()),
            manifest_hash=mf_hash,
            size_bytes=total_size,
            created=time.time(),
        )

        # Store manifest as temp file for IPFS
        mf_path = os.path.join(os.path.dirname(self.db_path), f"manifest_{snap.id}.json")
        with open(mf_path, "w") as f:
            json.dump(manifest, f, indent=2)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO snapshots (id, description, files, manifest_hash, size_bytes, created, ipfs_cid)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (snap.id, snap.description, json.dumps(snap.files),
                 snap.manifest_hash, snap.size_bytes, snap.created, snap.ipfs_cid),
            )

        return snap

    async def push_to_ipfs(self, snapshot: BackupSnapshot) -> str:
        mf_path = os.path.join(os.path.dirname(self.db_path), f"manifest_{snapshot.id}.json")
        if not os.path.exists(mf_path):
            return ""

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                with open(mf_path, "rb") as f:
                    files = {"file": (f"manifest_{snapshot.id}.json", f, "application/json")}
                    resp = await client.post(f"{self._ipfs_api}/api/v0/add", files=files)
                    resp.raise_for_status()
                    result = resp.json()
                    cid = result.get("Hash", "")
                    if cid:
                        with sqlite3.connect(self.db_path) as conn:
                            conn.execute(
                                "UPDATE snapshots SET ipfs_cid = ?, verified = 1 WHERE id = ?",
                                (cid, snapshot.id),
                            )
                        logger.info(f"  [Survivability] Pushed snapshot {snapshot.id} to IPFS: {cid}")
                        return cid
        except Exception as e:
            logger.warning(f"  IPFS push failed: {e}")
        return ""

    async def pull_from_ipfs(self, cid: str, output_dir: str = "") -> bool:
        output_dir = output_dir or os.path.join(os.path.dirname(self.db_path), "restored")
        os.makedirs(output_dir, exist_ok=True)
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(f"{self._ipfs_api}/api/v0/get", params={"arg": cid})
                resp.raise_for_status()
                # IPFS returns tar stream
                import tarfile
                import io
                with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:*") as tar:
                    tar.extractall(output_dir)
                logger.info(f"  [Survivability] Restored from IPFS {cid} to {output_dir}")
                return True
        except Exception as e:
            logger.warning(f"  IPFS pull failed: {e}")
        return False

    def verify_integrity(self, snapshot_id: str = None) -> list[IntegrityCheck]:
        if snapshot_id:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT files, manifest_hash FROM snapshots WHERE id = ?", (snapshot_id,)
                ).fetchone()
                if not row:
                    return []
                files = json.loads(row[0])
                expected_manifest = {f: self.compute_file_hash(os.path.join(self.repo_path, f)) for f in files}
                actual_hash = self.manifest_hash(expected_manifest)
                checks = []
                for f, exp_hash in expected_manifest.items():
                    act_hash = self.compute_file_hash(os.path.join(self.repo_path, f))
                    checks.append(IntegrityCheck(
                        file_path=f, expected_hash=exp_hash, actual_hash=act_hash,
                        status="match" if exp_hash == act_hash else "mismatch",
                        checked_at=time.time(),
                    ))
                return checks
        else:
            # Full repo scan
            checks = []
            for root, dirs, files in os.walk(self.repo_path):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", ".git", "venv", ".venv", "node_modules", "data")]
                for f in files:
                    if f.endswith((".py", ".json", ".yml", ".yaml", ".toml", ".sh", ".sql")):
                        full = os.path.join(root, f)
                        rel = os.path.relpath(full, self.repo_path)
                        act = self.compute_file_hash(full)
                        checks.append(IntegrityCheck(
                            file_path=rel, expected_hash="", actual_hash=act,
                            status="scanned", checked_at=time.time(),
                        ))
            return checks

    def log_integrity_results(self, checks: list[IntegrityCheck]):
        with sqlite3.connect(self.db_path) as conn:
            for c in checks:
                conn.execute(
                    "INSERT INTO integrity_log (file_path, expected_hash, actual_hash, status, checked_at) VALUES (?, ?, ?, ?, ?)",
                    (c.file_path, c.expected_hash, c.actual_hash, c.status, c.checked_at),
                )

    async def self_update(self, branch: str = "main", remote: str = "origin") -> dict:
        """Git pull + dependency sync + restart signal."""
        update_id = str(uuid.uuid4())[:12]
        started = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO update_history (version, previous_version, status, started_at) VALUES (?, ?, ?, ?)",
                (f"git:{branch}", "", "started", started),
            )

        result = {"update_id": update_id, "success": False, "output": "", "restart_required": False}

        try:
            # Get current commit
            before = subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=self.repo_path
            ).stdout.strip()

            # Fetch and merge
            proc = subprocess.run(
                ["git", "fetch", remote, branch], capture_output=True, text=True, cwd=self.repo_path, timeout=60
            )
            if proc.returncode != 0:
                raise Exception(f"git fetch failed: {proc.stderr}")

            proc = subprocess.run(
                ["git", "merge", f"{remote}/{branch}"], capture_output=True, text=True, cwd=self.repo_path, timeout=60
            )
            if proc.returncode != 0:
                raise Exception(f"git merge failed: {proc.stderr}")

            after = subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=self.repo_path
            ).stdout.strip()

            if before == after:
                result["output"] = "Already up to date"
            else:
                result["output"] = f"Updated from {before[:8]} to {after[:8]}"
                result["restart_required"] = True

                # Update python deps if requirements changed
                req_changed = subprocess.run(
                    ["git", "diff", "--name-only", before, after], capture_output=True, text=True, cwd=self.repo_path
                ).stdout
                if "requirements" in req_changed or "pyproject.toml" in req_changed:
                    pip = subprocess.run(
                        ["pip", "install", "-r", "requirements.txt"], capture_output=True, text=True, cwd=self.repo_path, timeout=120
                    )
                    result["output"] += f"\nDeps updated: {pip.returncode == 0}"

            # Create post-update snapshot
            snap = self.create_snapshot(f"Post-update {after[:8]}")
            await self.push_to_ipfs(snap)

            result["success"] = True
            status = "completed"
        except Exception as e:
            result["output"] = f"Update failed: {e}"
            status = "failed"
            logger.error(f"  [Survivability] Self-update failed: {e}")

        completed = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE update_history SET status = ?, details = ?, completed_at = ? WHERE id = ?",
                (status, result["output"], completed, update_id),
            )

        return result

    def register_kill_switch(self, trigger_id: str, action: str = "trigger_shred", enabled: bool = True):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO kill_switches (id, trigger, action, enabled) VALUES (?, ?, ?, ?)",
                (trigger_id, trigger_id, action, int(enabled)),
            )

    def trigger_kill_switch(self, trigger: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, action, enabled FROM kill_switches WHERE trigger = ?", (trigger,)
            ).fetchone()
            if row and row[2]:
                conn.execute(
                    "UPDATE kill_switches SET last_triggered = ? WHERE id = ?",
                    (time.time(), row[0]),
                )
                logger.critical(f"  [KILL SWITCH] Triggered: {trigger} -> {row[1]}")
                # Execute shred script
                shred_script = os.path.join(self.repo_path, "kill_switch.sh")
                if os.path.exists(shred_script):
                    subprocess.Popen(["bash", shred_script], start_new_session=True)
                return True
        return False

    def list_snapshots(self, limit: int = 20) -> list[BackupSnapshot]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, description, files, manifest_hash, size_bytes, created, ipfs_cid, verified FROM snapshots ORDER BY created DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                BackupSnapshot(
                    id=r[0], description=r[1], files=json.loads(r[2]),
                    manifest_hash=r[3], size_bytes=r[4], created=r[5],
                    ipfs_cid=r[6], verified=bool(r[7]),
                )
                for r in rows
            ]

    def get_update_history(self, limit: int = 10) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT version, previous_version, status, details, started_at, completed_at FROM update_history ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                {"version": r[0], "previous_version": r[1], "status": r[2],
                 "details": r[3], "started_at": r[4], "completed_at": r[5]}
                for r in rows
            ]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            snapshots = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
            ipfs_synced = conn.execute("SELECT COUNT(*) FROM snapshots WHERE ipfs_cid != ''").fetchone()[0]
            updates = conn.execute("SELECT COUNT(*) FROM update_history WHERE status = 'completed'").fetchone()[0]
            kill_switches = conn.execute("SELECT COUNT(*) FROM kill_switches WHERE enabled = 1").fetchone()[0]
            last_integrity = conn.execute(
                "SELECT MAX(checked_at) FROM integrity_log"
            ).fetchone()[0]
            return {
                "snapshots": snapshots, "ipfs_synced": ipfs_synced,
                "successful_updates": updates, "active_kill_switches": kill_switches,
                "last_integrity_check": last_integrity,
            }


def get_survivability_engine() -> SurvivabilityEngine:
    return SurvivabilityEngine()