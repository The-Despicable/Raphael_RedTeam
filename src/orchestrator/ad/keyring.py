import json
import os
import sqlite3
import time
from typing import Optional

DB_PATH = os.getenv("KEYRING_DB", "/data/keyring.db")


class Credential:
    def __init__(self, target: str, username: str, password: str = "",
                 hash_val: str = "", service: str = "", source: str = "",
                 cracked: bool = False):
        self.target = target
        self.username = username
        self.password = password
        self.hash = hash_val
        self.service = service
        self.source = source
        self.cracked = cracked
        self.created_at = time.time()
        self.used_count = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "username": self.username,
            "password": self.password,
            "hash": self.hash,
            "service": self.service,
            "source": self.source,
            "cracked": self.cracked,
            "created_at": self.created_at,
            "used_count": self.used_count,
        }


class Keyring:
    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT DEFAULT '',
                hash TEXT DEFAULT '',
                service TEXT DEFAULT '',
                source TEXT DEFAULT '',
                cracked INTEGER DEFAULT 0,
                created_at REAL,
                used_count INTEGER DEFAULT 0,
                UNIQUE(target, username, service)
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cracked_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id INTEGER,
                method TEXT,
                cracked_at REAL,
                FOREIGN KEY (credential_id) REFERENCES credentials(id)
            )
        """)
        self.conn.commit()

    def store(self, target: str, username: str, password: str = "",
              hash_val: str = "", service: str = "", source: str = "") -> int:
        self.conn.execute("""
            INSERT OR REPLACE INTO credentials
            (target, username, password, hash, service, source, cracked, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (target, username, password, hash_val, service, source,
              bool(password), time.time()))
        self.conn.commit()
        return self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def find(self, target: str = "", service: str = "",
             cracked_only: bool = False) -> list[Credential]:
        query = "SELECT * FROM credentials WHERE 1=1"
        params = []
        if target:
            query += " AND target = ?"
            params.append(target)
        if service:
            query += " AND service = ?"
            params.append(service)
        if cracked_only:
            query += " AND cracked = 1"
        rows = self.conn.execute(query, params).fetchall()
        return [Credential(**dict(row)) for row in rows]

    def try_against(self, cred: Credential, targets: list[str] = None) -> dict:
        from orchestrator.ad.toolkit import get_ad_toolkit
        ad = get_ad_toolkit()
        check_targets = targets or [cred.target]
        results = {}
        for t in check_targets:
            for method in ["wmiexec", "psexec"]:
                if cred.password:
                    ok = ad.wmiexec(t, cred.username, password=cred.password, command="whoami")
                    if ok:
                        results[f"{t}:{method}"] = True
                        break
        if any(results.values()):
            self.conn.execute(
                "UPDATE credentials SET used_count = used_count + 1 WHERE target=? AND username=?",
                (cred.target, cred.username)
            )
            self.conn.commit()
        return results

    def mark_cracked(self, credential_id: int, method: str = "hashcat"):
        self.conn.execute(
            "UPDATE credentials SET cracked=1 WHERE id=?",
            (credential_id,)
        )
        self.conn.execute(
            "INSERT INTO cracked_log (credential_id, method, cracked_at) VALUES (?, ?, ?)",
            (credential_id, method, time.time())
        )
        self.conn.commit()

    def get_cracked_log(self) -> list[dict]:
        rows = self.conn.execute("""
            SELECT c.target, c.username, c.service, c.password,
                   cl.method, cl.cracked_at
            FROM cracked_log cl
            JOIN credentials c ON c.id = cl.credential_id
            ORDER BY cl.cracked_at DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def search(self, query: str) -> list[Credential]:
        rows = self.conn.execute(
            "SELECT * FROM credentials WHERE username LIKE ? OR password LIKE ? OR target LIKE ?",
            (f"%{query}%", f"%{query}%", f"%{query}%")
        ).fetchall()
        return [Credential(**dict(r)) for r in rows]


_keyring: Optional[Keyring] = None


def get_keyring() -> Keyring:
    global _keyring
    if _keyring is None:
        _keyring = Keyring()
    return _keyring
