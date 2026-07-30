"""
ML Model Format Analyzer (P1 - FORGE Phase 1)

Analyzes ML model file formats to identify attack surface:
- Pickle (.pkl, .pt, .joblib) — unsafe deserialization risk
- SafeTensors (.safetensors) — metadata injection surface
- ONNX (.onnx) — external data loading
- TensorFlow (.pb, .h5) — SavedModel injection
- GGML/GGUF (.bin, .gguf) — llama.cpp quantized models
- PyTorch JIT (.pt, .pth) — TorchScript code execution
- Keras (.keras, .h5) — Lambda layer injection
"""

from __future__ import annotations

import io
import os
import re
import json
import struct
import hashlib
import logging
import zipfile
import tempfile
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

_HAS_NUMPY = True
try:
    import numpy as np
except ImportError:
    _HAS_NUMPY = False

_HAS_PICKLE = True
try:
    import pickle
except ImportError:
    _HAS_PICKLE = False


class ModelFormat(Enum):
    """Supported ML model formats."""
    PICKLE = "pickle"
    TORCH = "torch"
    TORCH_JIT = "torch_jit"
    SAFETENSORS = "safetensors"
    ONNX = "onnx"
    TENSORFLOW = "tensorflow"
    TENSORFLOW_LITE = "tflite"
    KERAS = "keras"
    JOBLIB = "joblib"
    GGML = "ggml"
    GGUF = "gguf"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk level associated with a format/operation."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


# Magic bytes for format detection
MAGIC_BYTES: dict[bytes, ModelFormat] = {
    b"\x80\x02": ModelFormat.PICKLE,  # pickle protocol 2
    b"\x80\x03": ModelFormat.PICKLE,  # pickle protocol 3
    b"\x80\x04": ModelFormat.PICKLE,  # pickle protocol 4
    b"\x80\x05": ModelFormat.PICKLE,  # pickle protocol 5
    b"\x89PNG": ModelFormat.TORCH_JIT,  # TorchScript zip/PNG header
    b"PK\x03\x04": ModelFormat.TENSORFLOW,  # ZIP-based formats (TF, Keras)
    b"ONNX": ModelFormat.ONNX,  # ONNX proto format (at offset)
    b"\x08\x01\x12\x04": ModelFormat.TENSORFLOW_LITE,  # TFLite flatbuffer
    b"ggml": ModelFormat.GGML,
    b"GGUF": ModelFormat.GGUF,
}

# File extension to format mapping
EXTENSION_MAP: dict[str, ModelFormat] = {
    ".pkl": ModelFormat.PICKLE,
    ".pickle": ModelFormat.PICKLE,
    ".pt": ModelFormat.TORCH,
    ".pth": ModelFormat.TORCH,
    ".torch": ModelFormat.TORCH,
    ".safetensors": ModelFormat.SAFETENSORS,
    ".onnx": ModelFormat.ONNX,
    ".pb": ModelFormat.TENSORFLOW,
    ".h5": ModelFormat.KERAS,
    ".keras": ModelFormat.KERAS,
    ".tflite": ModelFormat.TENSORFLOW_LITE,
    ".lite": ModelFormat.TENSORFLOW_LITE,
    ".joblib": ModelFormat.JOBLIB,
    ".bin": ModelFormat.GGML,
    ".gguf": ModelFormat.GGUF,
    ".ggml": ModelFormat.GGML,
}

# Risk scores for each format (0-10, higher = more dangerous)
FORMAT_RISK: dict[ModelFormat, tuple[RiskLevel, str]] = {
    ModelFormat.PICKLE: (RiskLevel.CRITICAL, "Arbitrary code execution via __reduce__ on deserialization"),
    ModelFormat.TORCH: (RiskLevel.CRITICAL, "PyTorch models use pickle internally — same RCE risk"),
    ModelFormat.TORCH_JIT: (RiskLevel.HIGH, "TorchScript can contain embedded Python code execution"),
    ModelFormat.SAFETENSORS: (RiskLevel.MEDIUM, "No code execution in tensor data, but metadata field allows payload embedding"),
    ModelFormat.ONNX: (RiskLevel.MEDIUM, "External data loading and custom operator execution"),
    ModelFormat.TENSORFLOW: (RiskLevel.HIGH, "SavedModel can contain Lambda layers with arbitrary Python"),
    ModelFormat.KERAS: (RiskLevel.HIGH, "Keras Lambda layers allow arbitrary Python execution"),
    ModelFormat.JOBLIB: (RiskLevel.CRITICAL, "Joblib uses numpy/pickle internally — same RCE risk"),
    ModelFormat.GGML: (RiskLevel.LOW, "Quantized models — limited attack surface (buffer overflows possible)"),
    ModelFormat.GGUF: (RiskLevel.LOW, "GGUF format — metadata injection possible but no code exec"),
    ModelFormat.TENSORFLOW_LITE: (RiskLevel.LOW, "TFLite format — limited attack surface"),
    ModelFormat.UNKNOWN: (RiskLevel.MEDIUM, "Unknown format — requires manual analysis"),
}

# Pickle opcodes considered dangerous
DANGEROUS_PICKLE_OPCODES = {
    b"\x85": "REDUCE",        # REDUCE — calls callable with args
    b"\x28": "INST",          # INST — instantiate class
    b"\x29": "OBJ",           # OBJ — build object
    b"\x8a": "STACK_GLOBAL",  # STACK_GLOBAL — import global
    b"\x30": "GLOBAL",        # GLOBAL — push global
    b"\x31": "STACK_GLOBAL",  # STACK_GLOBAL — push global from stack
    b"\x2a": "NEWOBJ",        # NEWOBJ — instantiate class
    b"\x2b": "NEWOBJ_EX",     # NEWOBJ_EX — instantiate with kwargs
    b"\x15": "BUILD",         # BUILD — update object
}


@dataclass
class ModelFile:
    """Analysis result for an ML model file."""
    path: str
    format: ModelFormat
    risk: RiskLevel
    risk_score: float
    risk_description: str
    file_size: int
    sha256: str
    has_dangerous_ops: bool = False
    dangerous_ops: list[dict] = field(default_factory=list)
    embedded_modules: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    num_tensors: int = 0
    has_external_data: bool = False
    has_custom_code: bool = False
    is_signed: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format.value,
            "risk": self.risk.value,
            "risk_score": self.risk_score,
            "risk_description": self.risk_description,
            "file_size": self.file_size,
            "size_mb": round(self.file_size / (1024 * 1024), 2),
            "sha256": self.sha256,
            "has_dangerous_ops": self.has_dangerous_ops,
            "dangerous_ops": self.dangerous_ops,
            "embedded_modules": self.embedded_modules,
            "num_tensors": self.num_tensors,
            "has_external_data": self.has_external_data,
            "has_custom_code": self.has_custom_code,
            "is_signed": self.is_signed,
            "warnings": self.warnings,
        }


class ModelFormatAnalyzer:
    """Analyzes ML model files to identify format, risk, and attack surface.

    FORGE Rule 3 (import map): numpy/pickle imports are guarded.
    FORGE Rule 5 (shellcode): analysis only, no execution.
    """

    def __init__(self, scan_depth: str = "full"):
        self.scan_depth = scan_depth  # "quick", "full", "deep"
        self._scan_results: list[ModelFile] = []

    def analyze_file(self, path: str | Path) -> ModelFile:
        """Analyze a single model file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        file_size = path.stat().st_size
        sha256 = self._compute_hash(path)

        # Detect format
        fmt = self._detect_format(path)
        risk, risk_desc = FORMAT_RISK.get(fmt, (RiskLevel.UNKNOWN, "Unknown format"))

        result = ModelFile(
            path=str(path),
            format=fmt,
            risk=risk,
            risk_score=self._risk_to_score(risk),
            risk_description=risk_desc,
            file_size=file_size,
            sha256=sha256,
        )

        # Deep analysis based on format
        try:
            if fmt == ModelFormat.PICKLE or fmt == ModelFormat.TORCH or fmt == ModelFormat.JOBLIB:
                result = self._analyze_pickle(path, result)
            elif fmt == ModelFormat.SAFETENSORS:
                result = self._analyze_safetensors(path, result)
            elif fmt == ModelFormat.ONNX:
                result = self._analyze_onnx(path, result)
            elif fmt == ModelFormat.TENSORFLOW or fmt == ModelFormat.KERAS:
                result = self._analyze_zip_model(path, result)
            elif fmt in (ModelFormat.GGML, ModelFormat.GGUF):
                result = self._analyze_ggml(path, result)
        except Exception as e:
            logger.warning(f"Deep analysis failed for {path}: {e}")
            result.warnings.append(f"Analysis error: {e}")

        self._scan_results.append(result)
        return result

    def analyze_directory(self, path: str | Path, recursive: bool = True) -> list[ModelFile]:
        """Analyze all model files in a directory."""
        path = Path(path)
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        results = []
        pattern = "**/*" if recursive else "*"
        for f in path.glob(pattern):
            if not f.is_file():
                continue
            ext = f.suffix.lower()
            if ext in EXTENSION_MAP or self._has_magic_bytes(f):
                try:
                    results.append(self.analyze_file(f))
                except Exception as e:
                    logger.warning(f"Failed to analyze {f}: {e}")

        return results

    def _detect_format(self, path: Path) -> ModelFormat:
        """Detect model format from magic bytes and file extension."""
        ext = path.suffix.lower()
        if ext in EXTENSION_MAP:
            return EXTENSION_MAP[ext]

        # Try magic bytes
        try:
            with open(path, "rb") as f:
                header = f.read(8)

            for magic, fmt in MAGIC_BYTES.items():
                if header.startswith(magic):
                    return fmt

            # ONNX detection (starts with protobuf magic at variable offset)
            if b"onnx" in header.lower():
                return ModelFormat.ONNX
        except (IOError, OSError):
            pass

        return ModelFormat.UNKNOWN

    def _has_magic_bytes(self, path: Path) -> bool:
        """Quick check if file has known magic bytes."""
        try:
            with open(path, "rb") as f:
                header = f.read(8)
            for magic in MAGIC_BYTES:
                if header.startswith(magic):
                    return True
            return False
        except (IOError, OSError):
            return False

    def _compute_hash(self, path: Path) -> str:
        """Compute SHA-256 hash of the file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _analyze_pickle(self, path: Path, result: ModelFile) -> ModelFile:
        """Deep analysis of pickle-based model files."""
        if not _HAS_PICKLE:
            result.warnings.append("pickle module not available — limited analysis")
            return result

        try:
            data = path.read_bytes()

            # Scan for dangerous opcodes
            dangerous_found = []
            for op_byte, op_name in DANGEROUS_PICKLE_OPCODES.items():
                if op_byte in data:
                    dangerous_found.append({"opcode": op_name, "hex": op_byte.hex()})
                    result.has_dangerous_ops = True

            # Count occurrences of REDUCE opcode
            reduce_count = data.count(b"\x85")
            if reduce_count > 0:
                dangerous_found.append({"opcode": f"REDUCE (×{reduce_count})", "severity": "HIGH"})

            result.dangerous_ops = dangerous_found

            # Scan for embedded module references
            module_pattern = re.compile(rb"__import__\('(\w+)'\)|import\s+(\w+)")
            for match in module_pattern.finditer(data):
                module = (match.group(1) or match.group(2)).decode()
                if module not in ("os", "sys", "subprocess", "socket", "urllib", "pickle", "json"):
                    result.embedded_modules.append(module)

            # Check for __reduce__ in string form
            if b"__reduce__" in data:
                result.embedded_modules.append("__reduce__")

            # Risk scoring
            if reduce_count > 3:
                result.risk_score = min(result.risk_score + 3.0, 10.0)
                result.warnings.append(f"Multiple REDUCE opcodes ({reduce_count}) — likely malicious")

            if len(dangerous_found) > 5:
                result.warnings.append(f"High density of dangerous opcodes ({len(dangerous_found)})")

        except Exception as e:
            result.warnings.append(f"Pickle analysis error: {e}")

        return result

    def _analyze_safetensors(self, path: Path, result: ModelFile) -> ModelFile:
        """Deep analysis of SafeTensors files."""
        try:
            data = path.read_bytes()
            if len(data) < 8:
                return result

            # Parse metadata header
            meta_len = struct.unpack("<Q", data[:8])[0]
            if meta_len > 0 and meta_len < len(data) - 8:
                meta_bytes = data[8:8 + meta_len]
                meta = json.loads(meta_bytes.decode("utf-8"))

                result.metadata = meta.get("__metadata__", {})

                # Check for embedded payload in metadata
                if "_payload" in result.metadata:
                    result.has_custom_code = True
                    result.warnings.append("Embedded payload found in safetensors metadata")
                    result.risk_score = min(result.risk_score + 5.0, 10.0)
                    result.risk = RiskLevel.CRITICAL

                # Count tensors
                tensor_keys = [k for k in meta if k != "__metadata__"]
                result.num_tensors = len(tensor_keys)

                # Check for suspicious metadata fields
                suspicious_meta = [k for k in result.metadata
                                   if any(p in k.lower() for p in ["payload", "exec", "shell", "reverse", "exploit"])]
                if suspicious_meta:
                    result.warnings.append(f"Suspicious metadata fields: {suspicious_meta}")

        except (struct.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            result.warnings.append(f"Safetensors parsing error: {e}")
        except Exception as e:
            result.warnings.append(f"Safetensors analysis error: {e}")

        return result

    def _analyze_onnx(self, path: Path, result: ModelFile) -> ModelFile:
        """Deep analysis of ONNX model files."""
        try:
            data = path.read_bytes()

            # Check for external data loading
            if b"ExternalData" in data:
                result.has_external_data = True
                result.warnings.append("ONNX model references external data — potential path traversal")

            # Check for custom operators
            if b"custom_ops" in data or b"CustomOp" in data:
                result.has_custom_code = True
                result.warnings.append("Custom operators detected — potential code execution")

            # Check for embedded Python
            if b"python" in data.lower():
                result.embedded_modules.append("python_reference")

            if result.has_external_data or result.has_custom_code:
                result.risk_score = min(result.risk_score + 3.0, 10.0)

        except Exception as e:
            result.warnings.append(f"ONNX analysis error: {e}")

        return result

    def _analyze_zip_model(self, path: Path, result: ModelFile) -> ModelFile:
        """Deep analysis of ZIP-based models (TF, Keras)."""
        try:
            with zipfile.ZipFile(path) as zf:
                namelist = zf.namelist()

                # Check for Lambda layers
                for name in namelist:
                    if "lambda" in name.lower():
                        result.has_custom_code = True
                        result.risk_score = min(result.risk_score + 4.0, 10.0)
                        result.warnings.append(f"Lambda layer found: {name} — arbitrary Python execution risk")
                        break

                # Check for custom objects
                if any("custom" in f.lower() for f in namelist):
                    result.has_custom_code = True
                    result.embedded_modules.append("custom_objects")

        except (zipfile.BadZipFile, OSError) as e:
            result.warnings.append(f"ZIP analysis error: {e}")
        except Exception as e:
            result.warnings.append(f"ZIP model analysis error: {e}")

        return result

    def _analyze_ggml(self, path: Path, result: ModelFile) -> ModelFile:
        """Analysis of GGML/GGUF quantized models."""
        try:
            data = path.read_bytes()
            # GGUF has metadata key-value pairs
            if result.format == ModelFormat.GGUF and len(data) > 20:
                # Parse GGUF header for metadata count
                try:
                    # GGUF: magic(4) + version(4) + tensor_count(8) + metadata_kv_count(8)
                    header = data[:20]
                    if len(header) >= 20:
                        metadata_count = struct.unpack("<Q", header[12:20])[0]
                        result.metadata["metadata_kv_count"] = metadata_count
                        if metadata_count > 100:
                            result.warnings.append(f"Large metadata section ({metadata_count} entries)")
                except struct.error:
                    pass
        except Exception as e:
            result.warnings.append(f"GGML/GGUF analysis error: {e}")

        return result

    def _risk_to_score(self, risk: RiskLevel) -> float:
        mapping = {
            RiskLevel.CRITICAL: 9.0,
            RiskLevel.HIGH: 6.0,
            RiskLevel.MEDIUM: 3.0,
            RiskLevel.LOW: 1.0,
            RiskLevel.SAFE: 0.0,
        }
        return mapping.get(risk, 5.0)

    def get_high_risk_files(self, threshold: float = 5.0) -> list[ModelFile]:
        """Get files with risk score above threshold."""
        return [r for r in self._scan_results if r.risk_score >= threshold]

    def summary(self) -> dict:
        if not self._scan_results:
            return {"total_files": 0}

        high_risk = len([r for r in self._scan_results if r.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)])
        dangerous = len([r for r in self._scan_results if r.has_dangerous_ops])
        custom_code = len([r for r in self._scan_results if r.has_custom_code])

        return {
            "total_files": len(self._scan_results),
            "by_format": {fmt.value: len([r for r in self._scan_results if r.format == fmt])
                          for fmt in ModelFormat},
            "high_risk": high_risk,
            "has_dangerous_ops": dangerous,
            "has_custom_code": custom_code,
            "total_warnings": sum(len(r.warnings) for r in self._scan_results),
        }


def analyze_model(path: str) -> dict:
    """Convenience function to analyze a single model file."""
    analyzer = ModelFormatAnalyzer()
    result = analyzer.analyze_file(path)
    return result.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isdir(path):
            analyzer = ModelFormatAnalyzer()
            results = analyzer.analyze_directory(path)
            print(json.dumps({"files": [r.to_dict() for r in results], "summary": analyzer.summary()}, indent=2, default=str))
        else:
            result = analyze_model(path)
            print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: python model_format_analyzer.py <path_to_model_or_directory>")
