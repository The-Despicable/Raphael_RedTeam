"""
HuggingFace Hub API Client (P1 - FORGE Phase 1)

Interacts with the HuggingFace Hub API for model discovery, download,
and attack targeting. Supports anonymous and authenticated access.

Capabilities:
- Search models by query, task, tag, author
- Get model metadata (downloads, likes, pipeline tags)
- List model files and versions
- Download model files for analysis
- Check model provenance and safetensors conversion status
- Identify potential supply chain attack targets
"""

from __future__ import annotations

import os
import re
import json
import time
import uuid
import hashlib
import logging
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Optional requests library — falls back to urllib
_HAS_REQUESTS = True
try:
    import requests
except ImportError:
    _HAS_REQUESTS = False


class HFAuthMethod(Enum):
    """Authentication method for HF Hub API."""
    ANONYMOUS = "anonymous"
    TOKEN = "token"
    COOKIE = "cookie"


class ModelTask(Enum):
    """HF task categories."""
    TEXT_CLASSIFICATION = "text-classification"
    TOKEN_CLASSIFICATION = "token-classification"
    TEXT_GENERATION = "text-generation"
    FILL_MASK = "fill-mask"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    QUESTION_ANSWERING = "question-answering"
    TEXT2TEXT = "text2text-generation"
    IMAGE_CLASSIFICATION = "image-classification"
    OBJECT_DETECTION = "object-detection"
    IMAGE_SEGMENTATION = "image-segmentation"
    TEXT_TO_IMAGE = "text-to-image"
    IMAGE_TO_TEXT = "image-to-text"
    IMAGE_TO_IMAGE = "image-to-image"
    SPEECH_RECOGNITION = "automatic-speech-recognition"
    TEXT_TO_SPEECH = "text-to-speech"
    AUDIO_CLASSIFICATION = "audio-classification"
    EMBEDDING = "feature-extraction"
    SENTENCE_SIMILARITY = "sentence-similarity"
    TABLE_QA = "table-question-answering"
    VISUAL_QA = "visual-question-answering"
    VIDEO_CLASSIFICATION = "video-classification"
    REINFORCEMENT_LEARNING = "reinforcement-learning"
    ROBOTICS = "robotics"
    OTHER = "other"


@dataclass
class ModelInfo:
    """Metadata about a HuggingFace model."""
    model_id: str
    author: str = ""
    pipeline_tag: str = ""
    downloads: int = 0
    likes: int = 0
    is_safetensors: bool = False
    is_private: bool = False
    is_gated: bool = False
    disabled: bool = False
    tags: list[str] = field(default_factory=list)
    siblings: list[dict] = field(default_factory=list)
    card_data: dict = field(default_factory=dict)
    created_at: str = ""
    last_modified: str = ""
    sha: str = ""

    @classmethod
    def from_api(cls, data: dict) -> "ModelInfo":
        return cls(
            model_id=data.get("id", ""),
            author=data.get("author", "") or data.get("id", "").split("/")[0] if "/" in data.get("id", "") else "",
            pipeline_tag=data.get("pipeline_tag", ""),
            downloads=data.get("downloads", 0),
            likes=data.get("likes", 0),
            is_safetensors=data.get("safetensors", False),
            is_private=data.get("private", False),
            is_gated=data.get("gated", False),
            disabled=data.get("disabled", False),
            tags=data.get("tags", []),
            siblings=data.get("siblings", []),
            card_data=data.get("cardData", {}),
            created_at=data.get("createdAt", ""),
            last_modified=data.get("lastModified", ""),
            sha=data.get("sha", ""),
        )

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "author": self.author,
            "pipeline_tag": self.pipeline_tag,
            "downloads": self.downloads,
            "likes": self.likes,
            "is_safetensors": self.is_safetensors,
            "is_private": self.is_private,
            "is_gated": self.is_gated,
            "disabled": self.disabled,
            "tags": self.tags[:20],  # Limit to avoid huge payloads
            "sibling_count": len(self.siblings),
            "file_types": self._file_type_summary(),
            "created_at": self.created_at,
            "last_modified": self.last_modified,
        }

    def _file_type_summary(self) -> dict:
        """Summarize file types in the model repo."""
        summary = {}
        for sibling in self.siblings:
            filename = sibling.get("rfilename", "") or sibling.get("path", "")
            ext = Path(filename).suffix.lower()
            if ext:
                summary[ext] = summary.get(ext, 0) + 1
        return summary

    def has_format(self, fmt: str) -> bool:
        """Check if model has files of a specific format."""
        fmt = fmt.lower()
        for sibling in self.siblings:
            filename = sibling.get("rfilename", "") or sibling.get("path", "")
            if filename.lower().endswith(fmt):
                return True
        return False

    def has_pickle(self) -> bool:
        return self.has_format(".pkl") or self.has_format(".pt") or self.has_format(".pth")

    def has_safetensors(self) -> bool:
        return self.is_safetensors or self.has_format(".safetensors")

    def download_url(self, filename: str = "") -> str:
        """Get download URL for a file in the model repo."""
        base = f"https://huggingface.co/{self.model_id}/resolve/main"
        return f"{base}/{filename}" if filename else base


@dataclass
class HFQueryResult:
    """Result of an HF Hub query."""
    models: list[ModelInfo] = field(default_factory=list)
    total_count: int = 0
    query: str = ""
    next_url: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "total_count": self.total_count,
            "returned_count": len(self.models),
            "query": self.query,
            "next_url": self.next_url,
            "error": self.error,
            "models": [m.to_dict() for m in self.models],
        }

    def high_risk_models(self) -> list[ModelInfo]:
        """Filter models that are potential attack targets.

        High-risk indicators:
        - Pickle format (not safetensors) = RCE vector
        - High downloads = wider impact
        - Low likes/downloads ratio = potentially malicious
        - Private models = less scrutiny
        """
        return [m for m in self.models if m.has_pickle() and not m.has_safetensors()]


class HFHubAPIClient:
    """Client for the HuggingFace Hub API.

    FORGE Rule 3 (import map): requests library is optional — falls back to urllib.
    FORGE Rule 4 (subprocess): no subprocess calls.
    """

    HF_API_BASE = "https://huggingface.co/api"
    HF_MODELS_ENDPOINT = f"{HF_API_BASE}/models"
    HF_DATASETS_ENDPOINT = f"{HF_API_BASE}/datasets"

    # Rate limiting
    MAX_REQUESTS_PER_SECOND = 5
    MAX_RESULTS_PER_PAGE = 100

    def __init__(self, token: str = "", auth_method: HFAuthMethod = HFAuthMethod.ANONYMOUS):
        self.token = token or os.environ.get("HF_TOKEN", "")
        self.auth_method = auth_method if self.token else HFAuthMethod.ANONYMOUS
        self._last_request_time = 0.0
        self._request_count = 0
        self._session_id = uuid.uuid4().hex[:8]

    def get_model(self, model_id: str) -> ModelInfo:
        """Get metadata for a specific model."""
        url = f"{self.HF_MODELS_ENDPOINT}/{model_id}"
        data = self._request(url)
        return ModelInfo.from_api(data)

    def search_models(
        self,
        query: str = "",
        task: Optional[str] = None,
        author: Optional[str] = None,
        tags: Optional[list[str]] = None,
        sort: str = "downloads",
        direction: int = -1,
        limit: int = 50,
        full: bool = False,
    ) -> HFQueryResult:
        """Search models on HF Hub with filters."""
        params = {
            "sort": sort,
            "direction": direction,
            "limit": min(limit, self.MAX_RESULTS_PER_PAGE),
        }
        if query:
            params["search"] = query
        if task:
            params["pipeline_tag"] = task
        if author:
            params["author"] = author
        if tags:
            params["tags"] = ",".join(tags)
        if full:
            params["full"] = "true"

        url = f"{self.HF_MODELS_ENDPOINT}?{urllib.parse.urlencode(params)}"
        data = self._request(url)

        result = HFQueryResult(
            query=query or task or "",
            total_count=len(data),
        )

        if isinstance(data, list):
            for item in data:
                try:
                    result.models.append(ModelInfo.from_api(item))
                except Exception as e:
                    logger.debug(f"Failed to parse model: {e}")
                    continue
        elif isinstance(data, dict):
            result.error = data.get("error", "Unknown API error")

        return result

    def get_model_files(self, model_id: str) -> list[dict]:
        """List all files in a model repository."""
        url = f"{self.HF_MODELS_ENDPOINT}/{model_id}/tree/main"
        data = self._request(url)
        if isinstance(data, list):
            return data
        return []

    def download_model_file(self, model_id: str, filename: str, output_dir: str | Path) -> Path:
        """Download a specific file from a model repository."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        url = f"https://huggingface.co/{model_id}/resolve/main/{filename}"
        output_path = output_dir / filename

        # Check if already downloaded (caching)
        if output_path.exists():
            logger.info(f"File already cached: {output_path}")
            return output_path

        logger.info(f"Downloading {url} -> {output_path}")
        headers = self._get_headers()

        if _HAS_REQUESTS:
            resp = requests.get(url, headers=headers, stream=True, timeout=60)
            resp.raise_for_status()
            with open(output_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
        else:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                with open(output_path, "wb") as f:
                    while True:
                        chunk = resp.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)

        return output_path

    def _request(self, url: str) -> Any:
        """Make an HTTP request to the HF API with rate limiting."""
        self._rate_limit()

        headers = self._get_headers()
        logger.debug(f"HF API request: {url[:120]}...")

        try:
            if _HAS_REQUESTS:
                resp = requests.get(url, headers=headers, timeout=30)
                resp.raise_for_status()
                return resp.json()
            else:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            error_msg = f"HTTP {e.code}: {e.reason}"
            logger.warning(f"HF API error: {error_msg}")
            if e.code == 401:
                raise RuntimeError("HF API authentication failed — check token") from e
            if e.code == 404:
                raise FileNotFoundError(f"Model not found: {url}") from e
            if e.code == 429:
                logger.warning("HF API rate limited — waiting...")
                time.sleep(10)
                return self._request(url)  # Retry
            raise RuntimeError(error_msg) from e
        except requests.exceptions.RequestException as e:
            logger.warning(f"HF API request failed: {e}")
            raise RuntimeError(f"HF API request failed: {e}") from e
        except (json.JSONDecodeError, urllib.error.URLError) as e:
            logger.warning(f"HF API response error: {e}")
            raise RuntimeError(f"HF API response error: {e}") from e

    def _get_headers(self) -> dict:
        """Get HTTP headers for API requests."""
        headers = {
            "User-Agent": f"Raphael-ML/1.0 (session:{self._session_id})",
            "Accept": "application/json",
        }
        if self.auth_method == HFAuthMethod.TOKEN and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _rate_limit(self):
        """Rate limit to avoid HF API throttling."""
        now = time.time()
        elapsed = now - self._last_request_time
        min_interval = 1.0 / self.MAX_REQUESTS_PER_SECOND

        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

        self._last_request_time = time.time()
        self._request_count += 1

    def find_high_risk_targets(self, limit: int = 50) -> HFQueryResult:
        """Find models that are high-risk supply chain attack targets.

        Targets are models that:
        1. Use pickle format (not safetensors) = RCE risk
        2. Have high downloads = wider blast radius
        3. Are from less-known authors = less review
        4. Haven't been updated recently = abandoned
        """
        result = HFQueryResult(query="high_risk_pickle_models")

        # Search for popular models that still use pickle
        popular = self.search_models(sort="downloads", direction=-1, limit=limit)
        for model in popular.models:
            if model.has_pickle() and not model.has_safetensors():
                result.models.append(model)

        # Search for recently uploaded models (less review)
        recent = self.search_models(sort="createdAt", direction=-1, limit=limit)
        for model in recent.models:
            if model.has_pickle() and not model.has_safetensors():
                if model not in result.models:
                    result.models.append(model)

        result.total_count = len(result.models)
        return result

    def summary(self) -> dict:
        return {
            "client": "HFHubAPIClient",
            "version": "0.1.0",
            "session_id": self._session_id,
            "auth_method": self.auth_method.value,
            "authenticated": bool(self.token),
            "has_requests": _HAS_REQUESTS,
            "request_count": self._request_count,
            "api_base": self.HF_API_BASE,
        }


def search_hf_models(query: str = "", limit: int = 10) -> dict:
    """Convenience function to search HF models."""
    client = HFHubAPIClient()
    result = client.search_models(query=query, limit=limit)
    return result.to_dict()


def get_model_info(model_id: str) -> dict:
    """Convenience function to get a single model's info."""
    client = HFHubAPIClient()
    model = client.get_model(model_id)
    return model.to_dict()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        client = HFHubAPIClient()

        if cmd == "search" and len(sys.argv) > 2:
            query = sys.argv[2]
            limit = int(sys.argv[3]) if len(sys.argv) > 3 else 10
            result = client.search_models(query=query, limit=limit)
            print(json.dumps(result.to_dict(), indent=2, default=str))

        elif cmd == "info" and len(sys.argv) > 2:
            model_id = sys.argv[2]
            try:
                info = client.get_model(model_id)
                print(json.dumps(info.to_dict(), indent=2, default=str))
            except Exception as e:
                print(f"Error: {e}")

        elif cmd == "high-risk":
            limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
            result = client.find_high_risk_targets(limit=limit)
            print(f"Found {result.total_count} high-risk models")
            for m in result.models[:10]:
                print(f"  {m.model_id:50s} downloads={m.downloads:>8d} pickle={m.has_pickle()}")

        else:
            print("Usage:")
            print("  python hf_hub_api_client.py search <query> [limit]")
            print("  python hf_hub_api_client.py info <model_id>")
            print("  python hf_hub_api_client.py high-risk [limit]")
    else:
        client = HFHubAPIClient()
        print(json.dumps(client.summary(), indent=2, default=str))
