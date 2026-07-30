from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from raphael.cognitive.models import TargetModel


@dataclass
class NegativeEntry:
    technique_id: str
    target_signature: str
    failure_reason: str
    timestamp: float = field(default_factory=time.time)
    failure_count: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def age(self) -> float:
        return time.time() - self.timestamp
    
    @property
    def is_stale(self, max_age: float = 3600) -> bool:
        return self.age > max_age


class NegativeCache:
    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: float = 3600,
        max_failures_before_permanent: int = 3,
    ):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.max_failures = max_failures_before_permanent
        self._cache: Dict[str, NegativeEntry] = {}
        self._permanent_failures: Dict[str, NegativeEntry] = {}
    
    def _make_key(self, technique_id: str, target_signature: str) -> str:
        return f"{technique_id}:{target_signature}"
    
    def record_failure(
        self,
        technique_id: str,
        target_signature: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        key = self._make_key(technique_id, target_signature)
        
        if key in self._permanent_failures:
            self._permanent_failures[key].failure_count += 1
            return
        
        if key in self._cache:
            entry = self._cache[key]
            entry.failure_count += 1
            entry.timestamp = time.time()
            if entry.failure_count >= self.max_failures:
                self._permanent_failures[key] = entry
                del self._cache[key]
        else:
            entry = NegativeEntry(
                technique_id=technique_id,
                target_signature=target_signature,
                failure_reason=reason,
                metadata=metadata or {},
            )
            self._cache[key] = entry
        
        self._evict()
    
    def record_success(self, technique_id: str, target_signature: str) -> None:
        key = self._make_key(technique_id, target_signature)
        if key in self._cache:
            del self._cache[key]
        if key in self._permanent_failures:
            del self._permanent_failures[key]
    
    def is_dead(self, technique_id: str, target_model: TargetModel) -> bool:
        key = self._make_key(technique_id, target_model.identifier)
        
        if key in self._permanent_failures:
            return True
        
        if key in self._cache:
            entry = self._cache[key]
            if entry.is_stale(self.default_ttl):
                del self._cache[key]
                return False
            return True
        
        return False
    
    def get_entry(self, technique_id: str, target_signature: str) -> Optional[NegativeEntry]:
        key = self._make_key(technique_id, target_signature)
        if key in self._permanent_failures:
            return self._permanent_failures[key]
        if key in self._cache:
            entry = self._cache[key]
            if entry.is_stale(self.default_ttl):
                del self._cache[key]
                return None
            return entry
        return None
    
    def clear_stale(self) -> int:
        stale_keys = [
            k for k, e in self._cache.items() if e.is_stale(self.default_ttl)
        ]
        for k in stale_keys:
            del self._cache[k]
        return len(stale_keys)
    
    def _evict(self) -> None:
        if len(self._cache) <= self.max_size:
            return
        
        sorted_entries = sorted(
            self._cache.items(),
            key=lambda x: (x[1].failure_count, -x[1].timestamp)
        )
        
        to_remove = len(self._cache) - self.max_size
        for key, _ in sorted_entries[:to_remove]:
            del self._cache[key]
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "cache_size": len(self._cache),
            "permanent_failures": len(self._permanent_failures),
            "total_entries": len(self._cache) + len(self._permanent_failures),
        }