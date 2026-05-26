"""In-memory IOC store with bulk loading and per-type indexes.

The matcher hits the store on every event so the lookup path needs to
be O(1). We keep the IOCs in one map per type, which also makes
``list_by_type`` cheap for the API.

The store is intentionally tolerant: when two feeds disagree we keep
the *higher* confidence and threat-score for the same IOC, and merge
their tags so downstream consumers can see provenance from every feed
that flagged the indicator.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..utils.logging_setup import get_logger
from .ioc import IOC, IOCMeta, IOCType

_log = get_logger(__name__)


@dataclass
class IOCMatch:
    ioc: IOC
    field: str
    value: str
    confidence: float
    threat_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc": self.ioc.to_dict(),
            "field": self.field,
            "value": self.value,
            "confidence": self.confidence,
            "threat_score": self.threat_score,
        }


class IOCStore:
    def __init__(self) -> None:
        self._by_type: Dict[IOCType, Dict[str, IOC]] = defaultdict(dict)
        self._lock = threading.RLock()
        self._total = 0
        self._loaded_sources: Dict[str, int] = defaultdict(int)

    def add(self, ioc: IOC) -> bool:
        """Insert ``ioc``; merge with an existing entry if any."""
        with self._lock:
            bucket = self._by_type[ioc.type]
            existing = bucket.get(ioc.value)
            if existing is None:
                bucket[ioc.value] = ioc
                self._total += 1
                self._loaded_sources[ioc.meta.source] += 1
                return True
            merged_tags = tuple(sorted(set(existing.meta.tags) | set(ioc.meta.tags)))
            merged_meta = IOCMeta(
                source=existing.meta.source if existing.meta.confidence >= ioc.meta.confidence else ioc.meta.source,
                confidence=max(existing.meta.confidence, ioc.meta.confidence),
                threat_score=max(existing.meta.threat_score, ioc.meta.threat_score),
                tags=merged_tags,
                description=existing.meta.description or ioc.meta.description,
            )
            bucket[ioc.value] = IOC(type=existing.type, value=existing.value, meta=merged_meta)
            return False

    def add_all(self, iocs: Iterable[IOC]) -> int:
        added = 0
        for ioc in iocs:
            if self.add(ioc):
                added += 1
        return added

    def lookup(self, ioc_type: IOCType, value: str) -> Optional[IOC]:
        with self._lock:
            bucket = self._by_type.get(ioc_type)
            if not bucket:
                return None
            ioc = bucket.get(value)
            if ioc is not None:
                return ioc
            # case-insensitive fallback for hashes / domains
            if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256, IOCType.DOMAIN, IOCType.EMAIL):
                return bucket.get(value.lower())
            return None

    def list_by_type(self, ioc_type: IOCType, limit: int = 100) -> List[IOC]:
        with self._lock:
            return list(self._by_type.get(ioc_type, {}).values())[:limit]

    def all(self) -> List[IOC]:
        with self._lock:
            out: List[IOC] = []
            for bucket in self._by_type.values():
                out.extend(bucket.values())
            return out

    def remove(self, ioc_type: IOCType, value: str) -> bool:
        with self._lock:
            bucket = self._by_type.get(ioc_type)
            if not bucket or value not in bucket:
                return False
            del bucket[value]
            self._total -= 1
            return True

    def clear(self) -> None:
        with self._lock:
            self._by_type.clear()
            self._total = 0
            self._loaded_sources.clear()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total": self._total,
                "by_type": {t.value: len(b) for t, b in self._by_type.items()},
                "by_source": dict(self._loaded_sources),
            }
