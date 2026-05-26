"""Small TTL cache for reputation lookups.

The IOC matcher answers "is this on a known blocklist?" — a separate
question is "what is this thing's reputation right now?". We model
that with a simple in-memory cache keyed by (kind, value) that callers
can consult before they spend the CPU on a more expensive lookup
(e.g. WHOIS, passive DNS, an external API).

The cache is intentionally non-blocking: lookups never call out to
the network. Callers register a resolver function once, the cache
then memoizes results for ``ttl_seconds``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple


Kind = str
Resolver = Callable[[Kind, str], "Reputation"]


@dataclass
class Reputation:
    kind: Kind
    value: str
    score: float                          # 0..1, higher == worse
    classification: str = "unknown"        # benign | suspicious | malicious | unknown
    sources: Tuple[str, ...] = ()
    cached_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "score": round(self.score, 4),
            "classification": self.classification,
            "sources": list(self.sources),
            "age_s": max(0.0, time.time() - self.cached_at) if self.cached_at else 0.0,
        }


class ReputationCache:
    def __init__(self, resolver: Optional[Resolver] = None, *, ttl_seconds: float = 1800.0, max_entries: int = 8192) -> None:
        self.resolver = resolver
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: Dict[Tuple[Kind, str], Reputation] = {}
        self._lock = threading.RLock()

    def get(self, kind: Kind, value: str) -> Optional[Reputation]:
        key = (kind, value)
        with self._lock:
            rep = self._entries.get(key)
            if rep is None:
                return None
            if time.time() - rep.cached_at > self.ttl_seconds:
                del self._entries[key]
                return None
            return rep

    def put(self, rep: Reputation) -> None:
        with self._lock:
            if len(self._entries) >= self.max_entries:
                # evict the single oldest entry to bound memory
                oldest_key = min(self._entries, key=lambda k: self._entries[k].cached_at)
                del self._entries[oldest_key]
            rep.cached_at = time.time()
            self._entries[(rep.kind, rep.value)] = rep

    def resolve(self, kind: Kind, value: str) -> Optional[Reputation]:
        cached = self.get(kind, value)
        if cached is not None:
            return cached
        if self.resolver is None:
            return None
        rep = self.resolver(kind, value)
        if rep is not None:
            self.put(rep)
        return rep

    def __len__(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
