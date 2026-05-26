"""Dense numeric feature extraction.

The ML detectors need fixed-shape feature vectors but the events have
optional, heterogeneous fields. :class:`FeatureExtractor` keeps a tiny
fitted state (string hashing buckets and observed min/max for numeric
columns) and produces a deterministic vector for both training and
inference.

We deliberately avoid pulling in scikit-learn here. A 1.5 kB hashing
trick is enough for the volumes that hit the on-line pipeline, and
keeps the dependency closure light.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from ..ingestion.event import Event


_CATEGORICAL_FIELDS = (
    "event_type",
    "action",
    "process",
    "protocol",
    "user",
    "host",
    "source",
)
_NUMERIC_FIELDS = (
    "pid",
    "parent_pid",
    "src_port",
    "dst_port",
    "bytes_sent",
    "bytes_recv",
)
_TEXT_FIELDS = ("command_line", "message", "file_path")


def _hash_bucket(value: str, n_buckets: int) -> int:
    h = hashlib.blake2s(value.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(h, "big") % n_buckets


@dataclass
class FeatureExtractor:
    n_categorical_buckets: int = 64
    n_text_buckets: int = 32
    numeric_stats: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    fitted: bool = False

    @property
    def dim(self) -> int:
        return (
            len(_CATEGORICAL_FIELDS) * self.n_categorical_buckets
            + len(_NUMERIC_FIELDS) * 2
            + self.n_text_buckets
        )

    def fit(self, events: Iterable[Event]) -> "FeatureExtractor":
        stats: Dict[str, Tuple[float, float]] = {}
        for ev in events:
            for f in _NUMERIC_FIELDS:
                v = getattr(ev, f, None)
                if v is None:
                    continue
                x = float(v)
                lo, hi = stats.get(f, (x, x))
                stats[f] = (min(lo, x), max(hi, x))
        self.numeric_stats = stats
        self.fitted = True
        return self

    def transform(self, event: Event) -> List[float]:
        vec = [0.0] * self.dim

        # categorical hashing
        for i, field_name in enumerate(_CATEGORICAL_FIELDS):
            value = getattr(event, field_name, None)
            if not value:
                continue
            bucket = _hash_bucket(str(value), self.n_categorical_buckets)
            vec[i * self.n_categorical_buckets + bucket] = 1.0

        # numeric: scaled value + log presence indicator
        base = len(_CATEGORICAL_FIELDS) * self.n_categorical_buckets
        for i, field_name in enumerate(_NUMERIC_FIELDS):
            value = getattr(event, field_name, None)
            if value is None:
                continue
            x = float(value)
            lo, hi = self.numeric_stats.get(field_name, (0.0, max(1.0, x)))
            span = max(1.0, hi - lo)
            vec[base + 2 * i] = (x - lo) / span
            vec[base + 2 * i + 1] = math.log1p(abs(x))

        # text: token hashing trick across all text fields
        text_base = base + 2 * len(_NUMERIC_FIELDS)
        for field_name in _TEXT_FIELDS:
            value = getattr(event, field_name, None)
            if not value:
                continue
            for token in str(value).split():
                bucket = _hash_bucket(token.lower(), self.n_text_buckets)
                vec[text_base + bucket] += 1.0

        # token bag normalization (l2)
        norm = math.sqrt(sum(v * v for v in vec[text_base:]))
        if norm > 0:
            for i in range(text_base, len(vec)):
                vec[i] /= norm

        return vec

    def transform_many(self, events: Iterable[Event]) -> List[List[float]]:
        return [self.transform(ev) for ev in events]
