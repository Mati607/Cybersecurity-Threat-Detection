"""Detector contract and the :class:`Detection` value object.

Every detector takes an :class:`Event` (already normalized) and returns
zero or one :class:`Detection`. ``None`` is the common case — staying
silent is cheaper than emitting "score=0.0" detections that downstream
code would have to filter.

Each detector also exposes :meth:`name`, :meth:`fit`, and ``stateful``
flag so the pipeline can route streaming vs trained detectors uniformly.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from ..ingestion.event import Event


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score >= 0.9:
            return cls.CRITICAL
        if score >= 0.75:
            return cls.HIGH
        if score >= 0.5:
            return cls.MEDIUM
        return cls.LOW

    def at_least(self, other: "Severity") -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)


@dataclass
class Detection:
    event: Event
    detector: str
    score: float
    severity: Severity
    reasons: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "detector": self.detector,
            "score": round(float(self.score), 4),
            "severity": self.severity.value,
            "reasons": list(self.reasons),
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


class BaseDetector(abc.ABC):
    name: str = "base"
    stateful: bool = False

    @abc.abstractmethod
    def detect(self, event: Event) -> Optional[Detection]:
        ...

    def fit(self, events: Iterable[Event]) -> None:
        """Optional warm-up over a stream of events. Default is a no-op."""

    def reset(self) -> None:
        """Drop any accumulated state. Default is a no-op."""
