"""Ensemble detector that fans an event out to several sub-detectors.

The pipeline always wraps the configured detectors in an
:class:`EnsembleDetector` so downstream code only ever sees one
detection per event. Strategies:

* ``weighted_mean`` — score = sum(w_i * s_i) / sum(w_i) over hits
* ``max``           — score = max(s_i)
* ``majority``      — score = mean(s_i) but only if ``>= floor(n/2)`` hit

Reasons and tags are merged across the contributing detectors so the
explanation chain stays intact.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from ..ingestion.event import Event
from ..utils.logging_setup import get_logger
from .base import BaseDetector, Detection, Severity

_log = get_logger(__name__)


class EnsembleDetector(BaseDetector):
    name = "ensemble"
    stateful = False

    def __init__(
        self,
        detectors: Iterable[BaseDetector],
        weights: Optional[Dict[str, float]] = None,
        strategy: str = "weighted_mean",
        score_threshold: float = 0.5,
    ) -> None:
        self.detectors = list(detectors)
        self.weights = dict(weights or {})
        self.strategy = strategy
        self.score_threshold = score_threshold

    def detect(self, event: Event) -> Optional[Detection]:
        hits: List[Detection] = []
        for det in self.detectors:
            try:
                out = det.detect(event)
            except Exception:                       # pragma: no cover
                _log.exception("detector %s raised", det.name)
                continue
            if out is not None:
                hits.append(out)

        if not hits:
            return None

        score = self._aggregate(hits)
        if score < self.score_threshold:
            return None

        reasons = [f"[{h.detector}] {r}" for h in hits for r in h.reasons]
        tags = sorted({tag for h in hits for tag in h.tags})
        severity = Severity.from_score(score)
        return Detection(
            event=event,
            detector=self.name,
            score=score,
            severity=severity,
            reasons=reasons or [f"hit by {len(hits)} detectors"],
            tags=tags,
            metadata={
                "strategy": self.strategy,
                "components": [
                    {"detector": h.detector, "score": h.score, "severity": h.severity.value}
                    for h in hits
                ],
            },
        )

    def fit(self, events: Iterable[Event]) -> None:
        events = list(events)
        for det in self.detectors:
            try:
                det.fit(events)
            except NotImplementedError:
                continue

    def _aggregate(self, hits: List[Detection]) -> float:
        if self.strategy == "max":
            return max(h.score for h in hits)
        if self.strategy == "majority":
            required = max(1, len(self.detectors) // 2)
            if len(hits) < required:
                return 0.0
            return sum(h.score for h in hits) / len(hits)
        # default: weighted_mean
        total_w = 0.0
        total_s = 0.0
        for h in hits:
            w = float(self.weights.get(h.detector, 1.0))
            total_w += w
            total_s += w * h.score
        return total_s / total_w if total_w > 0 else 0.0
