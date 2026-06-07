"""Priority scoring for triaged alerts.

Severity answers "how bad is one detection"; priority answers "what should
the analyst look at first". They diverge constantly in a SOC:

* a CRITICAL detection seen once on one host is urgent but contained;
* a MEDIUM detection seen 500 times across 40 hosts is a campaign.

:class:`PriorityScorer` folds five signals into a single 0..1 score and
buckets it into a :class:`~threatpipe.triage.model.TriagePriority` band:

* **severity**   — the alert's peak severity, normalized to 0..1.
* **volume**     — how many detections collapsed into the alert (log-scaled
  so the 10th occurrence matters far more than the 1000th).
* **spread**     — how many distinct hosts are affected (a lateral
  fingerprint is scarier than a loud-on-one-box one).
* **intel**      — whether any detection carried a threat-intel match.
* **confidence** — the peak detector score, so a low-confidence anomaly
  doesn't ride severity alone to the top of the queue.

Weights are configurable but sum-normalized, so the output stays in 0..1
regardless of how a deployment tunes them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict

from ..detection.base import Severity
from .model import TriagePriority, TriagedAlert

_SEVERITY_WEIGHT: Dict[Severity, float] = {
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 1.0,
}

# Score thresholds, highest band first. The first band whose floor the
# score clears wins.
_BANDS = (
    (0.82, TriagePriority.P1),
    (0.62, TriagePriority.P2),
    (0.40, TriagePriority.P3),
    (0.20, TriagePriority.P4),
)


@dataclass
class PriorityScorer:
    severity_w: float = 0.40
    volume_w: float = 0.20
    spread_w: float = 0.20
    intel_w: float = 0.12
    confidence_w: float = 0.08

    # Saturation knobs: the count/host at which that signal is considered
    # "maxed out". Past these, more of the same barely moves the needle.
    volume_saturation: int = 100
    spread_saturation: int = 25

    def _weights(self) -> Dict[str, float]:
        total = (
            self.severity_w + self.volume_w + self.spread_w
            + self.intel_w + self.confidence_w
        )
        if total <= 0:
            # Degenerate config: fall back to severity-only so we never
            # divide by zero or return a flat score.
            return {"severity": 1.0, "volume": 0.0, "spread": 0.0, "intel": 0.0, "confidence": 0.0}
        return {
            "severity": self.severity_w / total,
            "volume": self.volume_w / total,
            "spread": self.spread_w / total,
            "intel": self.intel_w / total,
            "confidence": self.confidence_w / total,
        }

    def _volume_factor(self, count: int) -> float:
        if count <= 1:
            return 0.0
        # log-scaled so the curve is steep early and flattens out.
        return min(1.0, math.log1p(count - 1) / math.log1p(self.volume_saturation))

    def _spread_factor(self, hosts: int) -> float:
        if hosts <= 1:
            return 0.0
        return min(1.0, (hosts - 1) / max(1, self.spread_saturation - 1))

    def score(self, alert: TriagedAlert, *, intel_hit: bool = False) -> float:
        """Return the 0..1 priority score for ``alert``."""
        w = self._weights()
        severity = _SEVERITY_WEIGHT.get(alert.severity, 0.5)
        volume = self._volume_factor(alert.count)
        spread = self._spread_factor(alert.distinct_hosts)
        intel = 1.0 if intel_hit else 0.0
        confidence = max(0.0, min(1.0, alert.max_score))
        raw = (
            w["severity"] * severity
            + w["volume"] * volume
            + w["spread"] * spread
            + w["intel"] * intel
            + w["confidence"] * confidence
        )
        return max(0.0, min(1.0, raw))

    def band(self, score: float) -> TriagePriority:
        for floor, priority in _BANDS:
            if score >= floor:
                return priority
        return TriagePriority.P5

    def assign(self, alert: TriagedAlert, *, intel_hit: bool = False) -> TriagePriority:
        """Score ``alert`` and write ``priority``/``priority_score`` onto it."""
        s = self.score(alert, intel_hit=intel_hit)
        alert.priority_score = s
        alert.priority = self.band(s)
        return alert.priority
