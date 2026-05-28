"""Performance metrics for binary anomaly detectors.

``MetricsTracker`` accumulates (score, label) pairs and produces
``MetricsSnapshot`` objects that capture precision, recall, F1,
AUC-ROC approximation, and distribution statistics at a given threshold.

All arithmetic is stdlib-only.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..utils.timeutil import format_iso, now_epoch


# ------------------------------------------------------------------
# snapshot
# ------------------------------------------------------------------

@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
        }


@dataclass
class MetricsSnapshot:
    model_id: str
    version: int
    timestamp: float = field(default_factory=now_epoch)
    sample_count: int = 0
    positive_count: int = 0
    threshold: float = 0.5
    confusion: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    auc_roc: float = 0.0                # trapezoidal approximation
    mean_score: float = 0.0
    score_std: float = 0.0
    score_p50: float = 0.0
    score_p95: float = 0.0
    score_p99: float = 0.0
    drift_score: float = 0.0            # filled in by DriftDetector
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "version": self.version,
            "timestamp": self.timestamp,
            "timestamp_iso": format_iso(self.timestamp),
            "sample_count": self.sample_count,
            "positive_count": self.positive_count,
            "threshold": self.threshold,
            "confusion": self.confusion.to_dict(),
            "auc_roc": round(self.auc_roc, 4),
            "mean_score": round(self.mean_score, 4),
            "score_std": round(self.score_std, 4),
            "score_p50": round(self.score_p50, 4),
            "score_p95": round(self.score_p95, 4),
            "score_p99": round(self.score_p99, 4),
            "drift_score": round(self.drift_score, 4),
            "notes": self.notes,
        }


# ------------------------------------------------------------------
# tracker
# ------------------------------------------------------------------

class MetricsTracker:
    """Accumulates (score, label) pairs for one model version.

    Labels are optional floats: 1.0 = confirmed anomaly, 0.0 = benign.
    When no labels are available the confusion-matrix fields will be zero,
    but score-distribution statistics are still tracked.
    """

    def __init__(self, model_id: str, version: int, *, window: int = 10_000) -> None:
        self.model_id = model_id
        self.version = version
        self.window = window
        self._lock = threading.Lock()
        self._scores: List[float] = []
        self._labels: List[Optional[float]] = []

    # ------------------------------------------------------------------

    def record(self, score: float, label: Optional[float] = None) -> None:
        with self._lock:
            self._scores.append(score)
            self._labels.append(label)
            if len(self._scores) > self.window:
                self._scores.pop(0)
                self._labels.pop(0)

    def record_batch(self, pairs: List[Tuple[float, Optional[float]]]) -> None:
        for score, label in pairs:
            self.record(score, label)

    # ------------------------------------------------------------------

    def snapshot(self, threshold: float = 0.5) -> MetricsSnapshot:
        with self._lock:
            scores = list(self._scores)
            labels = list(self._labels)

        n = len(scores)
        if n == 0:
            return MetricsSnapshot(
                model_id=self.model_id, version=self.version, threshold=threshold
            )

        # distribution stats
        mean = sum(scores) / n
        variance = sum((s - mean) ** 2 for s in scores) / n
        std = math.sqrt(variance)
        sorted_scores = sorted(scores)
        p50 = _percentile(sorted_scores, 50)
        p95 = _percentile(sorted_scores, 95)
        p99 = _percentile(sorted_scores, 99)

        # confusion (only where labels are present)
        labeled = [(s, l) for s, l in zip(scores, labels) if l is not None]
        pos_count = sum(1 for _, l in labeled if l >= 0.5)
        cm = ConfusionMatrix()
        for s, l in labeled:
            pred = 1 if s >= threshold else 0
            true = 1 if l >= 0.5 else 0
            if pred == 1 and true == 1:
                cm.tp += 1
            elif pred == 1 and true == 0:
                cm.fp += 1
            elif pred == 0 and true == 1:
                cm.fn += 1
            else:
                cm.tn += 1

        auc = _trapezoidal_auc(labeled, steps=50) if labeled else 0.0

        return MetricsSnapshot(
            model_id=self.model_id,
            version=self.version,
            sample_count=n,
            positive_count=pos_count,
            threshold=threshold,
            confusion=cm,
            auc_roc=auc,
            mean_score=mean,
            score_std=std,
            score_p50=p50,
            score_p95=p95,
            score_p99=p99,
        )

    def score_buffer(self) -> List[float]:
        with self._lock:
            return list(self._scores)

    def __len__(self) -> int:
        with self._lock:
            return len(self._scores)


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (pct / 100) * (len(sorted_vals) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def _trapezoidal_auc(labeled: List[Tuple[float, float]], steps: int = 50) -> float:
    """Trapezoidal AUC-ROC without numpy."""
    if not labeled:
        return 0.0
    thresholds = [i / steps for i in range(steps + 1)]
    pts: List[Tuple[float, float]] = []
    for thr in thresholds:
        tp = fp = tn = fn = 0
        for s, l in labeled:
            pred = 1 if s >= thr else 0
            true = 1 if l >= 0.5 else 0
            if pred == 1 and true == 1:
                tp += 1
            elif pred == 1 and true == 0:
                fp += 1
            elif pred == 0 and true == 1:
                fn += 1
            else:
                tn += 1
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        pts.append((fpr, tpr))
    pts.sort()
    auc = 0.0
    for i in range(1, len(pts)):
        dx = pts[i][0] - pts[i - 1][0]
        dy = (pts[i][1] + pts[i - 1][1]) / 2
        auc += dx * dy
    return round(auc, 4)
