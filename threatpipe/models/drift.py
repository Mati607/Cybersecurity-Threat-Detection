"""Concept drift detection for anomaly score distributions.

Three complementary detectors are provided:

* **CUSUM** — tracks cumulative deviation from the reference mean; fast
  to respond to a sustained shift in the score distribution.
* **PSI** (Population Stability Index) — compares the score histogram
  of the current window against a reference window; catches both shifts
  and shape changes.
* **KS-approximation** — two-sample Kolmogorov-Smirnov statistic
  computed without scipy; catches distributional changes.

``DriftDetector`` runs all three and returns a composite score plus
per-algorithm signals in a ``DriftAlert``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..utils.timeutil import format_iso, now_epoch


class DriftSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "DriftSeverity":
        if score < 0.1:
            return cls.NONE
        if score < 0.3:
            return cls.LOW
        if score < 0.5:
            return cls.MEDIUM
        if score < 0.75:
            return cls.HIGH
        return cls.CRITICAL


@dataclass
class DriftAlert:
    model_id: str
    version: int
    timestamp: float = field(default_factory=now_epoch)
    composite_score: float = 0.0
    severity: DriftSeverity = DriftSeverity.NONE
    cusum_score: float = 0.0
    psi_score: float = 0.0
    ks_score: float = 0.0
    reference_mean: float = 0.0
    current_mean: float = 0.0
    reference_size: int = 0
    current_size: int = 0
    triggered: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "version": self.version,
            "timestamp": self.timestamp,
            "timestamp_iso": format_iso(self.timestamp),
            "composite_score": round(self.composite_score, 4),
            "severity": self.severity.value,
            "cusum_score": round(self.cusum_score, 4),
            "psi_score": round(self.psi_score, 4),
            "ks_score": round(self.ks_score, 4),
            "reference_mean": round(self.reference_mean, 4),
            "current_mean": round(self.current_mean, 4),
            "reference_size": self.reference_size,
            "current_size": self.current_size,
            "triggered": self.triggered,
            "description": self.description,
        }


class DriftDetector:
    """Detects concept drift in a stream of anomaly scores.

    Call :meth:`set_reference` once (or after each successful retrain)
    with the score buffer from the production model, then call
    :meth:`evaluate` with the current window to get a ``DriftAlert``.

    Parameters
    ----------
    cusum_threshold:
        CUSUM statistic value above which drift is flagged.
    psi_threshold:
        PSI value above which drift is flagged (0.25 is a common rule of
        thumb for "significant" population shift).
    ks_threshold:
        KS D-statistic above which drift is flagged (roughly 0.3 for
        moderate samples).
    n_bins:
        Number of histogram bins used for PSI.
    weights:
        (cusum, psi, ks) composite weights; must sum to 1.
    """

    def __init__(
        self,
        *,
        cusum_threshold: float = 1.0,
        psi_threshold: float = 0.25,
        ks_threshold: float = 0.3,
        n_bins: int = 10,
        weights: tuple = (0.4, 0.35, 0.25),
    ) -> None:
        self.cusum_threshold = cusum_threshold
        self.psi_threshold = psi_threshold
        self.ks_threshold = ks_threshold
        self.n_bins = n_bins
        self._w_cusum, self._w_psi, self._w_ks = weights

        self._reference: List[float] = []
        self._ref_mean: float = 0.0
        self._ref_std: float = 1.0
        self._ref_bins: List[float] = []   # bin edges
        self._ref_hist: List[float] = []   # normalised histogram

    # ------------------------------------------------------------------
    # setup
    # ------------------------------------------------------------------

    def set_reference(self, scores: List[float]) -> None:
        if not scores:
            return
        self._reference = list(scores)
        n = len(scores)
        self._ref_mean = sum(scores) / n
        self._ref_std = math.sqrt(sum((s - self._ref_mean) ** 2 for s in scores) / n) or 1e-9
        self._ref_bins, self._ref_hist = _histogram(scores, self.n_bins)

    def has_reference(self) -> bool:
        return bool(self._reference)

    # ------------------------------------------------------------------
    # evaluation
    # ------------------------------------------------------------------

    def evaluate(self, model_id: str, version: int, current_scores: List[float]) -> DriftAlert:
        alert = DriftAlert(
            model_id=model_id,
            version=version,
            reference_mean=self._ref_mean,
            reference_size=len(self._reference),
            current_size=len(current_scores),
        )

        if not current_scores or not self._reference:
            return alert

        cur_mean = sum(current_scores) / len(current_scores)
        alert.current_mean = cur_mean

        cusum = _cusum(current_scores, self._ref_mean, self._ref_std)
        psi = _psi(self._ref_hist, self._ref_bins, current_scores, self.n_bins)
        ks = _ks_statistic(self._reference, current_scores)

        alert.cusum_score = cusum
        alert.psi_score = psi
        alert.ks_score = ks

        # normalise each to [0,1] relative to their thresholds
        cusum_norm = min(cusum / max(self.cusum_threshold, 1e-9), 1.0)
        psi_norm = min(psi / max(self.psi_threshold, 1e-9), 1.0)
        ks_norm = min(ks / max(self.ks_threshold, 1e-9), 1.0)

        composite = (
            self._w_cusum * cusum_norm
            + self._w_psi * psi_norm
            + self._w_ks * ks_norm
        )
        alert.composite_score = round(composite, 4)
        alert.severity = DriftSeverity.from_score(composite)
        alert.triggered = (
            cusum > self.cusum_threshold
            or psi > self.psi_threshold
            or ks > self.ks_threshold
        )

        parts = []
        if cusum > self.cusum_threshold:
            parts.append(f"CUSUM={cusum:.3f}>{self.cusum_threshold}")
        if psi > self.psi_threshold:
            parts.append(f"PSI={psi:.3f}>{self.psi_threshold}")
        if ks > self.ks_threshold:
            parts.append(f"KS={ks:.3f}>{self.ks_threshold}")
        mean_shift = abs(cur_mean - self._ref_mean)
        if parts:
            alert.description = (
                f"Drift detected ({'; '.join(parts)}). "
                f"Mean shift: {mean_shift:.4f} "
                f"({self._ref_mean:.4f} → {cur_mean:.4f})."
            )
        return alert


# ------------------------------------------------------------------
# algorithm implementations
# ------------------------------------------------------------------

def _cusum(scores: List[float], ref_mean: float, ref_std: float) -> float:
    """Page-Hinkley CUSUM: returns peak positive deviation."""
    cusum_pos = 0.0
    peak = 0.0
    k = 0.5 * ref_std   # slack
    for s in scores:
        cusum_pos = max(0.0, cusum_pos + (s - ref_mean) - k)
        peak = max(peak, cusum_pos)
    return round(peak / max(ref_std, 1e-9), 4)


def _histogram(scores: List[float], n_bins: int):
    """Return (bin_edges, normalised_frequencies)."""
    lo, hi = min(scores), max(scores)
    if lo == hi:
        hi = lo + 1e-9
    width = (hi - lo) / n_bins
    edges = [lo + i * width for i in range(n_bins + 1)]
    counts = [0] * n_bins
    for s in scores:
        idx = min(int((s - lo) / width), n_bins - 1)
        counts[idx] += 1
    total = len(scores)
    freqs = [c / total for c in counts]
    return edges, freqs


def _bin_index(val: float, edges: List[float]) -> int:
    n = len(edges) - 1
    lo, hi = edges[0], edges[-1]
    if val <= lo:
        return 0
    if val >= hi:
        return n - 1
    width = (hi - lo) / n
    return min(int((val - lo) / width), n - 1)


def _psi(ref_hist: List[float], ref_bins: List[float], current_scores: List[float], n_bins: int) -> float:
    """Population Stability Index vs reference histogram."""
    if not ref_hist or not current_scores:
        return 0.0
    # project current_scores onto the reference bin edges
    cur_counts = [0] * len(ref_hist)
    for s in current_scores:
        idx = _bin_index(s, ref_bins)
        cur_counts[idx] += 1
    total = len(current_scores)
    eps = 1e-9
    psi = 0.0
    for ref_p, cur_c in zip(ref_hist, cur_counts):
        cur_p = cur_c / total
        ref_p_ = max(ref_p, eps)
        cur_p_ = max(cur_p, eps)
        psi += (cur_p_ - ref_p_) * math.log(cur_p_ / ref_p_)
    return round(psi, 4)


def _ks_statistic(ref: List[float], cur: List[float]) -> float:
    """Two-sample KS D-statistic (no scipy)."""
    if not ref or not cur:
        return 0.0
    ref_s = sorted(ref)
    cur_s = sorted(cur)
    nr, nc = len(ref_s), len(cur_s)
    # merge and walk both CDFs
    combined = sorted(ref_s + cur_s)
    ir = ic = 0
    max_d = 0.0
    for val in combined:
        while ir < nr and ref_s[ir] <= val:
            ir += 1
        while ic < nc and cur_s[ic] <= val:
            ic += 1
        d = abs(ir / nr - ic / nc)
        if d > max_d:
            max_d = d
    return round(max_d, 4)
