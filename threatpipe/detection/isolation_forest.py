"""Isolation Forest anomaly detector.

A hand-rolled Isolation Forest so the package stays scikit-learn-free
for the on-line path. The implementation follows Liu et al. (2008):

* sample ``sample_size`` events at random per tree
* recursively split on a random feature at a random threshold
* score by mean path length, normalized by the average path length
  ``c(n) = 2 * H(n-1) - 2 * (n-1) / n``

Only the score is exposed; tree internals are kept on the instance so
they can be persisted to disk (``save``/``load``) and re-loaded by the
API server without retraining.
"""

from __future__ import annotations

import math
import pickle
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from ..ingestion.event import Event
from ..utils.logging_setup import get_logger
from .base import BaseDetector, Detection, Severity
from .features import FeatureExtractor

_log = get_logger(__name__)


@dataclass
class _Node:
    feature: int = -1
    threshold: float = 0.0
    size: int = 0
    depth: int = 0
    left: Optional["_Node"] = None
    right: Optional["_Node"] = None


def _harmonic(n: int) -> float:
    if n <= 1:
        return 0.0
    return math.log(n - 1) + 0.5772156649


def _avg_path_length(n: int) -> float:
    if n <= 1:
        return 0.0
    return 2.0 * _harmonic(n) - 2.0 * (n - 1) / n


def _build_tree(
    points: Sequence[Sequence[float]],
    depth: int,
    max_depth: int,
    rng: random.Random,
) -> _Node:
    n = len(points)
    if n <= 1 or depth >= max_depth:
        return _Node(size=n, depth=depth)

    dims = len(points[0])
    # pick a feature that actually has spread, fall back to leaf if none
    attempts = 0
    while attempts < 8:
        attempts += 1
        feat = rng.randrange(dims)
        col = [p[feat] for p in points]
        lo, hi = min(col), max(col)
        if hi > lo:
            break
    else:
        return _Node(size=n, depth=depth)

    threshold = rng.uniform(lo, hi)
    left = [p for p in points if p[feat] < threshold]
    right = [p for p in points if p[feat] >= threshold]
    if not left or not right:
        return _Node(size=n, depth=depth)

    return _Node(
        feature=feat,
        threshold=threshold,
        size=n,
        depth=depth,
        left=_build_tree(left, depth + 1, max_depth, rng),
        right=_build_tree(right, depth + 1, max_depth, rng),
    )


def _path_length(node: _Node, x: Sequence[float], depth: int = 0) -> float:
    if node.feature == -1 or node.left is None or node.right is None:
        return depth + _avg_path_length(node.size)
    if x[node.feature] < node.threshold:
        return _path_length(node.left, x, depth + 1)
    return _path_length(node.right, x, depth + 1)


class IsolationForestDetector(BaseDetector):
    name = "isolation_forest"
    stateful = False

    def __init__(
        self,
        n_estimators: int = 64,
        sample_size: int = 256,
        contamination: float = 0.02,
        random_state: Optional[int] = 42,
        feature_extractor: Optional[FeatureExtractor] = None,
    ) -> None:
        self.n_estimators = n_estimators
        self.sample_size = sample_size
        self.contamination = contamination
        self.random_state = random_state
        self.extractor = feature_extractor or FeatureExtractor()
        self._trees: List[_Node] = []
        self._c_n: float = 1.0
        self._threshold: float = 0.6
        self._fitted: bool = False

    def fit(self, events: Iterable[Event]) -> None:
        rng = random.Random(self.random_state)
        events = list(events)
        if not events:
            _log.warning("isolation_forest.fit called with no events")
            return

        self.extractor.fit(events)
        X = self.extractor.transform_many(events)

        sample_size = min(self.sample_size, len(X))
        max_depth = int(math.ceil(math.log2(max(2, sample_size))))
        self._c_n = _avg_path_length(sample_size)
        self._trees = []
        for _ in range(self.n_estimators):
            sample = rng.sample(X, sample_size)
            self._trees.append(_build_tree(sample, 0, max_depth, rng))

        scores = [self._raw_score(x) for x in X]
        scores.sort()
        idx = max(0, min(len(scores) - 1, int(len(scores) * (1 - self.contamination))))
        self._threshold = scores[idx]
        self._fitted = True
        _log.info(
            "isolation_forest fitted: trees=%d sample=%d threshold=%.4f",
            len(self._trees), sample_size, self._threshold,
        )

    def _raw_score(self, x: Sequence[float]) -> float:
        if not self._trees or self._c_n == 0:
            return 0.0
        mean_path = sum(_path_length(t, x) for t in self._trees) / len(self._trees)
        return 2.0 ** (-mean_path / self._c_n)

    def detect(self, event: Event) -> Optional[Detection]:
        if not self._fitted:
            return None
        x = self.extractor.transform(event)
        s = self._raw_score(x)
        if s < self._threshold:
            return None
        return Detection(
            event=event,
            detector=self.name,
            score=min(1.0, max(0.0, s)),
            severity=Severity.from_score(s),
            reasons=[f"isolation score {s:.3f} >= threshold {self._threshold:.3f}"],
            tags=["anomaly", "ml"],
            metadata={"score_raw": round(s, 4), "threshold": round(self._threshold, 4)},
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(pickle.dumps({
            "trees": self._trees,
            "c_n": self._c_n,
            "threshold": self._threshold,
            "extractor": self.extractor,
        }))

    def load(self, path: str | Path) -> "IsolationForestDetector":
        blob = pickle.loads(Path(path).read_bytes())
        self._trees = blob["trees"]
        self._c_n = blob["c_n"]
        self._threshold = blob["threshold"]
        self.extractor = blob["extractor"]
        self._fitted = True
        return self
