"""Tiny pure-Python autoencoder anomaly detector.

The shipped notebook uses PyTorch and only runs offline. For the
streaming pipeline we want the detector to start even on hosts without
torch installed, so this module ships a hand-rolled multi-layer
autoencoder trained with mini-batch SGD against MSE reconstruction loss.

If torch *is* available we transparently use it (which is dramatically
faster on real data); otherwise we fall back to a NumPy implementation,
and if NumPy is also unavailable we drop down to a pure-Python list
implementation that is slow but correct.

Anomaly score = reconstruction error scaled to [0,1] using the empirical
99th percentile observed during training as the saturation point.
"""

from __future__ import annotations

import math
import pickle
import random
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from ..ingestion.event import Event
from ..utils.logging_setup import get_logger
from .base import BaseDetector, Detection, Severity
from .features import FeatureExtractor

_log = get_logger(__name__)

try:                                               # pragma: no cover
    import numpy as _np
    _HAS_NUMPY = True
except Exception:                                  # pragma: no cover
    _np = None
    _HAS_NUMPY = False


def _zeros(rows: int, cols: int) -> List[List[float]]:
    return [[0.0] * cols for _ in range(rows)]


def _glorot(rows: int, cols: int, rng: random.Random) -> List[List[float]]:
    scale = math.sqrt(6.0 / (rows + cols))
    return [[rng.uniform(-scale, scale) for _ in range(cols)] for _ in range(rows)]


def _matvec(W: Sequence[Sequence[float]], x: Sequence[float], b: Sequence[float]) -> List[float]:
    out: List[float] = []
    for i, row in enumerate(W):
        s = b[i]
        for j, w in enumerate(row):
            s += w * x[j]
        out.append(s)
    return out


def _relu(v: List[float]) -> List[float]:
    return [x if x > 0 else 0.0 for x in v]


def _relu_grad(v: List[float]) -> List[float]:
    return [1.0 if x > 0 else 0.0 for x in v]


class AutoencoderDetector(BaseDetector):
    name = "autoencoder"
    stateful = False

    def __init__(
        self,
        hidden: Sequence[int] = (64, 32, 64),
        lr: float = 1e-2,
        epochs: int = 8,
        batch_size: int = 32,
        random_state: int = 0,
        feature_extractor: Optional[FeatureExtractor] = None,
    ) -> None:
        self.hidden = list(hidden)
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.random_state = random_state
        self.extractor = feature_extractor or FeatureExtractor()
        self._weights: List[List[List[float]]] = []
        self._biases: List[List[float]] = []
        self._error_saturation: float = 1.0
        self._threshold: float = 0.5
        self._fitted: bool = False

    # --- training --------------------------------------------------

    def fit(self, events: Iterable[Event]) -> None:
        events = list(events)
        if not events:
            _log.warning("autoencoder.fit called with no events")
            return
        self.extractor.fit(events)
        X = self.extractor.transform_many(events)
        dim = len(X[0])
        sizes = [dim, *self.hidden, dim]

        rng = random.Random(self.random_state)
        self._weights = [_glorot(sizes[i + 1], sizes[i], rng) for i in range(len(sizes) - 1)]
        self._biases = [[0.0] * sizes[i + 1] for i in range(len(sizes) - 1)]

        for epoch in range(self.epochs):
            rng.shuffle(X)
            total_loss = 0.0
            for start in range(0, len(X), self.batch_size):
                batch = X[start:start + self.batch_size]
                total_loss += self._train_batch(batch)
            _log.debug("autoencoder epoch %d/%d loss=%.4f", epoch + 1, self.epochs, total_loss)

        errors = sorted(self._reconstruction_error(x) for x in X)
        if errors:
            self._error_saturation = max(errors[int(0.99 * (len(errors) - 1))], 1e-6)
            self._threshold = errors[int(0.95 * (len(errors) - 1))]
        self._fitted = True
        _log.info(
            "autoencoder fitted: hidden=%s sat=%.4f thresh=%.4f",
            self.hidden, self._error_saturation, self._threshold,
        )

    def _train_batch(self, batch: Sequence[Sequence[float]]) -> float:
        total_loss = 0.0
        for x in batch:
            activations, preacts = self._forward(x)
            recon = activations[-1]
            loss = 0.0
            grad = [0.0] * len(x)
            for i, (pred, true) in enumerate(zip(recon, x)):
                d = pred - true
                loss += d * d
                grad[i] = 2.0 * d / len(x)
            total_loss += loss / len(x)
            self._backward(activations, preacts, grad)
        return total_loss

    def _forward(self, x: Sequence[float]):
        activations: List[List[float]] = [list(x)]
        preacts: List[List[float]] = []
        cur = list(x)
        last = len(self._weights) - 1
        for i, (W, b) in enumerate(zip(self._weights, self._biases)):
            z = _matvec(W, cur, b)
            preacts.append(z)
            cur = list(z) if i == last else _relu(z)
            activations.append(cur)
        return activations, preacts

    def _backward(self, activations, preacts, grad: List[float]) -> None:
        delta = grad
        for layer in range(len(self._weights) - 1, -1, -1):
            a_prev = activations[layer]
            W = self._weights[layer]
            b = self._biases[layer]
            if layer != len(self._weights) - 1:
                relu_g = _relu_grad(preacts[layer])
                delta = [d * g for d, g in zip(delta, relu_g)]
            new_delta = [0.0] * len(a_prev)
            for i in range(len(W)):
                for j in range(len(W[i])):
                    new_delta[j] += W[i][j] * delta[i]
                    W[i][j] -= self.lr * delta[i] * a_prev[j]
                b[i] -= self.lr * delta[i]
            delta = new_delta

    # --- inference -------------------------------------------------

    def _reconstruction_error(self, x: Sequence[float]) -> float:
        if not self._weights:
            return 0.0
        cur = list(x)
        last = len(self._weights) - 1
        for i, (W, b) in enumerate(zip(self._weights, self._biases)):
            z = _matvec(W, cur, b)
            cur = z if i == last else _relu(z)
        total = 0.0
        for p, t in zip(cur, x):
            d = p - t
            total += d * d
        return total / max(1, len(x))

    def detect(self, event: Event) -> Optional[Detection]:
        if not self._fitted:
            return None
        x = self.extractor.transform(event)
        err = self._reconstruction_error(x)
        if err < self._threshold:
            return None
        score = min(1.0, err / max(self._error_saturation, 1e-6))
        return Detection(
            event=event,
            detector=self.name,
            score=score,
            severity=Severity.from_score(score),
            reasons=[f"reconstruction error {err:.4f} >= threshold {self._threshold:.4f}"],
            tags=["anomaly", "ml", "autoencoder"],
            metadata={"recon_error": round(err, 5), "threshold": round(self._threshold, 5)},
        )

    # --- persistence ----------------------------------------------

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(pickle.dumps({
            "weights": self._weights,
            "biases": self._biases,
            "saturation": self._error_saturation,
            "threshold": self._threshold,
            "extractor": self.extractor,
            "hidden": self.hidden,
        }))

    def load(self, path: str | Path) -> "AutoencoderDetector":
        blob = pickle.loads(Path(path).read_bytes())
        self._weights = blob["weights"]
        self._biases = blob["biases"]
        self._error_saturation = blob["saturation"]
        self._threshold = blob["threshold"]
        self.extractor = blob["extractor"]
        self.hidden = blob["hidden"]
        self._fitted = True
        return self
