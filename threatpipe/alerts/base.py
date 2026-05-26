"""Alert sink contract and shared utilities.

Sinks are callables ``Detection -> None``. We model the interface as an
abstract base class so concrete sinks can keep configuration on the
instance, but the pipeline only ever invokes ``sink(detection)``.
"""

from __future__ import annotations

import abc
import threading
import time
from collections import deque
from typing import Deque, Iterable, List, Optional

from ..detection.base import Detection, Severity
from ..utils.logging_setup import get_logger

_log = get_logger(__name__)


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def severity_at_least(observed: Severity, threshold: Severity) -> bool:
    return _SEVERITY_ORDER.index(observed) >= _SEVERITY_ORDER.index(threshold)


class AlertSink(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    def emit(self, detection: Detection) -> None:
        ...

    def __call__(self, detection: Detection) -> None:
        try:
            self.emit(detection)
        except Exception:                                    # pragma: no cover
            _log.exception("alert sink %s failed", self.name)


class NullSink(AlertSink):
    name = "null"

    def emit(self, detection: Detection) -> None:
        return None


class MultiSink(AlertSink):
    name = "multi"

    def __init__(self, sinks: Iterable[AlertSink]) -> None:
        self.sinks: List[AlertSink] = list(sinks)

    def emit(self, detection: Detection) -> None:
        for sink in self.sinks:
            sink(detection)


class RateLimitedSink(AlertSink):
    """Wrap a sink with a sliding-window rate limit."""

    def __init__(self, inner: AlertSink, per_minute: int) -> None:
        self.inner = inner
        self.per_minute = max(1, per_minute)
        self._stamps: Deque[float] = deque()
        self._lock = threading.Lock()
        self._dropped = 0

    @property
    def name(self) -> str:                                  # pragma: no cover
        return f"ratelimited({self.inner.name})"

    def emit(self, detection: Detection) -> None:
        now = time.time()
        with self._lock:
            while self._stamps and self._stamps[0] < now - 60:
                self._stamps.popleft()
            if len(self._stamps) >= self.per_minute:
                self._dropped += 1
                if self._dropped % 50 == 1:
                    _log.warning(
                        "alert rate-limit (%d/min) hit on %s; dropped=%d",
                        self.per_minute, self.inner.name, self._dropped,
                    )
                return
            self._stamps.append(now)
        self.inner.emit(detection)

    @property
    def dropped(self) -> int:
        return self._dropped


class SeverityFilterSink(AlertSink):
    """Forward only detections at or above a severity floor."""

    def __init__(self, inner: AlertSink, min_severity: Severity) -> None:
        self.inner = inner
        self.min_severity = min_severity

    @property
    def name(self) -> str:                                  # pragma: no cover
        return f"min={self.min_severity.value}({self.inner.name})"

    def emit(self, detection: Detection) -> None:
        if not severity_at_least(detection.severity, self.min_severity):
            return
        self.inner.emit(detection)
