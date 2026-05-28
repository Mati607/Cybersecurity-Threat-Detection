"""Auto-retraining framework for anomaly detectors.

``AutoTrainer`` monitors a :class:`MetricsTracker` and the
:class:`DriftDetector` for a specific model version.  When drift
crosses the configured threshold — or after a scheduled time interval
has elapsed — it emits a :class:`TrainEvent` and (optionally) calls
a user-supplied ``retrain_fn`` callback that actually rebuilds the
detector and registers the new version.

The scheduler runs in a daemon thread; a clean shutdown is triggered
by :meth:`stop`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import format_iso, now_epoch
from .drift import DriftAlert, DriftDetector, DriftSeverity
from .metrics import MetricsTracker

_log = get_logger(__name__)


class TrainReason(str, Enum):
    SCHEDULED = "scheduled"
    DRIFT_DETECTED = "drift_detected"
    MANUAL = "manual"
    INITIAL = "initial"


@dataclass
class TrainEvent:
    model_id: str
    version: int
    reason: TrainReason
    timestamp: float = field(default_factory=now_epoch)
    drift_alert: Optional[DriftAlert] = None
    success: bool = True
    new_version: Optional[int] = None
    error: str = ""
    duration_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "version": self.version,
            "reason": self.reason.value,
            "timestamp": self.timestamp,
            "timestamp_iso": format_iso(self.timestamp),
            "drift_alert": self.drift_alert.to_dict() if self.drift_alert else None,
            "success": self.success,
            "new_version": self.new_version,
            "error": self.error,
            "duration_s": round(self.duration_s, 3),
        }


class AutoTrainer:
    """Background trainer + drift monitor for a single model.

    Parameters
    ----------
    model_id:
        Identifier used in registry and log messages.
    tracker:
        :class:`MetricsTracker` recording live scores.
    drift_detector:
        Pre-configured :class:`DriftDetector`.
    retrain_fn:
        Callable ``(model_id, reason, old_version) -> new_version_int``.
        Called in the background thread; must be thread-safe.
    check_interval_s:
        How often (in seconds) to run the drift check.
    retrain_interval_s:
        How often to schedule a forced retrain regardless of drift.
        Set to 0 to disable.
    drift_severity_threshold:
        Minimum :class:`DriftSeverity` that triggers retraining.
    min_samples:
        Minimum number of samples needed before drift is evaluated.
    history_limit:
        Maximum number of :class:`TrainEvent` objects to keep in memory.
    """

    def __init__(
        self,
        model_id: str,
        tracker: MetricsTracker,
        drift_detector: DriftDetector,
        *,
        retrain_fn: Optional[Callable] = None,
        check_interval_s: float = 60.0,
        retrain_interval_s: float = 86_400.0,
        drift_severity_threshold: DriftSeverity = DriftSeverity.MEDIUM,
        min_samples: int = 100,
        history_limit: int = 200,
    ) -> None:
        self.model_id = model_id
        self.tracker = tracker
        self.drift_detector = drift_detector
        self.retrain_fn = retrain_fn
        self.check_interval_s = check_interval_s
        self.retrain_interval_s = retrain_interval_s
        self.drift_severity_threshold = drift_severity_threshold
        self.min_samples = min_samples
        self.history_limit = history_limit

        self._lock = threading.Lock()
        self._events: List[TrainEvent] = []
        self._last_retrain: float = 0.0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._current_version = tracker.version

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name=f"autotrainer-{self.model_id}", daemon=True
        )
        self._thread.start()
        _log.info("AutoTrainer started for %s", self.model_id)

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # ------------------------------------------------------------------
    # manual trigger
    # ------------------------------------------------------------------

    def trigger(self, *, reason: TrainReason = TrainReason.MANUAL) -> TrainEvent:
        return self._do_retrain(reason=reason, alert=None)

    def check_drift(self) -> Optional[DriftAlert]:
        buf = self.tracker.score_buffer()
        if len(buf) < self.min_samples or not self.drift_detector.has_reference():
            return None
        return self.drift_detector.evaluate(self.model_id, self._current_version, buf)

    # ------------------------------------------------------------------
    # history
    # ------------------------------------------------------------------

    def history(self) -> List[TrainEvent]:
        with self._lock:
            return list(self._events)

    def last_event(self) -> Optional[TrainEvent]:
        with self._lock:
            return self._events[-1] if self._events else None

    def status(self) -> Dict[str, Any]:
        with self._lock:
            last = self._events[-1] if self._events else None
        buf = self.tracker.score_buffer()
        alert = None
        if len(buf) >= self.min_samples and self.drift_detector.has_reference():
            alert = self.drift_detector.evaluate(
                self.model_id, self._current_version, buf
            )
        return {
            "model_id": self.model_id,
            "current_version": self._current_version,
            "running": self._running,
            "samples_collected": len(buf),
            "min_samples": self.min_samples,
            "last_retrain": format_iso(self._last_retrain) if self._last_retrain else None,
            "last_event": last.to_dict() if last else None,
            "current_drift": alert.to_dict() if alert else None,
            "check_interval_s": self.check_interval_s,
            "retrain_interval_s": self.retrain_interval_s,
        }

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.wait(self.check_interval_s):
            try:
                self._tick()
            except Exception as exc:  # pragma: no cover
                _log.error("AutoTrainer tick error for %s: %s", self.model_id, exc)

    def _tick(self) -> None:
        now = now_epoch()

        # scheduled retrain
        if (
            self.retrain_interval_s > 0
            and (now - self._last_retrain) >= self.retrain_interval_s
        ):
            _log.info("scheduled retrain for %s", self.model_id)
            self._do_retrain(reason=TrainReason.SCHEDULED, alert=None)
            return

        # drift check
        alert = self.check_drift()
        if alert and alert.triggered:
            sev_order = list(DriftSeverity)
            threshold_idx = sev_order.index(self.drift_severity_threshold)
            alert_idx = sev_order.index(alert.severity)
            if alert_idx >= threshold_idx:
                _log.warning(
                    "drift detected for %s (score=%.3f, severity=%s)",
                    self.model_id, alert.composite_score, alert.severity.value,
                )
                self._do_retrain(reason=TrainReason.DRIFT_DETECTED, alert=alert)

    def _do_retrain(self, *, reason: TrainReason, alert: Optional[DriftAlert]) -> TrainEvent:
        t0 = time.monotonic()
        event = TrainEvent(
            model_id=self.model_id,
            version=self._current_version,
            reason=reason,
            drift_alert=alert,
        )
        if self.retrain_fn is not None:
            try:
                new_ver = self.retrain_fn(self.model_id, reason, self._current_version)
                event.new_version = new_ver
                if new_ver is not None:
                    self._current_version = new_ver
                    # update reference distribution with current scores
                    buf = self.tracker.score_buffer()
                    if buf:
                        self.drift_detector.set_reference(buf)
            except Exception as exc:
                event.success = False
                event.error = str(exc)
                _log.error("retrain failed for %s: %s", self.model_id, exc)
        event.duration_s = time.monotonic() - t0
        self._last_retrain = now_epoch()
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.history_limit:
                self._events = self._events[-self.history_limit :]
        return event
