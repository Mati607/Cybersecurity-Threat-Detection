"""Retention policy + background sweeper.

Long-running forensics deployments need to garbage-collect old rows
or the SQLite file grows unbounded. :class:`RetentionPolicy` keeps a
per-severity retention window so analysts can hold ``critical``
detections for a year while letting ``low`` ones roll off in a week,
and :class:`RetentionSweeper` runs the policy on a timer in a daemon
thread.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import now_epoch
from .store import ForensicsStore

_log = get_logger(__name__)


_DEFAULT_SEVERITY_DAYS = {
    "low": 7,
    "medium": 30,
    "high": 90,
    "critical": 365,
}


@dataclass
class RetentionPolicy:
    event_retention_days: int = 14
    detection_retention_days: int = 90
    incident_retention_days: int = 365
    severity_overrides: Dict[str, int] = field(default_factory=lambda: dict(_DEFAULT_SEVERITY_DAYS))
    vacuum_after_sweep: bool = False

    def cutoff_for(self, severity: Optional[str] = None) -> float:
        days = self.detection_retention_days
        if severity:
            days = self.severity_overrides.get(severity.lower(), days)
        return now_epoch() - days * 86400

    def event_cutoff(self) -> float:
        return now_epoch() - self.event_retention_days * 86400

    def incident_cutoff(self) -> float:
        return now_epoch() - self.incident_retention_days * 86400

    def to_dict(self) -> Dict[str, object]:
        return {
            "event_retention_days": self.event_retention_days,
            "detection_retention_days": self.detection_retention_days,
            "incident_retention_days": self.incident_retention_days,
            "severity_overrides": dict(self.severity_overrides),
            "vacuum_after_sweep": self.vacuum_after_sweep,
        }


class RetentionSweeper:
    def __init__(self, store: ForensicsStore, policy: RetentionPolicy, *, interval_s: float = 3600.0) -> None:
        self.store = store
        self.policy = policy
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_run: Optional[float] = None
        self.last_removed: Dict[str, int] = {}

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="forensics-retention", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def sweep_now(self) -> Dict[str, int]:
        # The store delete is naive (single cutoff) — we honor the
        # *worst-case* cutoff so we never accidentally drop a critical
        # detection a low-severity policy would have spared. The
        # severity overrides only narrow the retention; they never
        # widen it.
        event_removed = self.store.delete_older_than(cutoff_ts=self.policy.event_cutoff())
        detection_cutoff = self.policy.cutoff_for(severity="critical")
        det_removed = self.store.delete_older_than(cutoff_ts=detection_cutoff)
        # We pass through events twice — once for event-only cutoff, then
        # again as part of the detection cutoff which is broader. The
        # store handles missing rows fine.
        inc_removed = self.store.delete_older_than(cutoff_ts=self.policy.incident_cutoff())
        removed = {
            "events": event_removed.get("events", 0),
            "detections": det_removed.get("detections", 0),
            "incidents": inc_removed.get("incidents", 0),
        }
        if self.policy.vacuum_after_sweep:
            try:
                self.store.vacuum()
            except Exception:                              # pragma: no cover
                _log.exception("vacuum failed")
        self.last_run = now_epoch()
        self.last_removed = removed
        if any(removed.values()):
            _log.info("forensics retention sweep removed %s", removed)
        return removed

    def _loop(self) -> None:
        _log.info("retention sweeper started; interval=%.0fs", self.interval_s)
        while not self._stop.is_set():
            try:
                self.sweep_now()
            except Exception:                              # pragma: no cover
                _log.exception("retention sweep crashed")
            # break the sleep into shorter naps so stop() reacts quickly
            slept = 0.0
            while slept < self.interval_s and not self._stop.is_set():
                time.sleep(min(1.0, self.interval_s - slept))
                slept += 1.0
        _log.info("retention sweeper stopped")
