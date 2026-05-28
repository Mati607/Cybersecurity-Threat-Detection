"""Pipeline-side adapter that mirrors detections + events into the store.

The forensics layer is decoupled from the rest of the pipeline through
this thin sink so callers can plug it in conditionally — the rest of
the codebase has no compile-time dependency on SQLite.

The sink batches writes when called from the streaming worker so we
don't fsync per event. ``flush()`` is exposed for tests and CLI ad-hoc
flushes.
"""

from __future__ import annotations

import threading
from typing import Any, List, Optional

from ..detection.base import Detection
from ..ingestion.event import Event
from ..utils.logging_setup import get_logger
from .store import ForensicsStore

_log = get_logger(__name__)


class ForensicsSink:
    def __init__(
        self,
        store: ForensicsStore,
        *,
        record_events: bool = True,
        record_detections: bool = True,
        record_incidents: bool = True,
        buffer_size: int = 0,
    ) -> None:
        self.store = store
        self.record_events = record_events
        self.record_detections = record_detections
        self.record_incidents = record_incidents
        self.buffer_size = max(0, int(buffer_size))
        self._lock = threading.Lock()
        self._event_buf: List[Event] = []
        self._detection_buf: List[Detection] = []
        self._stats = {
            "events_written": 0,
            "detections_written": 0,
            "incidents_written": 0,
            "errors": 0,
        }

    # --- single-record entry points -------------------------------

    def on_event(self, event: Event) -> None:
        if not self.record_events:
            return
        if self.buffer_size <= 1:
            self._safe_write_event(event)
            return
        with self._lock:
            self._event_buf.append(event)
            if len(self._event_buf) >= self.buffer_size:
                self._drain_locked_events()

    def on_detection(self, detection: Detection) -> None:
        if not self.record_detections:
            return
        if self.buffer_size <= 1:
            self._safe_write_detection(detection)
            return
        with self._lock:
            self._detection_buf.append(detection)
            if len(self._detection_buf) >= self.buffer_size:
                self._drain_locked_detections()

    def on_incident(self, incident: Any) -> None:
        if not self.record_incidents:
            return
        try:
            self.store.record_incident(incident)
            self._stats["incidents_written"] += 1
        except Exception:                                   # pragma: no cover
            self._stats["errors"] += 1
            _log.exception("incident write failed")

    # --- internal -------------------------------------------------

    def _safe_write_event(self, event: Event) -> None:
        try:
            self.store.record_event(event)
            self._stats["events_written"] += 1
        except Exception:                                   # pragma: no cover
            self._stats["errors"] += 1
            _log.exception("event write failed")

    def _safe_write_detection(self, detection: Detection) -> None:
        try:
            self.store.record_detection(detection)
            self._stats["detections_written"] += 1
        except Exception:                                   # pragma: no cover
            self._stats["errors"] += 1
            _log.exception("detection write failed")

    def _drain_locked_events(self) -> None:
        for event in self._event_buf:
            self._safe_write_event(event)
        self._event_buf.clear()

    def _drain_locked_detections(self) -> None:
        for detection in self._detection_buf:
            self._safe_write_detection(detection)
        self._detection_buf.clear()

    # --- public flush --------------------------------------------

    def flush(self) -> None:
        with self._lock:
            self._drain_locked_events()
            self._drain_locked_detections()

    def stats(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            stats["pending_events"] = len(self._event_buf)
            stats["pending_detections"] = len(self._detection_buf)
        return stats
