"""Thread-safe in-memory store of triaged alerts.

Keyed by ``fingerprint`` so the engine can answer "have we seen this
before?" in O(1) without scanning. ``alert_id`` is also indexed for the
API's by-id lookups. Eviction prefers closed/suppressed alerts so an
analyst's open backlog survives memory pressure; only when everything is
still active does it drop the stalest open alert.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..detection.base import Severity
from ..utils.logging_setup import get_logger
from .model import TriagePriority, TriagedAlert, TriageStatus

_log = get_logger(__name__)

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


class TriageStore:
    def __init__(self, max_size: int = 10_000) -> None:
        self.max_size = max_size
        self._by_fingerprint: Dict[str, TriagedAlert] = {}
        self._by_id: Dict[str, TriagedAlert] = {}
        self._lock = threading.RLock()

    def get_by_fingerprint(self, fingerprint: str) -> Optional[TriagedAlert]:
        with self._lock:
            return self._by_fingerprint.get(fingerprint)

    def get(self, alert_id: str) -> Optional[TriagedAlert]:
        with self._lock:
            return self._by_id.get(alert_id)

    def upsert(self, alert: TriagedAlert) -> None:
        with self._lock:
            self._by_fingerprint[alert.fingerprint] = alert
            self._by_id[alert.alert_id] = alert
            if len(self._by_id) > self.max_size:
                self._evict_locked()

    def _evict_locked(self) -> None:
        # Closed/suppressed first (oldest by last_seen), then stale active.
        dead = sorted(
            (a for a in self._by_id.values() if not a.is_active),
            key=lambda a: a.last_seen,
        )
        while len(self._by_id) > self.max_size and dead:
            self._drop_locked(dead.pop(0))
        while len(self._by_id) > self.max_size:
            oldest = min(self._by_id.values(), key=lambda a: a.last_seen)
            self._drop_locked(oldest)

    def _drop_locked(self, alert: TriagedAlert) -> None:
        self._by_id.pop(alert.alert_id, None)
        # Only clear the fingerprint slot if it still points at this alert.
        if self._by_fingerprint.get(alert.fingerprint) is alert:
            self._by_fingerprint.pop(alert.fingerprint, None)

    def remove(self, alert_id: str) -> bool:
        with self._lock:
            alert = self._by_id.get(alert_id)
            if alert is None:
                return False
            self._drop_locked(alert)
            return True

    def list(
        self,
        *,
        status: Optional[TriageStatus] = None,
        min_priority: Optional[TriagePriority] = None,
        min_severity: Optional[str] = None,
        host: Optional[str] = None,
        active_only: bool = False,
        limit: int = 100,
    ) -> List[TriagedAlert]:
        with self._lock:
            items = list(self._by_id.values())
        if status is not None:
            items = [a for a in items if a.status == status]
        if active_only:
            items = [a for a in items if a.is_active]
        if min_priority is not None:
            items = [a for a in items if a.priority.at_least(min_priority)]
        if min_severity is not None:
            try:
                idx = _SEVERITY_ORDER.index(min_severity.lower())
            except ValueError:
                idx = 0
            items = [a for a in items if _SEVERITY_ORDER.index(a.severity.value) >= idx]
        if host is not None:
            items = [a for a in items if host in a.hosts]
        # Most urgent first (P1<P5), then loudest, then most recent.
        items.sort(key=lambda a: (a.priority.value, -a.priority_score, -a.last_seen))
        return items[:limit]

    def update(
        self,
        alert_id: str,
        *,
        status: Optional[TriageStatus] = None,
        disposition=None,
        note: Optional[str] = None,
    ) -> Optional[TriagedAlert]:
        with self._lock:
            alert = self._by_id.get(alert_id)
            if alert is None:
                return None
            if status is not None:
                alert.status = status
            if disposition is not None:
                alert.disposition = disposition
            if note:
                alert.notes.append(note)
            return alert

    def __len__(self) -> int:
        return len(self._by_id)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            alerts = list(self._by_id.values())
        by_status: Dict[str, int] = {}
        by_priority: Dict[str, int] = {p.name: 0 for p in TriagePriority}
        by_severity: Dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        total_detections = 0
        for a in alerts:
            by_status[a.status.value] = by_status.get(a.status.value, 0) + 1
            by_priority[a.priority.name] += 1
            by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
            total_detections += a.count
        dedup_ratio = round(total_detections / len(alerts), 2) if alerts else 0.0
        return {
            "total_alerts": len(alerts),
            "active_alerts": sum(1 for a in alerts if a.is_active),
            "suppressed_alerts": sum(1 for a in alerts if a.is_suppressed),
            "total_detections": total_detections,
            "dedup_ratio": dedup_ratio,
            "by_status": by_status,
            "by_priority": by_priority,
            "by_severity": by_severity,
        }

    def export_json(self, path: str | Path) -> int:
        with self._lock:
            data = [a.to_dict() for a in self._by_id.values()]
        Path(path).write_text(json.dumps({"alerts": data}, indent=2))
        return len(data)
