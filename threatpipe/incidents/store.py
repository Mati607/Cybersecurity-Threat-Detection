"""Thread-safe in-memory incident store with filtering."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..utils.logging_setup import get_logger
from .model import Incident, IncidentStatus

_log = get_logger(__name__)


class IncidentStore:
    def __init__(self, max_size: int = 5000) -> None:
        self.max_size = max_size
        self._incidents: Dict[str, Incident] = {}
        self._lock = threading.RLock()

    def upsert(self, incident: Incident) -> None:
        with self._lock:
            self._incidents[incident.incident_id] = incident
            if len(self._incidents) > self.max_size:
                # drop the oldest resolved/false-positive entries first
                drop_candidates = sorted(
                    [i for i in self._incidents.values() if not i.is_active],
                    key=lambda i: i.last_seen,
                )
                while len(self._incidents) > self.max_size and drop_candidates:
                    victim = drop_candidates.pop(0)
                    self._incidents.pop(victim.incident_id, None)
                # if everything is still active, oldest-by-last-seen wins
                while len(self._incidents) > self.max_size:
                    oldest = min(self._incidents.values(), key=lambda i: i.last_seen)
                    self._incidents.pop(oldest.incident_id, None)

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return self._incidents.get(incident_id)

    def list(
        self,
        *,
        status: Optional[IncidentStatus] = None,
        min_severity: Optional[str] = None,
        host: Optional[str] = None,
        limit: int = 100,
    ) -> List[Incident]:
        from ..detection.base import Severity
        with self._lock:
            items = list(self._incidents.values())
        if status is not None:
            items = [i for i in items if i.status == status]
        if min_severity is not None:
            order = ["low", "medium", "high", "critical"]
            try:
                idx = order.index(min_severity.lower())
            except ValueError:
                idx = 0
            items = [i for i in items if order.index(i.severity.value) >= idx]
        if host is not None:
            items = [i for i in items if host in i.affected_hosts]
        items.sort(key=lambda i: (i.last_seen, i.score), reverse=True)
        return items[:limit]

    def remove(self, incident_id: str) -> bool:
        with self._lock:
            return self._incidents.pop(incident_id, None) is not None

    def update_status(self, incident_id: str, status: IncidentStatus, note: Optional[str] = None) -> Optional[Incident]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                return None
            incident.status = status
            if note:
                incident.notes.append(note)
            return incident

    def __len__(self) -> int:
        return len(self._incidents)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_status: Dict[str, int] = {}
            by_severity: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            for inc in self._incidents.values():
                by_status[inc.status.value] = by_status.get(inc.status.value, 0) + 1
                by_severity[inc.severity.value] = by_severity.get(inc.severity.value, 0) + 1
            return {
                "total": len(self._incidents),
                "by_status": by_status,
                "by_severity": by_severity,
            }

    def export_json(self, path: str | Path) -> int:
        with self._lock:
            data = [inc.to_dict() for inc in self._incidents.values()]
        Path(path).write_text(json.dumps({"incidents": data}, indent=2))
        return len(data)
