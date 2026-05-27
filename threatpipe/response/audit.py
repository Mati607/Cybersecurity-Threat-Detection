"""Append-only audit log for response actions.

Every action the response engine fires (success, dry-run, or failure)
is recorded here. The log is the source of truth for "what did we
automate, when, and what was the outcome", and is queryable via the
REST API.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional

from ..utils.timeutil import format_iso, now_epoch
from .actions import ActionResult, ActionStatus


@dataclass
class AuditEntry:
    entry_id: int
    timestamp: float
    playbook_id: Optional[str]
    step_id: Optional[str]
    action: str
    status: ActionStatus
    detail: str
    detection_id: Optional[str]
    incident_id: Optional[str]
    duration_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "timestamp_iso": format_iso(self.timestamp),
            "playbook_id": self.playbook_id,
            "step_id": self.step_id,
            "action": self.action,
            "status": self.status.value,
            "detail": self.detail,
            "detection_id": self.detection_id,
            "incident_id": self.incident_id,
            "duration_ms": round(self.duration_ms, 2),
            "metadata": dict(self.metadata),
        }


class AuditLog:
    def __init__(self, max_entries: int = 10_000, persist_path: Optional[str | Path] = None) -> None:
        self.max_entries = max_entries
        self.persist_path = Path(persist_path) if persist_path else None
        self._entries: Deque[AuditEntry] = deque(maxlen=max_entries)
        self._next_id = 1
        self._lock = threading.Lock()
        if self.persist_path:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        result: ActionResult,
        playbook_id: Optional[str],
        step_id: Optional[str],
        detection_id: Optional[str],
        incident_id: Optional[str],
    ) -> AuditEntry:
        with self._lock:
            entry = AuditEntry(
                entry_id=self._next_id,
                timestamp=result.finished_at or now_epoch(),
                playbook_id=playbook_id,
                step_id=step_id,
                action=result.action,
                status=result.status,
                detail=result.detail,
                detection_id=detection_id,
                incident_id=incident_id,
                duration_ms=result.duration_ms,
                metadata=dict(result.metadata),
            )
            self._next_id += 1
            self._entries.append(entry)
        if self.persist_path:
            try:
                with self.persist_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry.to_dict()) + "\n")
            except OSError:                                  # pragma: no cover
                pass
        return entry

    def list(
        self,
        *,
        limit: int = 100,
        status: Optional[ActionStatus] = None,
        action: Optional[str] = None,
        playbook_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> List[AuditEntry]:
        with self._lock:
            items: Iterable[AuditEntry] = reversed(self._entries)
        out: List[AuditEntry] = []
        for entry in items:
            if status and entry.status != status:
                continue
            if action and entry.action != action:
                continue
            if playbook_id and entry.playbook_id != playbook_id:
                continue
            if incident_id and entry.incident_id != incident_id:
                continue
            out.append(entry)
            if len(out) >= limit:
                break
        return out

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_action: Dict[str, int] = {}
            by_status: Dict[str, int] = {}
            for entry in self._entries:
                by_action[entry.action] = by_action.get(entry.action, 0) + 1
                by_status[entry.status.value] = by_status.get(entry.status.value, 0) + 1
            return {
                "total": len(self._entries),
                "by_action": by_action,
                "by_status": by_status,
                "next_id": self._next_id,
            }

    def __len__(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
