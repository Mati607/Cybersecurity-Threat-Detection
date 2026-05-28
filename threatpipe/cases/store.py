"""In-memory case store with optional JSON persistence + filtering."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..utils.logging_setup import get_logger
from .model import (
    Case,
    CasePriority,
    CaseStatus,
    CustodyAction,
    CustodyEntry,
    Evidence,
    EvidenceType,
    Note,
)

_log = get_logger(__name__)


class CaseStore:
    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else None
        self._cases: Dict[str, Case] = {}
        self._lock = threading.RLock()
        if self.path and self.path.exists():
            self.load()

    def put(self, case: Case) -> Case:
        with self._lock:
            self._cases[case.case_id] = case
        self.save()
        return case

    def get(self, case_id: str) -> Optional[Case]:
        with self._lock:
            return self._cases.get(case_id)

    def remove(self, case_id: str) -> bool:
        with self._lock:
            removed = self._cases.pop(case_id, None) is not None
        if removed:
            self.save()
        return removed

    def list(
        self,
        *,
        status: Optional[CaseStatus] = None,
        priority: Optional[CasePriority] = None,
        assignee: Optional[str] = None,
        open_only: bool = False,
        incident_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Case]:
        with self._lock:
            items = list(self._cases.values())
        if status is not None:
            items = [c for c in items if c.status == status]
        if priority is not None:
            items = [c for c in items if c.priority == priority]
        if assignee is not None:
            items = [c for c in items if c.assignee == assignee]
        if open_only:
            items = [c for c in items if not c.is_closed]
        if incident_id is not None:
            items = [c for c in items if incident_id in c.incident_ids]
        items.sort(key=lambda c: (c.priority.value, -c.updated_at))
        return items[:limit]

    def find_by_incident(self, incident_id: str) -> Optional[Case]:
        with self._lock:
            for case in self._cases.values():
                if incident_id in case.incident_ids:
                    return case
        return None

    def __len__(self) -> int:
        return len(self._cases)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_status: Dict[str, int] = {}
            by_priority: Dict[str, int] = {}
            open_count = 0
            for case in self._cases.values():
                by_status[case.status.value] = by_status.get(case.status.value, 0) + 1
                by_priority[case.priority.value] = by_priority.get(case.priority.value, 0) + 1
                if not case.is_closed:
                    open_count += 1
            return {
                "total": len(self._cases),
                "open": open_count,
                "by_status": by_status,
                "by_priority": by_priority,
            }

    # --- persistence ---------------------------------------------

    def save(self) -> None:
        if not self.path:
            return
        with self._lock:
            payload = {"cases": [c.to_dict() for c in self._cases.values()]}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        except OSError:                                      # pragma: no cover
            _log.exception("failed to persist case store")

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        items = data.get("cases", data) if isinstance(data, dict) else data
        with self._lock:
            self._cases.clear()
            for raw in items or []:
                case = _case_from_dict(raw)
                if case is not None:
                    self._cases[case.case_id] = case


def _case_from_dict(raw: Dict[str, Any]) -> Optional[Case]:
    try:
        case = Case(
            case_id=raw["case_id"],
            title=raw.get("title", ""),
            created_at=float(raw.get("created_at", 0.0)),
            updated_at=float(raw.get("updated_at", 0.0)),
            status=CaseStatus(raw.get("status", "new")),
            priority=CasePriority(raw.get("priority", "p3")),
            assignee=raw.get("assignee"),
            reporter=raw.get("reporter", "system"),
            description=raw.get("description", ""),
            incident_ids=list(raw.get("incident_ids", [])),
            tags=set(raw.get("tags", [])),
            closed_at=raw.get("closed_at"),
        )
    except (KeyError, ValueError):
        return None
    for n in raw.get("notes", []):
        case.notes.append(Note(note_id=n["note_id"], author=n["author"],
                                body=n["body"], created_at=float(n.get("created_at", 0.0))))
    for e in raw.get("evidence", []):
        try:
            case.evidence.append(Evidence(
                evidence_id=e["evidence_id"], type=EvidenceType(e["type"]),
                label=e.get("label", ""), ref=e.get("ref", ""),
                added_by=e.get("added_by", "system"), added_at=float(e.get("added_at", 0.0)),
                sha256=e.get("sha256"), metadata=dict(e.get("metadata", {})),
            ))
        except (KeyError, ValueError):
            continue
    for c in raw.get("custody", []):
        try:
            case.custody.append(CustodyEntry(
                seq=int(c["seq"]), action=CustodyAction(c["action"]), actor=c["actor"],
                timestamp=float(c["timestamp"]), detail=c.get("detail", ""),
                prev_hash=c.get("prev_hash", ""), entry_hash=c.get("entry_hash", ""),
            ))
        except (KeyError, ValueError):
            continue
    return case
