"""Case lifecycle operations with chain-of-custody enforcement.

Every mutation to a case goes through the manager so it can append a
tamper-evident custody entry. The custody log is a hash chain: each
entry hashes its own contents plus the previous entry's hash, so any
post-hoc edit invalidates every subsequent link (verifiable via
:meth:`Case.custody_is_valid`).

The manager is the only writer of custody entries - callers never
construct them directly.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import now_epoch
from .model import (
    Case,
    CasePriority,
    CaseStatus,
    CustodyAction,
    CustodyEntry,
    Evidence,
    EvidenceType,
    Note,
    new_id,
)
from .store import CaseStore

_log = get_logger(__name__)


class CaseManager:
    def __init__(self, store: Optional[CaseStore] = None) -> None:
        # NB: CaseStore defines __len__, so an empty store is falsy -
        # must check identity, not truthiness, or we'd silently drop a
        # caller-supplied (persistent) store on the floor.
        self.store = store if store is not None else CaseStore()
        self._lock = threading.RLock()

    # --- custody helper -------------------------------------------

    def _append_custody(self, case: Case, action: CustodyAction, actor: str, detail: str = "") -> CustodyEntry:
        prev_hash = case.custody[-1].entry_hash if case.custody else ""
        entry = CustodyEntry(
            seq=len(case.custody) + 1,
            action=action,
            actor=actor,
            timestamp=now_epoch(),
            detail=detail,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        case.custody.append(entry)
        case.updated_at = entry.timestamp
        return entry

    # --- lifecycle ------------------------------------------------

    def open_case(
        self,
        title: str,
        *,
        reporter: str = "system",
        description: str = "",
        priority: CasePriority = CasePriority.P3,
        incident_ids: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> Case:
        with self._lock:
            case = Case(
                case_id=new_id("CASE"),
                title=title,
                reporter=reporter,
                description=description,
                priority=priority,
                incident_ids=list(incident_ids or []),
                tags=set(tags or []),
            )
            self._append_custody(case, CustodyAction.CREATED, reporter,
                                  f"opened with priority {priority.value}")
            for inc_id in case.incident_ids:
                self._append_custody(case, CustodyAction.INCIDENT_LINKED, reporter, inc_id)
            self.store.put(case)
            return case

    def open_from_incident(self, incident: Any, *, reporter: str = "system") -> Case:
        """Create (or return existing) case for an incident."""
        with self._lock:
            inc_id = getattr(incident, "incident_id", None)
            if inc_id:
                existing = self.store.find_by_incident(inc_id)
                if existing is not None:
                    return existing
            severity = getattr(getattr(incident, "severity", None), "value", "medium")
            title = getattr(incident, "title", None) or f"Investigation for {inc_id}"
            case = self.open_case(
                title=title,
                reporter=reporter,
                description=f"Auto-created from incident {inc_id}",
                priority=CasePriority.from_severity(severity),
                incident_ids=[inc_id] if inc_id else [],
                tags=list(getattr(incident, "tags", []) or []),
            )
            return case

    def assign(self, case_id: str, assignee: str, *, actor: str = "system") -> Optional[Case]:
        with self._lock:
            case = self.store.get(case_id)
            if case is None:
                return None
            case.assignee = assignee
            self._append_custody(case, CustodyAction.ASSIGNED, actor, f"assigned to {assignee}")
            self.store.put(case)
            return case

    def change_status(self, case_id: str, status: CaseStatus, *, actor: str = "system",
                      reason: str = "") -> Optional[Case]:
        with self._lock:
            case = self.store.get(case_id)
            if case is None:
                return None
            was_closed = case.is_closed
            old = case.status
            case.status = status
            if status.is_closed and not was_closed:
                case.closed_at = now_epoch()
                self._append_custody(case, CustodyAction.CLOSED, actor,
                                     f"{old.value} -> {status.value} ({reason})".strip())
            elif was_closed and not status.is_closed:
                case.closed_at = None
                self._append_custody(case, CustodyAction.REOPENED, actor,
                                     f"{old.value} -> {status.value} ({reason})".strip())
            else:
                self._append_custody(case, CustodyAction.STATUS_CHANGED, actor,
                                     f"{old.value} -> {status.value} ({reason})".strip())
            self.store.put(case)
            return case

    def set_priority(self, case_id: str, priority: CasePriority, *, actor: str = "system") -> Optional[Case]:
        with self._lock:
            case = self.store.get(case_id)
            if case is None:
                return None
            old = case.priority
            case.priority = priority
            self._append_custody(case, CustodyAction.PRIORITY_CHANGED, actor,
                                 f"{old.value} -> {priority.value}")
            self.store.put(case)
            return case

    # --- content --------------------------------------------------

    def add_note(self, case_id: str, author: str, body: str) -> Optional[Note]:
        with self._lock:
            case = self.store.get(case_id)
            if case is None:
                return None
            note = Note(note_id=new_id("NOTE"), author=author, body=body)
            case.notes.append(note)
            self._append_custody(case, CustodyAction.NOTE_ADDED, author, note.note_id)
            self.store.put(case)
            return note

    def add_evidence(
        self,
        case_id: str,
        *,
        type: EvidenceType,
        label: str,
        ref: str,
        added_by: str = "system",
        content: Optional[bytes] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Evidence]:
        with self._lock:
            case = self.store.get(case_id)
            if case is None:
                return None
            sha = Evidence.hash_content(content) if content is not None else None
            ev = Evidence(
                evidence_id=new_id("EVD"),
                type=type,
                label=label,
                ref=ref,
                added_by=added_by,
                sha256=sha,
                metadata=dict(metadata or {}),
            )
            case.evidence.append(ev)
            self._append_custody(case, CustodyAction.EVIDENCE_ADDED, added_by,
                                 f"{type.value}:{ev.evidence_id}" + (f" sha256={sha[:12]}" if sha else ""))
            self.store.put(case)
            return ev

    def remove_evidence(self, case_id: str, evidence_id: str, *, actor: str = "system") -> bool:
        with self._lock:
            case = self.store.get(case_id)
            if case is None:
                return False
            before = len(case.evidence)
            case.evidence = [e for e in case.evidence if e.evidence_id != evidence_id]
            if len(case.evidence) == before:
                return False
            self._append_custody(case, CustodyAction.EVIDENCE_REMOVED, actor, evidence_id)
            self.store.put(case)
            return True

    def link_incident(self, case_id: str, incident_id: str, *, actor: str = "system") -> Optional[Case]:
        with self._lock:
            case = self.store.get(case_id)
            if case is None:
                return None
            if incident_id not in case.incident_ids:
                case.incident_ids.append(incident_id)
                self._append_custody(case, CustodyAction.INCIDENT_LINKED, actor, incident_id)
                self.store.put(case)
            return case

    # --- read -----------------------------------------------------

    def get(self, case_id: str) -> Optional[Case]:
        return self.store.get(case_id)

    def verify_custody(self, case_id: str) -> Optional[bool]:
        case = self.store.get(case_id)
        return None if case is None else case.custody_is_valid()
