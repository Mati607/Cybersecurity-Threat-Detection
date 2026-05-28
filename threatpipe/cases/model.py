"""Case-management value objects.

A :class:`Case` is the analyst-owned investigation wrapper around one
or more incidents. Where an :class:`~threatpipe.incidents.Incident` is
machine-generated and mutates as detections stream in, a case is
human-owned: it carries notes, attached evidence, assignment, priority,
and an immutable chain-of-custody log so the investigation is
defensible if it ends up in front of auditors or in court.
"""

from __future__ import annotations

import enum
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..utils.timeutil import format_iso, now_epoch


class CaseStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    CLOSED_RESOLVED = "closed_resolved"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"
    CLOSED_DUPLICATE = "closed_duplicate"

    @property
    def is_closed(self) -> bool:
        return self.value.startswith("closed_")


class CasePriority(str, enum.Enum):
    P1 = "p1"   # critical
    P2 = "p2"   # high
    P3 = "p3"   # medium
    P4 = "p4"   # low

    @classmethod
    def from_severity(cls, severity: str) -> "CasePriority":
        return {
            "critical": cls.P1,
            "high": cls.P2,
            "medium": cls.P3,
            "low": cls.P4,
        }.get(str(severity).lower(), cls.P3)


class EvidenceType(str, enum.Enum):
    DETECTION = "detection"
    EVENT = "event"
    IOC = "ioc"
    FILE = "file"
    GRAPH_SNAPSHOT = "graph_snapshot"
    LOG_EXCERPT = "log_excerpt"
    SCREENSHOT = "screenshot"
    NOTE = "note"
    EXTERNAL = "external"


class CustodyAction(str, enum.Enum):
    CREATED = "created"
    ASSIGNED = "assigned"
    STATUS_CHANGED = "status_changed"
    PRIORITY_CHANGED = "priority_changed"
    NOTE_ADDED = "note_added"
    EVIDENCE_ADDED = "evidence_added"
    EVIDENCE_REMOVED = "evidence_removed"
    INCIDENT_LINKED = "incident_linked"
    REOPENED = "reopened"
    CLOSED = "closed"


@dataclass
class Note:
    note_id: str
    author: str
    body: str
    created_at: float = field(default_factory=now_epoch)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "author": self.author,
            "body": self.body,
            "created_at": self.created_at,
            "created_iso": format_iso(self.created_at),
        }


@dataclass
class Evidence:
    evidence_id: str
    type: EvidenceType
    label: str
    ref: str                       # detection uid, event id, file path, ...
    added_by: str
    added_at: float = field(default_factory=now_epoch)
    sha256: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def hash_content(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "type": self.type.value,
            "label": self.label,
            "ref": self.ref,
            "added_by": self.added_by,
            "added_at": self.added_at,
            "added_iso": format_iso(self.added_at),
            "sha256": self.sha256,
            "metadata": dict(self.metadata),
        }


@dataclass
class CustodyEntry:
    seq: int
    action: CustodyAction
    actor: str
    timestamp: float
    detail: str = ""
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = f"{self.seq}|{self.action.value}|{self.actor}|{self.timestamp:.6f}|{self.detail}|{self.prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "action": self.action.value,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "timestamp_iso": format_iso(self.timestamp),
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


@dataclass
class Case:
    case_id: str
    title: str
    created_at: float = field(default_factory=now_epoch)
    updated_at: float = field(default_factory=now_epoch)
    status: CaseStatus = CaseStatus.NEW
    priority: CasePriority = CasePriority.P3
    assignee: Optional[str] = None
    reporter: str = "system"
    description: str = ""
    incident_ids: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    notes: List[Note] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    custody: List[CustodyEntry] = field(default_factory=list)
    closed_at: Optional[float] = None

    @property
    def is_closed(self) -> bool:
        return self.status.is_closed

    @property
    def age_seconds(self) -> float:
        end = self.closed_at if self.closed_at else now_epoch()
        return max(0.0, end - self.created_at)

    def custody_is_valid(self) -> bool:
        """Verify the hash chain hasn't been tampered with."""
        prev = ""
        for entry in self.custody:
            expected = CustodyEntry(
                seq=entry.seq, action=entry.action, actor=entry.actor,
                timestamp=entry.timestamp, detail=entry.detail, prev_hash=prev,
            ).compute_hash()
            if entry.entry_hash != expected or entry.prev_hash != prev:
                return False
            prev = entry.entry_hash
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "created_at": self.created_at,
            "created_iso": format_iso(self.created_at),
            "updated_at": self.updated_at,
            "status": self.status.value,
            "priority": self.priority.value,
            "assignee": self.assignee,
            "reporter": self.reporter,
            "description": self.description,
            "incident_ids": list(self.incident_ids),
            "tags": sorted(self.tags),
            "note_count": len(self.notes),
            "evidence_count": len(self.evidence),
            "notes": [n.to_dict() for n in self.notes],
            "evidence": [e.to_dict() for e in self.evidence],
            "custody": [c.to_dict() for c in self.custody],
            "custody_valid": self.custody_is_valid(),
            "is_closed": self.is_closed,
            "age_seconds": round(self.age_seconds, 2),
        }


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"
