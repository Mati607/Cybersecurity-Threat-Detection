"""Triage value objects.

The triage layer sits between raw detections and the analyst-facing
alerts/incidents. A :class:`TriagedAlert` is the *deduplicated* unit an
analyst actually works: many near-identical detections collapse into one
alert whose ``count`` grows as the same activity recurs. The engine owns
mutation (see :mod:`threatpipe.triage.engine`); the dataclasses here stay
small and serializable so the store and API can round-trip them.

The two enums an analyst cares about are orthogonal:

* :class:`TriageStatus` — *where the alert is in the workflow* (new,
  acknowledged, suppressed, closed). Mutated by analysts and by the
  suppression engine.
* :class:`TriageDisposition` — *what the alert turned out to be* (true
  positive, false positive, benign). Mutated by analysts and recycled as
  feedback into suppression rules.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..detection.base import Detection, Severity


class TriagePriority(int, enum.Enum):
    """Analyst work-queue priority, P1 (highest) … P5 (lowest).

    Distinct from :class:`Severity` on purpose: severity is a property of
    a single detection, priority is a property of the *deduplicated*
    alert and folds in frequency, host spread, and intel context. A
    low-severity detector firing across forty hosts can out-prioritize a
    one-off critical.
    """

    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4
    P5 = 5

    @property
    def label(self) -> str:
        return {
            TriagePriority.P1: "critical",
            TriagePriority.P2: "high",
            TriagePriority.P3: "moderate",
            TriagePriority.P4: "low",
            TriagePriority.P5: "informational",
        }[self]

    def at_least(self, other: "TriagePriority") -> bool:
        """``True`` when this priority is *as urgent or more* than ``other``.

        P1 is the most urgent, so "more urgent" means a *smaller* value.
        """
        return self.value <= other.value


class TriageStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"
    CLOSED = "closed"


class TriageDisposition(str, enum.Enum):
    UNDETERMINED = "undetermined"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    DUPLICATE = "duplicate"


# Statuses that still demand analyst attention. Suppressed/closed alerts
# are kept for audit but never re-forwarded or counted as backlog.
_ACTIVE_STATUSES = frozenset(
    {TriageStatus.NEW, TriageStatus.ACKNOWLEDGED, TriageStatus.IN_PROGRESS, TriageStatus.ESCALATED}
)

# Cap how much per-detection detail an alert hoards. A noisy fingerprint
# can absorb tens of thousands of detections; we only keep a sample so the
# store stays bounded and ``to_dict`` payloads stay small.
_MAX_SAMPLE_IDS = 50
_MAX_SAMPLE_REASONS = 8


@dataclass
class TriagedAlert:
    """A deduplicated, prioritized alert built from one or more detections."""

    alert_id: str
    fingerprint: str
    title: str
    detector: str
    first_seen: float
    last_seen: float
    severity: Severity = Severity.LOW
    priority: TriagePriority = TriagePriority.P4
    priority_score: float = 0.0
    status: TriageStatus = TriageStatus.NEW
    disposition: TriageDisposition = TriageDisposition.UNDETERMINED
    count: int = 0
    max_score: float = 0.0
    hosts: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    sample_reasons: List[str] = field(default_factory=list)
    sample_detection_ids: List[str] = field(default_factory=list)
    suppressed_by: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.status in _ACTIVE_STATUSES

    @property
    def is_suppressed(self) -> bool:
        return self.status == TriageStatus.SUPPRESSED

    @property
    def age_s(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def distinct_hosts(self) -> int:
        return len(self.hosts)

    def absorb(self, detection: Detection) -> None:
        """Fold a fresh detection into this alert (idempotent on event id).

        The engine guarantees the fingerprint matches before calling this;
        here we just merge the bookkeeping. Duplicate event ids are ignored
        so a replay doesn't inflate ``count``.
        """
        event = detection.event
        if event.event_id in self.sample_detection_ids:
            return
        self.count += 1
        self.last_seen = max(self.last_seen, event.timestamp)
        self.first_seen = min(self.first_seen, event.timestamp)
        self.max_score = max(self.max_score, float(detection.score))
        if detection.severity.at_least(self.severity):
            self.severity = detection.severity
        if event.host:
            self.hosts.add(event.host)
        if event.user:
            self.users.add(event.user)
        self.tags.update(detection.tags)
        for reason in detection.reasons:
            if reason not in self.sample_reasons and len(self.sample_reasons) < _MAX_SAMPLE_REASONS:
                self.sample_reasons.append(reason)
        if len(self.sample_detection_ids) < _MAX_SAMPLE_IDS:
            self.sample_detection_ids.append(event.event_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "detector": self.detector,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "age_s": round(self.age_s, 3),
            "severity": self.severity.value,
            "priority": self.priority.value,
            "priority_label": self.priority.label,
            "priority_score": round(self.priority_score, 4),
            "status": self.status.value,
            "disposition": self.disposition.value,
            "count": self.count,
            "max_score": round(self.max_score, 4),
            "distinct_hosts": self.distinct_hosts,
            "hosts": sorted(self.hosts),
            "users": sorted(self.users),
            "tags": sorted(self.tags),
            "sample_reasons": list(self.sample_reasons),
            "sample_detection_ids": list(self.sample_detection_ids),
            "suppressed_by": self.suppressed_by,
            "notes": list(self.notes),
            "metadata": dict(self.metadata),
        }


@dataclass
class SuppressionRule:
    """A rule that silences alerts matching a set of field conditions.

    Conditions are matched against the *detection's event* plus a couple
    of synthetic fields (``detector``, ``severity``, ``tag``). Values
    support a trailing ``*`` wildcard so an analyst can suppress, say,
    ``process=/usr/bin/*`` without enumerating every binary.

    ``max_severity`` is a safety valve: a rule only suppresses detections
    at or below that ceiling, so a broad "ignore this scanner" rule can't
    accidentally swallow a genuinely critical detection from the same
    source. ``expires_at`` lets analysts add time-boxed suppressions
    during maintenance windows.
    """

    rule_id: str
    name: str = ""
    match: Dict[str, str] = field(default_factory=dict)
    max_severity: Severity = Severity.CRITICAL
    reason: str = ""
    created_by: str = "system"
    created_at: float = 0.0
    expires_at: Optional[float] = None
    enabled: bool = True
    hit_count: int = 0

    def is_expired(self, now: float) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def matches(self, detection: Detection) -> bool:
        """Return ``True`` when every condition matches the detection."""
        if not self.match:
            return False
        if not detection.severity.at_least(Severity.LOW):  # defensive; always true
            return False
        # The ceiling: never suppress something more severe than allowed.
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if order.index(detection.severity) > order.index(self.max_severity):
            return False
        for field_name, expected in self.match.items():
            actual = self._extract(detection, field_name)
            if not _value_matches(actual, expected):
                return False
        return True

    @staticmethod
    def _extract(detection: Detection, field_name: str) -> Any:
        if field_name == "detector":
            return detection.detector
        if field_name == "severity":
            return detection.severity.value
        if field_name == "tag":
            return list(detection.tags)
        return getattr(detection.event, field_name, None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "match": dict(self.match),
            "max_severity": self.max_severity.value,
            "reason": self.reason,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SuppressionRule":
        data = dict(raw)
        if not data.get("rule_id"):
            raise ValueError("rule_id is required")
        sev = data.get("max_severity", "critical")
        if not isinstance(sev, Severity):
            try:
                sev = Severity(sev)
            except ValueError:
                sev = Severity.CRITICAL
        return cls(
            rule_id=data["rule_id"],
            name=data.get("name", ""),
            match=dict(data.get("match", {})),
            max_severity=sev,
            reason=data.get("reason", ""),
            created_by=data.get("created_by", "system"),
            created_at=float(data.get("created_at", 0.0)),
            expires_at=data.get("expires_at"),
            enabled=bool(data.get("enabled", True)),
            hit_count=int(data.get("hit_count", 0)),
        )


def _value_matches(actual: Any, expected: str) -> bool:
    """Glob-lite match: trailing ``*`` is a prefix match, else equality.

    Lists (e.g. tags) match if *any* element matches, so
    ``tag=mitre:T1059`` hits a detection carrying that tag among others.
    """
    if actual is None:
        return False
    if isinstance(actual, (list, tuple, set)):
        return any(_value_matches(item, expected) for item in actual)
    actual_s = str(actual)
    if expected.endswith("*"):
        return actual_s.startswith(expected[:-1])
    return actual_s == expected
