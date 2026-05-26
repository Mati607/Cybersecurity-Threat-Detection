"""Incident value objects.

An :class:`Incident` is a correlated set of detections that an analyst
would treat as a single investigation. We deliberately keep the model
small and immutable-by-default — the aggregator owns mutation and
guards consistency through its own lock.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..detection.base import Detection, Severity


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class KillChainPhase(str, enum.Enum):
    RECON = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"
    UNKNOWN = "unknown"


@dataclass
class KillChainStep:
    phase: KillChainPhase
    timestamp: float
    detection_id: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "timestamp": self.timestamp,
            "detection_id": self.detection_id,
            "evidence": self.evidence,
        }


@dataclass
class Incident:
    incident_id: str
    title: str
    first_seen: float
    last_seen: float
    severity: Severity = Severity.MEDIUM
    score: float = 0.0
    status: IncidentStatus = IncidentStatus.OPEN
    detection_ids: List[str] = field(default_factory=list)
    affected_hosts: Set[str] = field(default_factory=set)
    affected_users: Set[str] = field(default_factory=set)
    affected_files: Set[str] = field(default_factory=set)
    affected_iocs: Set[Tuple[str, str]] = field(default_factory=set)
    kill_chain: List[KillChainStep] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    correlation_group_id: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def detection_count(self) -> int:
        return len(self.detection_ids)

    @property
    def is_active(self) -> bool:
        return self.status in (IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING)

    @property
    def covered_phases(self) -> Set[KillChainPhase]:
        return {step.phase for step in self.kill_chain}

    def update_severity_from_score(self) -> None:
        self.severity = Severity.from_score(self.score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity": self.severity.value,
            "score": round(self.score, 4),
            "status": self.status.value,
            "detection_count": self.detection_count,
            "detection_ids": list(self.detection_ids),
            "affected_hosts": sorted(self.affected_hosts),
            "affected_users": sorted(self.affected_users),
            "affected_files": sorted(self.affected_files),
            "affected_iocs": [list(t) for t in sorted(self.affected_iocs)],
            "kill_chain": [step.to_dict() for step in self.kill_chain],
            "covered_phases": sorted(p.value for p in self.covered_phases),
            "tags": sorted(self.tags),
            "correlation_group_id": self.correlation_group_id,
            "notes": list(self.notes),
        }
