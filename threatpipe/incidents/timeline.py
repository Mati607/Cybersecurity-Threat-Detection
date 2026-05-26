"""Build human-readable incident timelines."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from ..detection.base import Detection
from ..utils.timeutil import format_iso
from .killchain import infer_phase
from .model import KillChainPhase


@dataclass
class TimelineEntry:
    timestamp: float
    kind: str                         # detection | escalation | note
    title: str
    description: str
    severity: str = "low"
    phase: KillChainPhase = KillChainPhase.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "timestamp_iso": format_iso(self.timestamp),
            "kind": self.kind,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "phase": self.phase.value,
        }


def build_timeline(detections: Iterable[Detection]) -> List[TimelineEntry]:
    entries: List[TimelineEntry] = []
    last_severity = None
    for det in sorted(detections, key=lambda d: d.event.timestamp):
        phase = infer_phase(det)
        entries.append(TimelineEntry(
            timestamp=det.event.timestamp,
            kind="detection",
            title=f"{det.severity.value.upper()} {det.detector}",
            description="; ".join(det.reasons[:3]) or f"score {det.score:.2f}",
            severity=det.severity.value,
            phase=phase,
        ))
        if last_severity is not None and det.severity.value != last_severity:
            entries.append(TimelineEntry(
                timestamp=det.event.timestamp,
                kind="escalation",
                title=f"severity {last_severity} -> {det.severity.value}",
                description="severity escalated by new detection",
                severity=det.severity.value,
                phase=phase,
            ))
        last_severity = det.severity.value
    return entries
