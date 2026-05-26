"""Heuristic mapping from detection tags/event shape to a kill-chain phase.

We use a simple priority list so the first matching signal wins. This
is deliberately conservative — when we don't have enough information
we return ``UNKNOWN`` rather than guess; the timeline view is more
useful when phases are honest about what we don't know.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..detection.base import Detection
from ..ingestion.event import Event, EventType
from .model import KillChainPhase, KillChainStep


_TAG_HINTS: Tuple[Tuple[str, KillChainPhase], ...] = (
    ("reconnaissance", KillChainPhase.RECON),
    ("recon", KillChainPhase.RECON),
    ("scanning", KillChainPhase.RECON),
    ("weaponization", KillChainPhase.WEAPONIZATION),
    ("phish", KillChainPhase.DELIVERY),
    ("delivery", KillChainPhase.DELIVERY),
    ("execution", KillChainPhase.EXPLOITATION),
    ("exploit", KillChainPhase.EXPLOITATION),
    ("persistence", KillChainPhase.INSTALLATION),
    ("install", KillChainPhase.INSTALLATION),
    ("c2", KillChainPhase.COMMAND_AND_CONTROL),
    ("command_and_control", KillChainPhase.COMMAND_AND_CONTROL),
    ("beacon", KillChainPhase.COMMAND_AND_CONTROL),
    ("exfiltration", KillChainPhase.ACTIONS_ON_OBJECTIVES),
    ("impact", KillChainPhase.ACTIONS_ON_OBJECTIVES),
    ("ransomware", KillChainPhase.ACTIONS_ON_OBJECTIVES),
)

_MITRE_TO_PHASE = {
    # not exhaustive; just enough to cover the bundled rule catalog
    "T1027": KillChainPhase.WEAPONIZATION,
    "T1055": KillChainPhase.EXPLOITATION,
    "T1059": KillChainPhase.EXPLOITATION,
    "T1003": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1547": KillChainPhase.INSTALLATION,
    "T1078": KillChainPhase.EXPLOITATION,
    "T1071": KillChainPhase.COMMAND_AND_CONTROL,
    "T1486": KillChainPhase.ACTIONS_ON_OBJECTIVES,
}


def infer_phase(detection: Detection) -> KillChainPhase:
    tags = [t.lower() for t in detection.tags]
    # MITRE technique tags ("mitre:T1059" etc.) get first dibs
    for tag in tags:
        if tag.startswith("mitre:"):
            tech = tag.split(":", 1)[1].split(".", 1)[0].upper()
            phase = _MITRE_TO_PHASE.get(tech)
            if phase is not None:
                return phase
    for needle, phase in _TAG_HINTS:
        if any(needle in t for t in tags):
            return phase

    event = detection.event
    if event.event_type == EventType.AUTH:
        return KillChainPhase.EXPLOITATION
    if event.event_type == EventType.NETWORK:
        return KillChainPhase.COMMAND_AND_CONTROL
    if event.event_type == EventType.PROCESS:
        return KillChainPhase.EXPLOITATION
    if event.event_type == EventType.FILE and (event.action or "").lower() in ("write", "create"):
        return KillChainPhase.INSTALLATION
    return KillChainPhase.UNKNOWN


def project_killchain(detections: Iterable[Detection]) -> List[KillChainStep]:
    """Turn a set of detections into an ordered list of kill-chain steps."""
    steps: List[KillChainStep] = []
    for det in detections:
        phase = infer_phase(det)
        evidence = "; ".join(det.reasons[:2]) or det.detector
        steps.append(KillChainStep(
            phase=phase,
            timestamp=det.event.timestamp,
            detection_id=det.event.event_id,
            evidence=evidence,
        ))
    steps.sort(key=lambda s: s.timestamp)
    return steps
