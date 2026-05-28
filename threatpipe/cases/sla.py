"""SLA policy + evaluation for cases.

A case carries an implicit clock: how long until it must be
acknowledged (first response) and how long until it must be resolved.
:class:`SLAPolicy` keeps those windows per priority, and
:func:`evaluate_sla` returns whether a case is on track, at risk, or
breached, with the remaining time so a dashboard can color it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..utils.timeutil import now_epoch
from .model import Case, CasePriority, CaseStatus


class SLAStatus(str, enum.Enum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"        # within the warning window
    BREACHED = "breached"
    MET = "met"                # closed within the window
    NOT_APPLICABLE = "n/a"


# minutes per priority for (first-response, resolution)
_DEFAULT_RESPONSE_MIN = {
    CasePriority.P1: 15,
    CasePriority.P2: 60,
    CasePriority.P3: 240,
    CasePriority.P4: 1440,
}
_DEFAULT_RESOLVE_MIN = {
    CasePriority.P1: 240,
    CasePriority.P2: 1440,
    CasePriority.P3: 4320,
    CasePriority.P4: 10080,
}


@dataclass
class SLAPolicy:
    response_minutes: Dict[CasePriority, int] = field(
        default_factory=lambda: dict(_DEFAULT_RESPONSE_MIN))
    resolve_minutes: Dict[CasePriority, int] = field(
        default_factory=lambda: dict(_DEFAULT_RESOLVE_MIN))
    at_risk_fraction: float = 0.8     # flag when 80% of the window has elapsed

    def response_window_s(self, priority: CasePriority) -> int:
        return self.response_minutes.get(priority, 240) * 60

    def resolve_window_s(self, priority: CasePriority) -> int:
        return self.resolve_minutes.get(priority, 4320) * 60

    def to_dict(self) -> Dict[str, Any]:
        return {
            "response_minutes": {k.value: v for k, v in self.response_minutes.items()},
            "resolve_minutes": {k.value: v for k, v in self.resolve_minutes.items()},
            "at_risk_fraction": self.at_risk_fraction,
        }


def _first_response_ts(case: Case) -> Optional[float]:
    """When was the case first acknowledged (assigned or moved off NEW)?"""
    from .model import CustodyAction
    for entry in case.custody:
        if entry.action in (CustodyAction.ASSIGNED, CustodyAction.STATUS_CHANGED):
            return entry.timestamp
    return None


def evaluate_sla(case: Case, policy: SLAPolicy, *, now: Optional[float] = None) -> Dict[str, Any]:
    now = now if now is not None else now_epoch()

    resp_window = policy.response_window_s(case.priority)
    resp_deadline = case.created_at + resp_window
    first_resp = _first_response_ts(case)
    if first_resp is not None:
        response_status = SLAStatus.MET if first_resp <= resp_deadline else SLAStatus.BREACHED
        response_remaining = resp_deadline - first_resp
    else:
        response_remaining = resp_deadline - now
        response_status = _live_status(now, case.created_at, resp_window, policy.at_risk_fraction)

    resolve_window = policy.resolve_window_s(case.priority)
    resolve_deadline = case.created_at + resolve_window
    if case.is_closed and case.closed_at is not None:
        resolve_status = SLAStatus.MET if case.closed_at <= resolve_deadline else SLAStatus.BREACHED
        resolve_remaining = resolve_deadline - case.closed_at
    else:
        resolve_remaining = resolve_deadline - now
        resolve_status = _live_status(now, case.created_at, resolve_window, policy.at_risk_fraction)

    return {
        "priority": case.priority.value,
        "response": {
            "status": response_status.value,
            "deadline": resp_deadline,
            "remaining_s": round(response_remaining, 1),
        },
        "resolution": {
            "status": resolve_status.value,
            "deadline": resolve_deadline,
            "remaining_s": round(resolve_remaining, 1),
        },
    }


def _live_status(now: float, start: float, window_s: int, at_risk_fraction: float) -> SLAStatus:
    elapsed = now - start
    if elapsed >= window_s:
        return SLAStatus.BREACHED
    if elapsed >= window_s * at_risk_fraction:
        return SLAStatus.AT_RISK
    return SLAStatus.ON_TRACK
