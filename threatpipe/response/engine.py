"""Glue between the detection / incident layer and the action catalog.

The engine subscribes to two kinds of signals:

* every detection that survives the ensemble threshold
* every incident the aggregator opens or updates

For each signal it walks the registered playbooks, applies trigger /
condition / rate-limit checks, and runs the matching steps through
the action handlers. Results land in an :class:`AuditLog` regardless
of outcome.

The engine is deliberately optimistic: a failing playbook never
blocks subsequent ones, and a failing step inside a playbook only
aborts the playbook when ``continue_on_failure`` is false (the
default).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence

from ..detection.base import Detection
from ..utils.logging_setup import get_logger
from .actions import (
    DEFAULT_ACTIONS,
    ActionContext,
    ActionResult,
    ActionStatus,
    BaseAction,
)
from .audit import AuditLog
from .playbook import Playbook, PlaybookTrigger

_log = get_logger(__name__)


class ResponseEngine:
    def __init__(
        self,
        *,
        actions: Optional[Mapping[str, BaseAction]] = None,
        audit_log: Optional[AuditLog] = None,
        graph: Optional[Any] = None,
        global_dry_run: bool = False,
    ) -> None:
        self.actions: Dict[str, BaseAction] = dict(actions or DEFAULT_ACTIONS)
        self.audit_log = audit_log or AuditLog()
        self.graph = graph
        self.global_dry_run = global_dry_run
        self.playbooks: List[Playbook] = []
        self._lock = threading.RLock()
        self._fire_times: Dict[str, Deque[float]] = defaultdict(deque)

    # --- registration ---------------------------------------------

    def register_playbooks(self, playbooks: Iterable[Playbook]) -> None:
        with self._lock:
            self.playbooks.extend(playbooks)

    def replace_playbooks(self, playbooks: Iterable[Playbook]) -> None:
        with self._lock:
            self.playbooks = list(playbooks)
            self._fire_times.clear()

    def register_action(self, action: BaseAction) -> None:
        self.actions[action.name] = action

    def list_playbooks(self) -> List[Playbook]:
        with self._lock:
            return list(self.playbooks)

    # --- hooks ---------------------------------------------------

    def on_detection(self, detection: Detection) -> List[ActionResult]:
        scope = _detection_scope(detection)
        return self._fire(PlaybookTrigger.DETECTION, scope, detection=detection)

    def on_incident(self, incident: Any, *, new: bool = False) -> List[ActionResult]:
        scope = _incident_scope(incident)
        trigger = PlaybookTrigger.INCIDENT_OPENED if new else PlaybookTrigger.INCIDENT_UPDATED
        return self._fire(trigger, scope, incident=incident)

    def on_incident_status(self, incident: Any) -> List[ActionResult]:
        return self._fire(PlaybookTrigger.INCIDENT_STATUS,
                          _incident_scope(incident), incident=incident)

    # --- internals ------------------------------------------------

    def _fire(
        self,
        trigger: PlaybookTrigger,
        scope: Mapping[str, Any],
        *,
        detection: Optional[Detection] = None,
        incident: Optional[Any] = None,
    ) -> List[ActionResult]:
        results: List[ActionResult] = []
        for playbook in self._matching(trigger, scope):
            if not self._rate_limit_ok(playbook):
                _log.info("rate limit hit for playbook %s", playbook.playbook_id)
                continue
            for step in playbook.steps:
                action = self.actions.get(step.action)
                if action is None:
                    _log.warning("playbook %s references unknown action %s",
                                 playbook.playbook_id, step.action)
                    continue
                ctx = ActionContext(
                    detection=detection,
                    incident=incident,
                    args=_render_args(step.args, scope),
                    metadata={"graph": self.graph},
                    playbook_id=playbook.playbook_id,
                    step_id=step.step_id,
                    dry_run=self.global_dry_run or playbook.dry_run,
                )
                result = action(ctx)
                self.audit_log.record(
                    result=result,
                    playbook_id=playbook.playbook_id,
                    step_id=step.step_id,
                    detection_id=detection.event.event_id if detection else None,
                    incident_id=getattr(incident, "incident_id", None) if incident else None,
                )
                results.append(result)
                if result.status == ActionStatus.FAILURE and not step.continue_on_failure:
                    _log.warning("playbook %s aborted at step %s: %s",
                                 playbook.playbook_id, step.step_id, result.detail)
                    break
        return results

    def _matching(self, trigger: PlaybookTrigger, scope: Mapping[str, Any]) -> List[Playbook]:
        with self._lock:
            return [
                pb for pb in self.playbooks
                if pb.trigger == trigger and pb.is_applicable(scope)
            ]

    def _rate_limit_ok(self, playbook: Playbook) -> bool:
        now = time.time()
        with self._lock:
            stamps = self._fire_times[playbook.playbook_id]
            while stamps and stamps[0] < now - 60:
                stamps.popleft()
            if len(stamps) >= playbook.max_per_minute:
                return False
            stamps.append(now)
        return True


def _detection_scope(detection: Detection) -> Dict[str, Any]:
    return {
        "score": detection.score,
        "severity": detection.severity.value,
        "detector": detection.detector,
        "tags": list(detection.tags),
        "event": detection.event,
    }


def _incident_scope(incident: Any) -> Dict[str, Any]:
    return {
        "score": getattr(incident, "score", 0.0),
        "severity": getattr(incident.severity, "value", "low") if hasattr(incident, "severity") else "low",
        "tags": list(getattr(incident, "tags", []) or []),
        "status": getattr(incident.status, "value", "open") if hasattr(incident, "status") else "open",
        "incident_id": getattr(incident, "incident_id", None),
        "detection_count": getattr(incident, "detection_count", 0),
        "incident": incident,
    }


def _render_args(args: Mapping[str, Any], scope: Mapping[str, Any]) -> Dict[str, Any]:
    rendered: Dict[str, Any] = {}
    ctx = ActionContext(args=dict(scope))
    for key, value in args.items():
        if isinstance(value, str):
            rendered[key] = ctx.render(value)
        else:
            rendered[key] = value
    return rendered
