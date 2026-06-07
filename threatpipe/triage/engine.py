"""The triage engine: dedup → suppress → prioritize → forward.

This is the orchestration layer the pipeline plugs in as an alert sink.
For each incoming :class:`~threatpipe.detection.base.Detection` it:

1. computes a :mod:`fingerprint <threatpipe.triage.fingerprint>` and finds
   or creates the matching :class:`~threatpipe.triage.model.TriagedAlert`
   (collapsing recurrence into a ``count``);
2. checks the :class:`~threatpipe.triage.suppression.SuppressionList` and
   silences the alert if a rule matches;
3. (re)scores priority with the :class:`~threatpipe.triage.priority.PriorityScorer`;
4. forwards *actionable* alerts to an optional downstream sink — once on
   creation, and again only when an alert's priority escalates, so the
   downstream channel (Slack, PagerDuty, …) sees signal, not the raw
   detection firehose.

The engine itself is a callable ``Detection -> None`` so it drops into the
existing ``alert_sink`` slot, but :meth:`ingest` returns a rich
:class:`TriageResult` that tests and the API use directly.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from ..detection.base import Detection
from ..utils.logging_setup import get_logger
from .fingerprint import describe
from .fingerprint import fingerprint as compute_fingerprint
from .model import TriagedAlert, TriagePriority, TriageStatus
from .priority import PriorityScorer
from .store import TriageStore
from .suppression import SuppressionList

_log = get_logger(__name__)

DownstreamSink = Callable[[TriagedAlert], None]


@dataclass
class TriageResult:
    """Outcome of ingesting one detection."""

    alert: TriagedAlert
    is_new: bool
    suppressed: bool
    escalated: bool
    forwarded: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert": self.alert.to_dict(),
            "is_new": self.is_new,
            "suppressed": self.suppressed,
            "escalated": self.escalated,
            "forwarded": self.forwarded,
        }


class TriageEngine:
    def __init__(
        self,
        store: Optional[TriageStore] = None,
        suppressions: Optional[SuppressionList] = None,
        scorer: Optional[PriorityScorer] = None,
        *,
        downstream: Optional[DownstreamSink] = None,
        dedup_window_s: float = 3600.0,
        escalate_at: TriagePriority = TriagePriority.P2,
    ) -> None:
        self.store = store or TriageStore()
        self.suppressions = suppressions or SuppressionList()
        self.scorer = scorer or PriorityScorer()
        self.downstream = downstream
        # After this much quiet, the same fingerprint starts a fresh alert
        # rather than reviving a long-dormant one — yesterday's brute-force
        # and today's shouldn't share a count.
        self.dedup_window_s = dedup_window_s
        self.escalate_at = escalate_at
        self._lock = threading.RLock()
        self._next_id = 1
        self._forwarded = 0
        self._suppressed = 0

    # -- main entry point -------------------------------------------------
    def ingest(self, detection: Detection) -> TriageResult:
        digest = compute_fingerprint(detection)
        intel_hit = self._has_intel_match(detection)

        with self._lock:
            existing = self.store.get_by_fingerprint(digest)
            now = detection.event.timestamp or time.time()
            reusable = (
                existing is not None
                and existing.is_active
                and (now - existing.last_seen) <= self.dedup_window_s
            )
            if reusable:
                alert = existing
                is_new = False
            else:
                alert = self._new_alert(digest, detection)
                is_new = True

            prev_priority = alert.priority
            alert.absorb(detection)

            # Suppression is evaluated every time: a rule added after an
            # alert opened should silence subsequent recurrences too.
            matched = self.suppressions.match(detection)
            if matched is not None and alert.status != TriageStatus.SUPPRESSED:
                alert.status = TriageStatus.SUPPRESSED
                alert.suppressed_by = matched.rule_id
                self._suppressed += 1
                _log.debug("alert %s suppressed by rule %s", alert.alert_id, matched.rule_id)

            self.scorer.assign(alert, intel_hit=intel_hit)
            if intel_hit:
                alert.metadata["intel_hit"] = True

            escalated = (
                not is_new
                and alert.is_active
                and alert.priority.at_least(self.escalate_at)
                and not prev_priority.at_least(self.escalate_at)
            )
            if escalated and alert.status == TriageStatus.ACKNOWLEDGED:
                # A re-escalation pulls an acknowledged alert back onto the
                # active radar.
                alert.status = TriageStatus.ESCALATED

            self.store.upsert(alert)

        forwarded = self._maybe_forward(alert, is_new=is_new, escalated=escalated)
        return TriageResult(
            alert=alert,
            is_new=is_new,
            suppressed=alert.is_suppressed,
            escalated=escalated,
            forwarded=forwarded,
        )

    def __call__(self, detection: Detection) -> None:
        """AlertSink-compatible entry point."""
        try:
            self.ingest(detection)
        except Exception:                                   # pragma: no cover
            _log.exception("triage engine failed on detection")

    # -- helpers ----------------------------------------------------------
    def _new_alert(self, digest: str, detection: Detection) -> TriagedAlert:
        alert_id = f"ALERT-{self._next_id:06d}"
        self._next_id += 1
        ts = detection.event.timestamp or time.time()
        return TriagedAlert(
            alert_id=alert_id,
            fingerprint=digest,
            title=describe(detection),
            detector=detection.detector,
            first_seen=ts,
            last_seen=ts,
            severity=detection.severity,
        )

    def _maybe_forward(self, alert: TriagedAlert, *, is_new: bool, escalated: bool) -> bool:
        if self.downstream is None or alert.is_suppressed:
            return False
        if not (is_new or escalated):
            return False
        try:
            self.downstream(alert)
            self._forwarded += 1
            return True
        except Exception:                                   # pragma: no cover
            _log.exception("triage downstream sink failed")
            return False

    @staticmethod
    def _has_intel_match(detection: Detection) -> bool:
        if any(t.startswith("intel") or t == "ioc" for t in detection.tags):
            return True
        matches = detection.metadata.get("matches")
        return bool(matches)

    # -- introspection ----------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        return {
            **self.store.stats(),
            "suppression": self.suppressions.stats(),
            "forwarded_downstream": self._forwarded,
            "suppressed_events": self._suppressed,
            "dedup_window_s": self.dedup_window_s,
            "escalate_at": self.escalate_at.value,
        }

    def reset(self) -> None:
        with self._lock:
            self._next_id = 1
            self._forwarded = 0
            self._suppressed = 0
