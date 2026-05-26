"""Promote correlation groups into long-lived incidents.

The :class:`~threatpipe.graph.GraphCorrelator` produces transient
:class:`CorrelationGroup`s while events stream in. The aggregator
hooks onto those events, materializes them into :class:`Incident`s in
the :class:`IncidentStore`, and keeps the kill-chain projection up to
date.

We deliberately don't open a new incident per detection — a single
detection isn't worth waking an analyst up. We only promote a
correlation group once it crosses ``min_score`` *and* either contains
multiple detections or hits a severity floor.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ..detection.base import Detection, Severity
from ..graph.correlation import CorrelationGroup
from ..utils.logging_setup import get_logger
from .killchain import project_killchain
from .model import Incident, IncidentStatus, KillChainPhase, KillChainStep
from .store import IncidentStore

_log = get_logger(__name__)


class IncidentAggregator:
    def __init__(
        self,
        store: IncidentStore,
        *,
        min_score: float = 0.55,
        min_severity: Severity = Severity.MEDIUM,
        min_detections_low_score: int = 3,
    ) -> None:
        self.store = store
        self.min_score = min_score
        self.min_severity = min_severity
        self.min_detections_low_score = min_detections_low_score
        self._lock = threading.RLock()
        self._group_to_incident: Dict[str, str] = {}
        self._detections_by_group: Dict[str, List[Detection]] = defaultdict(list)
        self._next_id = 1

    def ingest(self, group: CorrelationGroup, detection: Detection) -> Optional[Incident]:
        """Update incident state from a correlator update.

        Returns the incident that ended up reflecting the change, or
        ``None`` when the group hasn't passed the promotion threshold
        yet.
        """
        with self._lock:
            store = self._detections_by_group[group.group_id]
            if all(d.event.event_id != detection.event.event_id for d in store):
                store.append(detection)

            if not self._should_promote(group, store):
                return None

            incident_id = self._group_to_incident.get(group.group_id)
            if incident_id is None:
                incident = self._materialize(group, store)
                self._group_to_incident[group.group_id] = incident.incident_id
                self.store.upsert(incident)
                _log.info(
                    "opened incident %s from group %s (score=%.2f, dets=%d)",
                    incident.incident_id, group.group_id, incident.score, len(store),
                )
                return incident

            incident = self.store.get(incident_id)
            if incident is None:
                # store may have evicted it under memory pressure — recreate
                incident = self._materialize(group, store, override_id=incident_id)
                self.store.upsert(incident)
                return incident
            self._update(incident, group, store)
            self.store.upsert(incident)
            return incident

    def _should_promote(self, group: CorrelationGroup, detections: List[Detection]) -> bool:
        if group.score >= self.min_score and group.severity.at_least(self.min_severity):
            return True
        if len(detections) >= self.min_detections_low_score:
            return True
        return False

    def _materialize(
        self,
        group: CorrelationGroup,
        detections: List[Detection],
        *,
        override_id: Optional[str] = None,
    ) -> Incident:
        if override_id is None:
            incident_id = f"INC-{self._next_id:06d}"
            self._next_id += 1
        else:
            incident_id = override_id
        title = self._build_title(detections)
        incident = Incident(
            incident_id=incident_id,
            title=title,
            first_seen=group.first_seen,
            last_seen=group.last_seen,
            severity=group.severity,
            score=group.score,
            correlation_group_id=group.group_id,
        )
        self._update(incident, group, detections)
        return incident

    def _update(self, incident: Incident, group: CorrelationGroup, detections: List[Detection]) -> None:
        incident.first_seen = min(incident.first_seen or group.first_seen, group.first_seen)
        incident.last_seen = max(incident.last_seen, group.last_seen)
        incident.score = max(incident.score, group.score)
        incident.severity = Severity.from_score(incident.score)
        incident.detection_ids = sorted({d.event.event_id for d in detections})
        incident.tags.update(group.tags)
        for d in detections:
            ev = d.event
            if ev.host:
                incident.affected_hosts.add(ev.host)
            if ev.user:
                incident.affected_users.add(ev.user)
            if ev.file_path:
                incident.affected_files.add(ev.file_path)
            for match in d.metadata.get("matches", []) or []:
                ioc = match.get("ioc") if isinstance(match, dict) else None
                if isinstance(ioc, dict) and ioc.get("type") and ioc.get("value"):
                    incident.affected_iocs.add((ioc["type"], ioc["value"]))
        incident.kill_chain = project_killchain(detections)
        # Keep the most informative title as the highest-severity reason.
        candidate_title = self._build_title(detections)
        if candidate_title:
            incident.title = candidate_title

    def _build_title(self, detections: List[Detection]) -> str:
        if not detections:
            return "Unidentified correlated activity"
        top = max(detections, key=lambda d: d.score)
        hosts = sorted({d.event.host for d in detections if d.event.host})
        host_str = f" on {hosts[0]}" if hosts else ""
        if len(hosts) > 1:
            host_str += f" (+{len(hosts) - 1} hosts)"
        if top.reasons:
            primary = top.reasons[0]
            return f"{top.severity.value.title()}: {primary[:120]}{host_str}"
        return f"{top.severity.value.title()} {top.detector} activity{host_str}"

    def reset(self) -> None:
        with self._lock:
            self._group_to_incident.clear()
            self._detections_by_group.clear()
