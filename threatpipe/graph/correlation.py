"""Graph-aware detection correlator.

The standard ensemble emits one detection per event. The correlator
keeps a rolling window of recent detections, projects them onto the
provenance graph, and groups detections that share a node neighborhood
within a configurable BFS radius.

The output is :class:`CorrelationGroup` objects that downstream code
(in particular the ``incidents`` module) treats as the seed for an
incident. Groups also carry a boosted score so a single low-score
detection that ends up being one of a chain inside an attacker's
neighborhood gets promoted appropriately.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Set

from ..detection.base import Detection, Severity
from ..utils.logging_setup import get_logger
from .nodes import NodeKey
from .provenance import ProvenanceGraph

_log = get_logger(__name__)


@dataclass
class CorrelationGroup:
    group_id: str
    seed_keys: Set[NodeKey]
    detections: List[Detection] = field(default_factory=list)
    score: float = 0.0
    severity: Severity = Severity.LOW
    first_seen: float = 0.0
    last_seen: float = 0.0
    tags: Set[str] = field(default_factory=set)

    def merge(self, other: "CorrelationGroup") -> None:
        self.seed_keys |= other.seed_keys
        seen_ids = {d.event.event_id for d in self.detections}
        for d in other.detections:
            if d.event.event_id not in seen_ids:
                self.detections.append(d)
        self.score = max(self.score, other.score)
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        self.tags |= other.tags
        self.severity = Severity.from_score(self.score)

    def to_dict(self) -> Dict[str, object]:
        return {
            "group_id": self.group_id,
            "seed_keys": [list(k) for k in self.seed_keys],
            "detection_count": len(self.detections),
            "score": round(self.score, 4),
            "severity": self.severity.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": sorted(self.tags),
            "detection_ids": [d.event.event_id for d in self.detections],
        }


class GraphCorrelator:
    def __init__(
        self,
        graph: ProvenanceGraph,
        *,
        window_seconds: float = 300.0,
        radius: int = 2,
        score_boost: float = 0.15,
    ) -> None:
        self.graph = graph
        self.window_seconds = window_seconds
        self.radius = radius
        self.score_boost = score_boost
        self._lock = threading.Lock()
        self._groups: Dict[str, CorrelationGroup] = {}
        self._recent: Deque[CorrelationGroup] = deque()
        self._next_id = 1

    def correlate(self, detection: Detection, touched: Sequence[NodeKey]) -> CorrelationGroup:
        neighborhood = self._neighborhood(touched)
        with self._lock:
            self._purge_expired(now=detection.event.timestamp)
            target = self._find_overlapping(neighborhood)
            if target is None:
                target = CorrelationGroup(
                    group_id=f"G-{self._next_id:06d}",
                    seed_keys=set(touched),
                    first_seen=detection.event.timestamp,
                    last_seen=detection.event.timestamp,
                )
                self._next_id += 1
                self._groups[target.group_id] = target
                self._recent.append(target)
            target.seed_keys |= set(touched)
            if all(d.event.event_id != detection.event.event_id for d in target.detections):
                target.detections.append(detection)
            target.last_seen = max(target.last_seen, detection.event.timestamp)
            target.score = min(
                1.0,
                max(target.score, detection.score) + self.score_boost * (len(target.detections) - 1),
            )
            target.severity = Severity.from_score(target.score)
            target.tags.update(detection.tags)
            return target

    def _neighborhood(self, seeds: Iterable[NodeKey]) -> Set[NodeKey]:
        keys: Set[NodeKey] = set()
        frontier = list(seeds)
        for _ in range(max(0, self.radius)):
            next_frontier: List[NodeKey] = []
            for k in frontier:
                if k in keys:
                    continue
                keys.add(k)
                for edge in self.graph.edges_from(k):
                    if edge.dst not in keys:
                        next_frontier.append(edge.dst)
                for edge in self.graph.edges_to(k):
                    if edge.src not in keys:
                        next_frontier.append(edge.src)
            frontier = next_frontier
        keys.update(frontier)
        return keys

    def _find_overlapping(self, neighborhood: Set[NodeKey]) -> Optional[CorrelationGroup]:
        best: Optional[CorrelationGroup] = None
        best_overlap = 0
        for group in self._groups.values():
            overlap = len(group.seed_keys & neighborhood)
            if overlap > best_overlap:
                best = group
                best_overlap = overlap
        return best

    def _purge_expired(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._recent and self._recent[0].last_seen < cutoff:
            stale = self._recent.popleft()
            self._groups.pop(stale.group_id, None)

    def active_groups(self) -> List[CorrelationGroup]:
        with self._lock:
            return list(self._groups.values())

    def reset(self) -> None:
        with self._lock:
            self._groups.clear()
            self._recent.clear()
