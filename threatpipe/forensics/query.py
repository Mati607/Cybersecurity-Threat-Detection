"""Higher-level read API over :class:`ForensicsStore`.

The store is a thin SQL layer — :class:`ForensicsQuery` adds the
analyst-shaped queries we keep wanting in practice: histograms over a
time range, top-N by host / detector, severity breakdowns. Everything
returns plain dicts so the REST handlers can pass results through
without conversion.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..utils.timeutil import format_iso
from .store import ForensicsStore


@dataclass(frozen=True)
class TimeRange:
    since: Optional[float] = None
    until: Optional[float] = None

    @property
    def span(self) -> float:
        if self.since is None or self.until is None:
            return 0.0
        return max(0.0, self.until - self.since)


@dataclass
class Aggregate:
    name: str
    buckets: List[Dict[str, Any]]
    total: int

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "total": self.total, "buckets": list(self.buckets)}


class ForensicsQuery:
    def __init__(self, store: ForensicsStore) -> None:
        self.store = store

    # --- time-series histograms ---------------------------------------

    def detections_histogram(self, *, range: TimeRange, bin_seconds: int = 60) -> Aggregate:
        if range.since is None or range.until is None or bin_seconds <= 0:
            return Aggregate(name="detections_histogram", buckets=[], total=0)
        n_bins = max(1, int(math.ceil(range.span / bin_seconds)))
        counts = [0] * n_bins
        sev_counts: List[Dict[str, int]] = [
            {"low": 0, "medium": 0, "high": 0, "critical": 0} for _ in range_(n_bins)
        ]
        total = 0
        for det in self.store.iter_detections(since=range.since, until=range.until, limit=100_000):
            idx = int((det.timestamp - range.since) // bin_seconds)
            if 0 <= idx < n_bins:
                counts[idx] += 1
                sev_counts[idx][det.severity] = sev_counts[idx].get(det.severity, 0) + 1
                total += 1
        buckets = [
            {
                "ts": range.since + i * bin_seconds,
                "ts_iso": format_iso(range.since + i * bin_seconds),
                "count": counts[i],
                "by_severity": sev_counts[i],
            }
            for i in range_(n_bins)
        ]
        return Aggregate(name="detections_histogram", buckets=buckets, total=total)

    # --- top-N aggregates ---------------------------------------------

    def top_detectors(self, *, range: TimeRange, limit: int = 10) -> Aggregate:
        counter: Dict[str, int] = {}
        total = 0
        for det in self.store.iter_detections(since=range.since, until=range.until, limit=100_000):
            counter[det.detector] = counter.get(det.detector, 0) + 1
            total += 1
        rows = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        return Aggregate(name="top_detectors", buckets=[{"detector": k, "count": v} for k, v in rows], total=total)

    def top_hosts(self, *, range: TimeRange, limit: int = 10) -> Aggregate:
        counter: Dict[str, int] = {}
        total = 0
        for det in self.store.iter_detections(since=range.since, until=range.until, limit=100_000):
            if not det.host:
                continue
            counter[det.host] = counter.get(det.host, 0) + 1
            total += 1
        rows = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        return Aggregate(name="top_hosts", buckets=[{"host": k, "count": v} for k, v in rows], total=total)

    def severity_breakdown(self, *, range: TimeRange) -> Aggregate:
        counter: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        total = 0
        for det in self.store.iter_detections(since=range.since, until=range.until, limit=100_000):
            counter[det.severity] = counter.get(det.severity, 0) + 1
            total += 1
        return Aggregate(name="severity_breakdown",
                          buckets=[{"severity": k, "count": v} for k, v in counter.items()], total=total)

    def event_volume_by_type(self, *, range: TimeRange) -> Aggregate:
        counter: Dict[str, int] = {}
        total = 0
        for ev in self.store.iter_events(since=range.since, until=range.until, limit=200_000):
            counter[ev.event_type] = counter.get(ev.event_type, 0) + 1
            total += 1
        rows = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)
        return Aggregate(name="event_volume_by_type",
                          buckets=[{"event_type": k, "count": v} for k, v in rows], total=total)

    # --- raw search ---------------------------------------------------

    def search_detections(
        self,
        *,
        range: TimeRange,
        host: Optional[str] = None,
        severity: Optional[str] = None,
        detector: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        items = list(self.store.iter_detections(
            since=range.since, until=range.until,
            host=host, severity=severity, detector=detector, limit=limit,
        ))
        return [d.to_dict() for d in items]

    def stats(self) -> Dict[str, Any]:
        return self.store.stats()


def range_(n: int):
    """Small wrapper to dodge the ``range`` keyword collision in this
    module (we shadow it with the dataclass ``TimeRange.range``-ish
    accessors elsewhere)."""
    i = 0
    while i < n:
        yield i
        i += 1
