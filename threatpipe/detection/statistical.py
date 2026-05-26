"""Online statistical anomaly detector.

Maintains a per-(host, event_type) windowed count and a per-host
exponentially weighted moving average / variance of:

* events-per-minute
* unique destination-port count
* unique process count
* outbound bytes

An event is flagged anomalous when the current value of one of these
streams exceeds the local EWMA by more than ``z_threshold`` standard
deviations. The score is a saturating function of the z-score so the
ensemble can blend it with the other detectors directly.

This is the kind of "is anything weird right now?" baseline that runs
in front of more expensive ML detectors, and it pays for itself by
catching scan-and-spray-style anomalies that signature rules miss.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from ..ingestion.event import Event
from .base import BaseDetector, Detection, Severity


@dataclass
class _EWMA:
    alpha: float = 0.05
    mean: float = 0.0
    var: float = 1.0
    seen: int = 0

    def update(self, value: float) -> Tuple[float, float]:
        if self.seen == 0:
            self.mean = value
            self.var = 1.0
        else:
            delta = value - self.mean
            self.mean += self.alpha * delta
            self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)
        self.seen += 1
        return self.mean, self.var

    def z(self, value: float) -> float:
        std = math.sqrt(max(self.var, 1e-6))
        return (value - self.mean) / std


@dataclass
class _HostState:
    last_minute: int = 0
    rate: int = 0
    unique_ports: Set[int] = field(default_factory=set)
    unique_procs: Set[str] = field(default_factory=set)
    bytes_window: int = 0
    rate_ewma: _EWMA = field(default_factory=_EWMA)
    ports_ewma: _EWMA = field(default_factory=_EWMA)
    procs_ewma: _EWMA = field(default_factory=_EWMA)
    bytes_ewma: _EWMA = field(default_factory=_EWMA)
    recent_minutes: Deque[int] = field(default_factory=lambda: deque(maxlen=60))


class StatisticalDetector(BaseDetector):
    name = "statistical"
    stateful = True

    def __init__(
        self,
        z_threshold: float = 3.5,
        warmup_events: int = 200,
        score_saturation: float = 8.0,
    ) -> None:
        self.z_threshold = z_threshold
        self.warmup_events = warmup_events
        self.score_saturation = score_saturation
        self._state: Dict[str, _HostState] = defaultdict(_HostState)
        self._total_seen = 0

    def reset(self) -> None:
        self._state.clear()
        self._total_seen = 0

    def detect(self, event: Event) -> Optional[Detection]:
        self._total_seen += 1
        key = event.host or "__unknown__"
        st = self._state[key]
        minute = int(event.timestamp // 60)

        if st.last_minute == 0:
            st.last_minute = minute

        # Time advanced — close the prior bucket.
        if minute != st.last_minute:
            self._close_bucket(st)
            st.last_minute = minute
            st.rate = 0
            st.unique_ports = set()
            st.unique_procs = set()
            st.bytes_window = 0

        st.rate += 1
        if event.dst_port is not None:
            st.unique_ports.add(int(event.dst_port))
        if event.process:
            st.unique_procs.add(event.process)
        if event.bytes_sent:
            try:
                st.bytes_window += int(event.bytes_sent)
            except (TypeError, ValueError):
                pass

        if self._total_seen < self.warmup_events:
            return None

        reasons: List[str] = []
        z_max = 0.0
        for label, current, ewma in (
            ("rate", st.rate, st.rate_ewma),
            ("ports", len(st.unique_ports), st.ports_ewma),
            ("procs", len(st.unique_procs), st.procs_ewma),
            ("bytes", st.bytes_window, st.bytes_ewma),
        ):
            if ewma.seen < 5:
                continue
            z = ewma.z(float(current))
            if z > self.z_threshold:
                reasons.append(f"{label} z={z:.2f} (cur={current:.0f} mean={ewma.mean:.2f})")
                z_max = max(z_max, z)

        if not reasons:
            return None

        score = min(1.0, z_max / self.score_saturation)
        return Detection(
            event=event,
            detector=self.name,
            score=score,
            severity=Severity.from_score(score),
            reasons=reasons,
            tags=["anomaly", "statistical"],
            metadata={
                "host": key,
                "minute": minute,
                "z_max": round(z_max, 3),
                "active_streams": len(reasons),
            },
        )

    def _close_bucket(self, st: _HostState) -> None:
        st.rate_ewma.update(float(st.rate))
        st.ports_ewma.update(float(len(st.unique_ports)))
        st.procs_ewma.update(float(len(st.unique_procs)))
        st.bytes_ewma.update(float(st.bytes_window))
        st.recent_minutes.append(st.rate)

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        return {
            host: {
                "rate_mean": st.rate_ewma.mean,
                "rate_var": st.rate_ewma.var,
                "ports_mean": st.ports_ewma.mean,
                "procs_mean": st.procs_ewma.mean,
                "bytes_mean": st.bytes_ewma.mean,
                "buckets_observed": st.rate_ewma.seen,
            }
            for host, st in self._state.items()
        }
