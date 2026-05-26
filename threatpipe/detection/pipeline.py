"""High-level detection pipeline.

Glues together:

* the event queue produced by an ingestion source
* the ensemble of detectors
* an optional alert sink (kept as a generic callable so the alerts
  package can be wired in without a circular dependency)

The pipeline runs in its own thread; ``run_once`` is exposed as a sync
helper used by tests and by the CLI ``replay`` sub-command.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from ..ingestion.base import EventQueue
from ..ingestion.event import Event
from ..utils.config import PipelineConfig
from ..utils.logging_setup import get_logger
from .base import BaseDetector, Detection
from .ensemble import EnsembleDetector
from .rule_engine import RuleEngine
from .statistical import StatisticalDetector
from .isolation_forest import IsolationForestDetector
from .autoencoder import AutoencoderDetector

_log = get_logger(__name__)


AlertSink = Callable[[Detection], None]


@dataclass
class PipelineMetrics:
    events_in: int = 0
    detections_out: int = 0
    by_severity: Dict[str, int] = field(default_factory=lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0})
    by_detector: Dict[str, int] = field(default_factory=dict)
    last_event_ts: float = 0.0
    started_at: float = field(default_factory=time.time)

    def record(self, detection: Detection) -> None:
        self.detections_out += 1
        self.by_severity[detection.severity.value] += 1
        for component in detection.metadata.get("components", [{"detector": detection.detector}]):
            name = component.get("detector", "unknown")
            self.by_detector[name] = self.by_detector.get(name, 0) + 1


def _build_default_ensemble(config: PipelineConfig) -> EnsembleDetector:
    factories: Dict[str, Callable[[], BaseDetector]] = {
        "rule": lambda: (
            RuleEngine.from_json(config.detection.rules_path)
            if config.detection.rules_path
            else RuleEngine()
        ),
        "statistical": lambda: StatisticalDetector(),
        "isolation_forest": lambda: IsolationForestDetector(
            contamination=config.detection.isolation_forest_contamination,
        ),
        "autoencoder": lambda: AutoencoderDetector(
            hidden=config.detection.autoencoder_hidden,
        ),
    }
    detectors: List[BaseDetector] = []
    for name in config.detection.engines:
        factory = factories.get(name)
        if factory is None:
            _log.warning("unknown detector requested in config: %s", name)
            continue
        detectors.append(factory())
    return EnsembleDetector(
        detectors=detectors,
        weights=config.detection.weights,
        strategy=config.detection.ensemble_strategy,
        score_threshold=config.detection.score_threshold,
    )


class DetectionPipeline:
    def __init__(
        self,
        config: PipelineConfig,
        queue: Optional[EventQueue] = None,
        ensemble: Optional[EnsembleDetector] = None,
        alert_sink: Optional[AlertSink] = None,
        graph: Optional["ProvenanceGraphLike"] = None,
        correlator: Optional["GraphCorrelatorLike"] = None,
        incident_aggregator: Optional["IncidentAggregatorLike"] = None,
    ) -> None:
        self.config = config
        self.queue = queue or EventQueue()
        self.ensemble = ensemble or _build_default_ensemble(config)
        self.alert_sink = alert_sink
        self.graph = graph
        self._graph_builder = None
        if graph is not None:
            # local import to avoid circular dependency at module load time
            from ..graph.builder import GraphBuilder
            self._graph_builder = GraphBuilder(graph)
        self.correlator = correlator
        self.incident_aggregator = incident_aggregator
        self.metrics = PipelineMetrics()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._recent: List[Detection] = []
        self._recent_limit = 1000
        self._lock = threading.Lock()

    def warmup(self, events: Iterable[Event]) -> None:
        """Train any stateful detectors against a bootstrap event stream."""
        self.ensemble.fit(events)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="detection-pipeline", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        _log.info("detection pipeline started")
        try:
            while not self._stop.is_set():
                batch = self.queue.get_batch(self.config.ingestion.batch_size, timeout=0.5)
                for event in batch:
                    self._handle(event)
        except Exception:                                # pragma: no cover
            _log.exception("detection pipeline crashed")
        finally:
            _log.info("detection pipeline stopped")

    def _handle(self, event: Event) -> None:
        self.metrics.events_in += 1
        self.metrics.last_event_ts = event.timestamp
        touched = self._graph_builder.absorb(event) if self._graph_builder is not None else []
        detection = self.ensemble.detect(event)
        if detection is None:
            return
        self.metrics.record(detection)
        if self.graph is not None and touched:
            self.graph.attribute_detection(touched, detection.score)
        if self.correlator is not None:
            try:
                group = self.correlator.correlate(detection, touched)
            except Exception:                            # pragma: no cover
                _log.exception("correlator raised")
                group = None
            if group is not None and self.incident_aggregator is not None:
                try:
                    self.incident_aggregator.ingest(group, detection)
                except Exception:                        # pragma: no cover
                    _log.exception("incident aggregator raised")
        with self._lock:
            self._recent.append(detection)
            if len(self._recent) > self._recent_limit:
                del self._recent[: len(self._recent) - self._recent_limit]
        if self.alert_sink is not None:
            try:
                self.alert_sink(detection)
            except Exception:                            # pragma: no cover
                _log.exception("alert sink raised")

    def run_once(self, events: Iterable[Event]) -> List[Detection]:
        """Synchronous one-shot run used by tests and replay mode."""
        out: List[Detection] = []
        for event in events:
            self.metrics.events_in += 1
            self.metrics.last_event_ts = event.timestamp
            touched = self._graph_builder.absorb(event) if self._graph_builder is not None else []
            detection = self.ensemble.detect(event)
            if detection is None:
                continue
            self.metrics.record(detection)
            if self.graph is not None and touched:
                self.graph.attribute_detection(touched, detection.score)
            if self.correlator is not None:
                try:
                    group = self.correlator.correlate(detection, touched)
                except Exception:                        # pragma: no cover
                    _log.exception("correlator raised")
                    group = None
                if group is not None and self.incident_aggregator is not None:
                    try:
                        self.incident_aggregator.ingest(group, detection)
                    except Exception:                    # pragma: no cover
                        _log.exception("incident aggregator raised")
            out.append(detection)
            if self.alert_sink is not None:
                try:
                    self.alert_sink(detection)
                except Exception:                        # pragma: no cover
                    _log.exception("alert sink raised")
        with self._lock:
            self._recent.extend(out)
            if len(self._recent) > self._recent_limit:
                del self._recent[: len(self._recent) - self._recent_limit]
        return out

    def recent(self, limit: int = 100) -> List[Detection]:
        with self._lock:
            return list(self._recent[-limit:])

    def status(self) -> Dict[str, object]:
        uptime = max(0.0, time.time() - self.metrics.started_at)
        return {
            "uptime_s": round(uptime, 2),
            "events_in": self.metrics.events_in,
            "detections_out": self.metrics.detections_out,
            "queue_depth": len(self.queue),
            "queue_dropped": self.queue.dropped,
            "by_severity": dict(self.metrics.by_severity),
            "by_detector": dict(self.metrics.by_detector),
            "running": self._thread is not None and self._thread.is_alive(),
        }
