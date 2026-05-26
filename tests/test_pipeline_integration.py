"""End-to-end integration tests covering graph -> correlator -> incidents."""

from threatpipe.detection import DetectionPipeline
from threatpipe.graph import GraphBuilder, GraphCorrelator, ProvenanceGraph
from threatpipe.incidents import IncidentAggregator, IncidentStore
from threatpipe.intel import IOC, IOCMatcher, IOCMeta, IOCStore, IOCType
from threatpipe.ingestion import Event, EventType
from threatpipe.utils.config import PipelineConfig


def _wired_pipeline():
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.detection.score_threshold = 0.5
    pipeline = DetectionPipeline(cfg)
    graph = ProvenanceGraph()
    pipeline.graph = graph
    pipeline._graph_builder = GraphBuilder(graph)
    pipeline.correlator = GraphCorrelator(graph)
    inc_store = IncidentStore()
    pipeline.incident_aggregator = IncidentAggregator(inc_store)
    return pipeline, graph, inc_store


def test_pipeline_builds_graph_on_run_once():
    pipeline, graph, _ = _wired_pipeline()
    events = [
        Event(host="h", process="bash", pid=10, command_line="ls", event_type=EventType.PROCESS, timestamp=1),
        Event(host="h", process="curl", pid=11, parent_pid=10, event_type=EventType.PROCESS, timestamp=2),
    ]
    pipeline.run_once(events)
    assert graph.stats()["nodes"] >= 3


def test_attack_chain_collapses_into_single_incident():
    pipeline, graph, inc_store = _wired_pipeline()
    events = [
        Event(host="h", process="powershell.exe", pid=12, command_line="powershell -enc " + "A" * 80,
              event_type=EventType.PROCESS, timestamp=1),
        Event(host="h", process="bash", pid=12, file_path="/etc/cron.d/persist", action="write",
              event_type=EventType.FILE, timestamp=2),
        Event(host="h", process="bash", pid=12, file_path="docs/important.locked", action="write",
              event_type=EventType.FILE, timestamp=3),
    ]
    pipeline.run_once(events)
    incidents = inc_store.list()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.severity.value in ("high", "critical")
    assert "h" in incident.affected_hosts


def test_ioc_match_surfaces_in_incident():
    pipeline, graph, inc_store = _wired_pipeline()
    ioc_store = IOCStore()
    ioc_store.add(IOC(type=IOCType.IP, value="10.0.0.99",
                       meta=IOCMeta(source="test", confidence=0.9, threat_score=0.9, tags=("c2",))))
    pipeline.ensemble.detectors.append(IOCMatcher(ioc_store, min_score=0.1))
    events = [
        Event(host="h", process="curl", pid=11, dst_ip="10.0.0.99", dst_port=4444,
              event_type=EventType.NETWORK, timestamp=1),
        Event(host="h", process="bash", pid=12, file_path="docs/important.locked", action="write",
              event_type=EventType.FILE, timestamp=2),
    ]
    pipeline.run_once(events)
    incidents = inc_store.list()
    assert incidents
    assert any(("ip", "10.0.0.99") in inc.affected_iocs for inc in incidents)


def test_pipeline_works_without_graph_or_incidents():
    """Backwards compatibility: existing API shape stays usable."""
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    pipeline = DetectionPipeline(cfg)
    ev = Event(host="h", process="powershell.exe", pid=12, command_line="powershell -enc " + "A" * 80,
               event_type=EventType.PROCESS, timestamp=1)
    detections = pipeline.run_once([ev])
    assert len(detections) == 1
