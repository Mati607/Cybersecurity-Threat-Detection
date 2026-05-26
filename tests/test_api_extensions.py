"""Tests for the graph/intel/incidents REST endpoints."""

import json
import time
import urllib.error
import urllib.request
from typing import Tuple

import pytest

from threatpipe.api.server import ApiServer
from threatpipe.detection import DetectionPipeline
from threatpipe.graph import GraphBuilder, GraphCorrelator, ProvenanceGraph
from threatpipe.incidents import IncidentAggregator, IncidentStore
from threatpipe.incidents.model import Incident, IncidentStatus
from threatpipe.intel import IOC, IOCMatcher, IOCMeta, IOCStore, IOCType
from threatpipe.ingestion import Event, EventType
from threatpipe.utils.config import PipelineConfig


def _start(port: int, *, with_graph: bool = True, with_intel: bool = False,
           with_incidents: bool = True) -> Tuple[DetectionPipeline, ApiServer]:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.api.host = "127.0.0.1"
    cfg.api.port = port
    pipeline = DetectionPipeline(cfg)
    if with_graph:
        graph = ProvenanceGraph()
        pipeline.graph = graph
        pipeline._graph_builder = GraphBuilder(graph)
        pipeline.correlator = GraphCorrelator(graph)
    if with_incidents:
        pipeline.incident_aggregator = IncidentAggregator(IncidentStore())
    if with_intel:
        ioc_store = IOCStore()
        ioc_store.add(IOC(type=IOCType.IP, value="1.2.3.4", meta=IOCMeta(source="t")))
        pipeline.ensemble.detectors.append(IOCMatcher(ioc_store, min_score=0.1))
    server = ApiServer(pipeline)
    server.start()
    time.sleep(0.1)
    return pipeline, server


def _get(port: int, path: str):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2.0) as r:
        return r.status, json.loads(r.read())


def _post(port: int, path: str, body):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=2.0) as r:
        return r.status, json.loads(r.read())


def test_graph_stats_endpoint():
    pipeline, server = _start(18201)
    try:
        status, body = _get(18201, "/graph/stats")
        assert status == 200
        assert body["enabled"] is True
        assert "nodes" in body
    finally:
        server.stop()


def test_graph_stats_endpoint_when_disabled():
    pipeline, server = _start(18202, with_graph=False, with_incidents=False)
    try:
        status, body = _get(18202, "/graph/stats")
        assert status == 200
        assert body["enabled"] is False
    finally:
        server.stop()


def test_graph_top_after_events():
    pipeline, server = _start(18203)
    try:
        pipeline.run_once([
            Event(host="h", process="x", pid=1, event_type=EventType.PROCESS, timestamp=1),
            Event(host="h", process="y", pid=2, event_type=EventType.PROCESS, timestamp=2),
        ])
        status, body = _get(18203, "/graph/top?limit=5")
        assert status == 200
        assert body["count"] > 0
    finally:
        server.stop()


def test_graph_export_dot():
    pipeline, server = _start(18204)
    try:
        pipeline.run_once([Event(host="h", process="x", pid=1, event_type=EventType.PROCESS, timestamp=1)])
        with urllib.request.urlopen(f"http://127.0.0.1:18204/graph/export?format=dot", timeout=2.0) as r:
            data = r.read().decode("utf-8")
        assert data.startswith("digraph")
    finally:
        server.stop()


def test_intel_lookup_finds_match():
    pipeline, server = _start(18205, with_intel=True)
    try:
        status, body = _get(18205, "/intel/lookup?value=1.2.3.4")
        assert status == 200
        assert body["match"] is not None
        assert body["match"]["value"] == "1.2.3.4"
    finally:
        server.stop()


def test_intel_stats_when_disabled():
    pipeline, server = _start(18206)
    try:
        status, body = _get(18206, "/intel/stats")
        assert status == 200
        assert body["enabled"] is False
    finally:
        server.stop()


def test_incident_list_returns_aggregator_state():
    pipeline, server = _start(18207)
    try:
        pipeline.run_once([
            Event(host="h", process="powershell.exe", pid=10, command_line="powershell -enc " + "A" * 80,
                  event_type=EventType.PROCESS, timestamp=1),
            Event(host="h", process="bash", pid=11, file_path="docs/x.locked", action="write",
                  event_type=EventType.FILE, timestamp=2),
        ])
        status, body = _get(18207, "/incidents")
        assert status == 200
        assert body["count"] >= 1
    finally:
        server.stop()


def test_incident_status_update():
    pipeline, server = _start(18208)
    try:
        pipeline.run_once([
            Event(host="h", process="powershell.exe", pid=10, command_line="powershell -enc " + "A" * 80,
                  event_type=EventType.PROCESS, timestamp=1),
        ])
        listing = _get(18208, "/incidents")[1]
        inc_id = listing["items"][0]["incident_id"]
        status, body = _post(18208, "/incidents/status", {
            "id": inc_id, "status": "acknowledged", "note": "looking into it",
        })
        assert status == 200
        assert body["status"] == "acknowledged"
        assert "looking into it" in body["notes"]
    finally:
        server.stop()


def test_incident_get_404():
    pipeline, server = _start(18209)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(18209, "/incidents/get?id=does-not-exist")
        assert exc.value.code == 404
    finally:
        server.stop()
