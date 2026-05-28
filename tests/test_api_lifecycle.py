"""Tests for the forensics / simulator / cases / compliance API endpoints."""

import json
import time
import urllib.error
import urllib.request
from typing import Tuple

import pytest

from threatpipe.api.server import ApiServer
from threatpipe.cases import CaseManager
from threatpipe.detection import DetectionPipeline
from threatpipe.forensics import ForensicsSink, ForensicsStore
from threatpipe.ingestion import Event, EventType
from threatpipe.utils.config import PipelineConfig


def _start(port: int) -> Tuple[DetectionPipeline, ApiServer]:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.api.host = "127.0.0.1"
    cfg.api.port = port
    pipeline = DetectionPipeline(cfg)
    pipeline.forensics_sink = ForensicsSink(ForensicsStore(":memory:"))
    pipeline.case_manager = CaseManager()
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
    with urllib.request.urlopen(req, timeout=3.0) as r:
        return r.status, json.loads(r.read())


def _seed(pipeline):
    pipeline.run_once([
        Event(host="web1", process="powershell.exe", pid=10,
              command_line="powershell -enc " + "A" * 80,
              event_type=EventType.PROCESS, timestamp=1_700_000_000),
        Event(host="web1", process="bash", pid=12, file_path="x.locked",
              action="write", event_type=EventType.FILE, timestamp=1_700_000_010),
    ])


# --- forensics ---------------------------------------------------

def test_forensics_stats_endpoint():
    pipeline, server = _start(18401)
    try:
        _seed(pipeline)
        status, body = _get(18401, "/forensics/stats")
        assert status == 200
        assert body["enabled"] is True
        assert body["detections"]["count"] >= 1
    finally:
        server.stop()


def test_forensics_search_endpoint():
    pipeline, server = _start(18402)
    try:
        _seed(pipeline)
        status, body = _get(18402, "/forensics/search?limit=10")
        assert status == 200
        assert body["count"] >= 1
    finally:
        server.stop()


def test_forensics_histogram_requires_range():
    pipeline, server = _start(18403)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(18403, "/forensics/histogram")
        assert exc.value.code == 400
    finally:
        server.stop()


# --- simulator ---------------------------------------------------

def test_simulator_scenarios_endpoint():
    pipeline, server = _start(18404)
    try:
        status, body = _get(18404, "/simulator/scenarios")
        assert status == 200
        assert body["count"] >= 5
    finally:
        server.stop()


def test_simulator_run_endpoint_returns_coverage():
    pipeline, server = _start(18405)
    try:
        status, body = _post(18405, "/simulator/run", {"scenario": "ransomware"})
        assert status == 200
        assert "coverage" in body
        assert body["coverage"]["grade"] in ("A", "B", "C", "D", "F")
    finally:
        server.stop()


def test_simulator_run_unknown_scenario_404():
    pipeline, server = _start(18406)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(18406, "/simulator/run", {"scenario": "nope"})
        assert exc.value.code == 404
    finally:
        server.stop()


# --- cases -------------------------------------------------------

def test_cases_create_and_get():
    pipeline, server = _start(18407)
    try:
        status, created = _post(18407, "/cases", {"title": "Investigate web1", "priority": "p1"})
        assert status == 201
        case_id = created["case_id"]
        status, fetched = _get(18407, f"/cases/get?id={case_id}")
        assert status == 200
        assert fetched["case_id"] == case_id
        assert fetched["custody_valid"] is True
    finally:
        server.stop()


def test_cases_note_endpoint():
    pipeline, server = _start(18408)
    try:
        _, created = _post(18408, "/cases", {"title": "x"})
        status, note = _post(18408, "/cases/note",
                             {"id": created["case_id"], "author": "bob", "body": "looked into it"})
        assert status == 201
        assert note["author"] == "bob"
    finally:
        server.stop()


def test_cases_list_endpoint():
    pipeline, server = _start(18409)
    try:
        _post(18409, "/cases", {"title": "one"})
        _post(18409, "/cases", {"title": "two"})
        status, body = _get(18409, "/cases")
        assert status == 200
        assert body["count"] >= 2
    finally:
        server.stop()


# --- compliance --------------------------------------------------

def test_compliance_frameworks_endpoint():
    pipeline, server = _start(18410)
    try:
        status, body = _get(18410, "/compliance/frameworks")
        assert status == 200
        assert body["count"] >= 4
    finally:
        server.stop()


def test_compliance_report_endpoint():
    pipeline, server = _start(18411)
    try:
        status, body = _get(18411, "/compliance/report?framework=nist-800-53")
        assert status == 200
        assert body["framework"]["id"] == "nist-800-53"
        assert "summary" in body
    finally:
        server.stop()


def test_compliance_report_unknown_framework_404():
    pipeline, server = _start(18412)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(18412, "/compliance/report?framework=nope")
        assert exc.value.code == 404
    finally:
        server.stop()


# --- pipeline integration ---------------------------------------

def test_pipeline_persists_to_forensics_and_opens_cases():
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    pipeline = DetectionPipeline(cfg)
    store = ForensicsStore(":memory:")
    pipeline.forensics_sink = ForensicsSink(store)
    # graph + correlator + aggregator needed for incident -> case flow
    from threatpipe.graph import GraphBuilder, GraphCorrelator, ProvenanceGraph
    from threatpipe.incidents import IncidentAggregator, IncidentStore
    g = ProvenanceGraph()
    pipeline.graph = g
    pipeline._graph_builder = GraphBuilder(g)
    pipeline.correlator = GraphCorrelator(g)
    pipeline.incident_aggregator = IncidentAggregator(IncidentStore())
    pipeline.case_manager = CaseManager()

    pipeline.run_once([
        Event(host="web1", process="bash", pid=12, file_path="report.locked",
              action="write", event_type=EventType.FILE, timestamp=1_700_000_000),
    ])
    assert store.stats()["detections"]["count"] >= 1
    assert len(pipeline.case_manager.store) >= 1
