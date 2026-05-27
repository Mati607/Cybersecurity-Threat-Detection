"""Tests for the new /hunt, /attck, /response, and dashboard endpoints."""

import json
import time
import urllib.error
import urllib.request
from typing import Tuple

import pytest

from threatpipe.api.server import ApiServer
from threatpipe.detection import DetectionPipeline
from threatpipe.detection.base import Severity
from threatpipe.graph import GraphBuilder, GraphCorrelator, ProvenanceGraph
from threatpipe.hunt import HuntScheduler, HuntStore, SavedHunt
from threatpipe.incidents import IncidentAggregator, IncidentStore
from threatpipe.ingestion import Event, EventType
from threatpipe.response import (
    Playbook,
    PlaybookStep,
    PlaybookTrigger,
    ResponseEngine,
)
from threatpipe.utils.config import PipelineConfig


def _start(port: int, *, with_hunt: bool = True, with_response: bool = True,
           with_incidents: bool = True) -> Tuple[DetectionPipeline, ApiServer]:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.api.host = "127.0.0.1"
    cfg.api.port = port
    pipeline = DetectionPipeline(cfg)
    graph = ProvenanceGraph()
    pipeline.graph = graph
    pipeline._graph_builder = GraphBuilder(graph)
    pipeline.correlator = GraphCorrelator(graph)
    if with_incidents:
        pipeline.incident_aggregator = IncidentAggregator(IncidentStore())
    if with_response:
        engine = ResponseEngine()
        engine.register_playbooks([Playbook(
            playbook_id="pb-demo", name="demo",
            trigger=PlaybookTrigger.DETECTION,
            steps=[PlaybookStep(step_id="s1", action="notify",
                                args={"message": "{event.host}"})])])
        pipeline.response_engine = engine
    if with_hunt:
        store = HuntStore()
        store.upsert(SavedHunt(hunt_id="h1", name="high",
                                query='severity == "high" OR severity == "critical"',
                                schedule_seconds=60))
        pipeline.hunt_store = store
        pipeline.hunt_scheduler = HuntScheduler(
            store, provider=lambda hunt: pipeline.recent(limit=1000),
        )
    server = ApiServer(pipeline)
    server.start()
    time.sleep(0.1)
    return pipeline, server


def _get(port: int, path: str):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2.0) as r:
        return r.status, r.read()


def _get_json(port: int, path: str):
    status, body = _get(port, path)
    return status, json.loads(body)


def _post_json(port: int, path: str, body):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=2.0) as r:
        return r.status, json.loads(r.read())


# --- dashboard --------------------------------------------------

def test_dashboard_root_returns_html():
    pipeline, server = _start(18301)
    try:
        status, body = _get(18301, "/")
        assert status == 200
        assert b"threatpipe console" in body
        assert b"<!doctype html>" in body
    finally:
        server.stop()


def test_dashboard_alias_works():
    pipeline, server = _start(18302)
    try:
        status, body = _get(18302, "/dashboard")
        assert status == 200
        assert b"threatpipe console" in body
    finally:
        server.stop()


# --- hunt -------------------------------------------------------

def test_hunt_search_endpoint():
    pipeline, server = _start(18303)
    try:
        pipeline.run_once([
            Event(host="h", process="powershell.exe", pid=10,
                  command_line="powershell -enc " + "A" * 80,
                  event_type=EventType.PROCESS, timestamp=1),
        ])
        status, body = _post_json(18303, "/hunt/search", {
            "query": 'severity == "high" OR severity == "critical"',
            "target": "detections",
        })
        assert status == 200
        assert body["match_count"] >= 1
    finally:
        server.stop()


def test_hunt_list_endpoint_includes_saved_hunt():
    pipeline, server = _start(18304)
    try:
        status, body = _get_json(18304, "/hunt")
        assert status == 200
        assert body["count"] >= 1
        assert any(h["hunt_id"] == "h1" for h in body["items"])
    finally:
        server.stop()


def test_hunt_save_endpoint_persists():
    pipeline, server = _start(18305)
    try:
        status, _ = _post_json(18305, "/hunt", {
            "hunt_id": "ad-hoc",
            "name": "ad-hoc",
            "query": "score > 0.0",
        })
        assert status == 201
        listing = _get_json(18305, "/hunt")[1]
        assert any(h["hunt_id"] == "ad-hoc" for h in listing["items"])
    finally:
        server.stop()


def test_hunt_run_endpoint_executes_against_pipeline():
    pipeline, server = _start(18306)
    try:
        pipeline.run_once([Event(host="h", process="powershell.exe", pid=10,
                                  command_line="powershell -enc " + "A" * 80,
                                  event_type=EventType.PROCESS, timestamp=1)])
        status, body = _post_json(18306, "/hunt/run?id=h1", {})
        # Path parameter
        assert status in (200, 400)
        if status == 200:
            assert "match_count" in body
    finally:
        server.stop()


def test_hunt_search_rejects_bad_syntax():
    pipeline, server = _start(18307)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post_json(18307, "/hunt/search", {"query": "score >", "target": "detections"})
        assert exc.value.code == 400
    finally:
        server.stop()


# --- attck ------------------------------------------------------

def test_attck_techniques_endpoint():
    pipeline, server = _start(18308)
    try:
        status, body = _get_json(18308, "/attck/techniques")
        assert status == 200
        assert body["count"] > 30
    finally:
        server.stop()


def test_attck_techniques_query_filter():
    pipeline, server = _start(18309)
    try:
        status, body = _get_json(18309, "/attck/techniques?q=powershell")
        assert status == 200
        assert any("PowerShell" in t["name"] for t in body["items"])
    finally:
        server.stop()


def test_attck_coverage_endpoint():
    pipeline, server = _start(18310)
    try:
        status, body = _get_json(18310, "/attck/coverage")
        assert status == 200
        assert body["summary"]["techniques_total"] > 0
        assert body["summary"]["techniques_covered"] > 0
    finally:
        server.stop()


def test_attck_navigator_layer_endpoint():
    pipeline, server = _start(18311)
    try:
        status, body = _get_json(18311, "/attck/navigator")
        assert status == 200
        assert body["domain"] == "enterprise-attack"
        assert isinstance(body["techniques"], list)
    finally:
        server.stop()


# --- response ---------------------------------------------------

def test_response_playbook_listing():
    pipeline, server = _start(18312)
    try:
        status, body = _get_json(18312, "/response/playbooks")
        assert status == 200
        assert body["count"] == 1
        assert body["items"][0]["playbook_id"] == "pb-demo"
    finally:
        server.stop()


def test_response_audit_endpoint_after_pipeline_run():
    pipeline, server = _start(18313)
    try:
        pipeline.run_once([
            Event(host="h", process="powershell.exe", pid=10,
                  command_line="powershell -enc " + "A" * 80,
                  event_type=EventType.PROCESS, timestamp=1),
        ])
        status, body = _get_json(18313, "/response/audit")
        assert status == 200
        assert body["enabled"] is True
        assert body["count"] >= 1
    finally:
        server.stop()
