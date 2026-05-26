import json
import time
import urllib.error
import urllib.request
from typing import Tuple

import pytest

from threatpipe.api.server import ApiServer
from threatpipe.detection import DetectionPipeline
from threatpipe.ingestion import Event, EventType
from threatpipe.utils.config import PipelineConfig


def _start_pipeline(port: int, *, api_key: str = "") -> Tuple[DetectionPipeline, ApiServer]:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.api.host = "127.0.0.1"
    cfg.api.port = port
    cfg.api.api_key = api_key
    pipeline = DetectionPipeline(cfg)
    server = ApiServer(pipeline)
    server.start()
    time.sleep(0.1)
    return pipeline, server


def _get(port: int, path: str, *, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _post(port: int, path: str, body, *, headers=None):
    payload = json.dumps(body).encode("utf-8")
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=payload, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def test_health_endpoint():
    pipeline, server = _start_pipeline(18101)
    try:
        status, body = _get(18101, "/health")
        assert status == 200
        assert body["status"] == "ok"
    finally:
        server.stop()


def test_status_endpoint_includes_counters():
    pipeline, server = _start_pipeline(18102)
    try:
        status, body = _get(18102, "/status")
        assert status == 200
        assert "events_in" in body
        assert "by_severity" in body
    finally:
        server.stop()


def test_rules_endpoint_returns_catalog():
    pipeline, server = _start_pipeline(18103)
    try:
        status, body = _get(18103, "/rules")
        assert status == 200
        assert body["count"] > 0
    finally:
        server.stop()


def test_detect_endpoint_runs_ensemble():
    pipeline, server = _start_pipeline(18104)
    try:
        body = {
            "event_type": "process",
            "process": "powershell.exe",
            "command_line": "powershell -enc " + "A" * 64,
        }
        status, payload = _post(18104, "/detect", body)
        assert status == 200
        assert payload["detection"] is not None
        assert payload["detection"]["severity"] in ("high", "critical")
    finally:
        server.stop()


def test_events_endpoint_queues_event():
    pipeline, server = _start_pipeline(18105)
    try:
        before = pipeline.queue._q.qsize()
        status, payload = _post(18105, "/events", {"event_type": "process", "host": "x"})
        assert status == 202
        assert payload["accepted"] == 1
        assert pipeline.queue._q.qsize() == before + 1
    finally:
        server.stop()


def test_unauthorized_when_api_key_set():
    pipeline, server = _start_pipeline(18106, api_key="topsecret")
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(18106, "/health")
        assert exc.value.code == 401
        # ok with header
        status, _ = _get(18106, "/health", headers={"X-Api-Key": "topsecret"})
        assert status == 200
    finally:
        server.stop()


def test_invalid_json_body_returns_400():
    pipeline, server = _start_pipeline(18107)
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:18107/detect",
            data=b"{not json}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=2.0)
        assert exc.value.code == 400
    finally:
        server.stop()


def test_unknown_route_returns_404():
    pipeline, server = _start_pipeline(18108)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(18108, "/does-not-exist")
        assert exc.value.code == 404
    finally:
        server.stop()
