"""Tests for the triage REST endpoints."""

import json
import time
import urllib.error
import urllib.request
from typing import Tuple

import pytest

from threatpipe.api.server import ApiServer
from threatpipe.detection import DetectionPipeline
from threatpipe.ingestion import Event, EventType
from threatpipe.triage import TriageEngine
from threatpipe.utils.config import PipelineConfig


def _start(port: int, *, with_triage: bool = True) -> Tuple[DetectionPipeline, ApiServer]:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.api.host = "127.0.0.1"
    cfg.api.port = port
    pipeline = DetectionPipeline(cfg)
    if with_triage:
        pipeline.triage_engine = TriageEngine()
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


def _seed(pipeline, *, host="host0", score=0.95, detector="rule"):
    from threatpipe.detection import Detection, Severity
    event = Event(host=host, event_type=EventType.PROCESS, process="sshd", timestamp=time.time())
    det = Detection(event=event, detector=detector, score=score,
                    severity=Severity.from_score(score), reasons=["seed"])
    pipeline.triage_engine.ingest(det)
    return det


def test_triage_list_disabled():
    pipeline, server = _start(18401, with_triage=False)
    try:
        status, body = _get(18401, "/triage")
        assert status == 200
        assert body["enabled"] is False
        assert body["items"] == []
    finally:
        server.stop()


def test_triage_list_returns_alerts():
    pipeline, server = _start(18402)
    try:
        _seed(pipeline)
        _seed(pipeline)  # same fingerprint -> dedup
        status, body = _get(18402, "/triage")
        assert status == 200
        assert body["enabled"] is True
        assert body["count"] == 1
        assert body["items"][0]["count"] == 2
    finally:
        server.stop()


def test_triage_get_by_id():
    pipeline, server = _start(18403)
    try:
        _seed(pipeline)
        alert_id = pipeline.triage_engine.store.list()[0].alert_id
        status, body = _get(18403, f"/triage/get?id={alert_id}")
        assert status == 200
        assert body["alert_id"] == alert_id
    finally:
        server.stop()


def test_triage_get_missing_is_404():
    pipeline, server = _start(18404)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(18404, "/triage/get?id=ALERT-999999")
        assert exc.value.code == 404
    finally:
        server.stop()


def test_triage_stats_endpoint():
    pipeline, server = _start(18405)
    try:
        _seed(pipeline)
        status, body = _get(18405, "/triage/stats")
        assert status == 200
        assert body["enabled"] is True
        assert body["total_alerts"] == 1
        assert "suppression" in body
    finally:
        server.stop()


def test_triage_update_status():
    pipeline, server = _start(18406)
    try:
        _seed(pipeline)
        alert_id = pipeline.triage_engine.store.list()[0].alert_id
        status, body = _post(18406, "/triage/update",
                             {"id": alert_id, "status": "closed",
                              "disposition": "false_positive", "note": "benign"})
        assert status == 200
        assert body["status"] == "closed"
        assert body["disposition"] == "false_positive"
        assert "benign" in body["notes"]
    finally:
        server.stop()


def test_triage_suppress_lifecycle():
    pipeline, server = _start(18407)
    try:
        status, body = _post(18407, "/triage/suppress",
                             {"rule_id": "r1", "match": {"host": "host0"}})
        assert status == 201
        # listing reflects the new rule
        status, body = _get(18407, "/triage/suppressions")
        assert body["count"] == 1
        # a matching detection is now suppressed
        _seed(pipeline, host="host0")
        alert = pipeline.triage_engine.store.list()[0]
        assert alert.status.value == "suppressed"
        # remove it
        status, body = _post(18407, "/triage/unsuppress", {"rule_id": "r1"})
        assert body["removed"] is True
    finally:
        server.stop()


def test_triage_suppress_requires_match():
    pipeline, server = _start(18408)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(18408, "/triage/suppress", {"rule_id": "r1"})
        assert exc.value.code == 400
    finally:
        server.stop()
