"""API tests for /models and /reports endpoints."""

import json
import time
import urllib.error
import urllib.request
from typing import Tuple

import pytest

from threatpipe.api.server import ApiServer
from threatpipe.detection import DetectionPipeline
from threatpipe.models.registry import ModelRegistry
from threatpipe.reporting.builder import ReportBuilder
from threatpipe.reporting.model import ReportSchedule, ReportType
from threatpipe.reporting.scheduler import ReportScheduler
from threatpipe.reporting.store import ReportStore
from threatpipe.utils.config import PipelineConfig


def _start(port: int) -> Tuple[DetectionPipeline, ApiServer]:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.api.host = "127.0.0.1"
    cfg.api.port = port
    pipeline = DetectionPipeline(cfg)
    # attach model registry
    pipeline.model_registry = ModelRegistry()
    pipeline._auto_trainers = {}
    # attach reporting
    pipeline.report_store = ReportStore(":memory:")
    pipeline._report_builder = ReportBuilder(pipeline)
    pipeline.report_scheduler = ReportScheduler(
        pipeline._report_builder, pipeline.report_store, poll_interval_s=3600
    )
    server = ApiServer(pipeline)
    server.start()
    time.sleep(0.1)
    return pipeline, server


def _get(port: int, path: str):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3.0) as r:
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


# ------------------------------------------------------------------
# /models
# ------------------------------------------------------------------

def test_models_summary_empty():
    pipeline, server = _start(19001)
    try:
        status, body = _get(19001, "/models")
        assert status == 200
        assert body["model_count"] == 0
    finally:
        server.stop()


def test_models_register_endpoint():
    pipeline, server = _start(19002)
    try:
        status, body = _post(19002, "/models/register", {
            "model_id": "iforest",
            "detector_type": "isolation_forest",
            "train_samples": 1000,
        })
        assert status == 201
        assert body["version"] == 1
        assert body["detector_type"] == "isolation_forest"
    finally:
        server.stop()


def test_models_summary_after_register():
    pipeline, server = _start(19003)
    try:
        _post(19003, "/models/register", {"model_id": "iforest", "detector_type": "iforest"})
        status, body = _get(19003, "/models")
        assert status == 200
        assert body["model_count"] == 1
    finally:
        server.stop()


def test_models_list_endpoint():
    pipeline, server = _start(19004)
    try:
        _post(19004, "/models/register", {"model_id": "m1", "detector_type": "iforest"})
        _post(19004, "/models/register", {"model_id": "m2", "detector_type": "ae"})
        status, body = _get(19004, "/models/list")
        assert status == 200
        assert body["count"] == 2
    finally:
        server.stop()


def test_models_get_endpoint():
    pipeline, server = _start(19005)
    try:
        _post(19005, "/models/register", {"model_id": "iforest", "detector_type": "iforest"})
        status, body = _get(19005, "/models/get?model_id=iforest")
        assert status == 200
        assert body["model_id"] == "iforest"
        assert len(body["versions"]) == 1
    finally:
        server.stop()


def test_models_get_missing_param_400():
    pipeline, server = _start(19006)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(19006, "/models/get")
        assert exc.value.code == 400
    finally:
        server.stop()


def test_models_promote_endpoint():
    pipeline, server = _start(19007)
    try:
        _post(19007, "/models/register", {"model_id": "iforest", "detector_type": "iforest"})
        status, body = _post(19007, "/models/promote", {
            "model_id": "iforest", "version": 1, "status": "production"
        })
        assert status == 200
        assert body["status"] == "production"
    finally:
        server.stop()


def test_models_promote_bad_status_400():
    pipeline, server = _start(19008)
    try:
        _post(19008, "/models/register", {"model_id": "m", "detector_type": "ae"})
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(19008, "/models/promote", {"model_id": "m", "version": 1, "status": "nope"})
        assert exc.value.code == 400
    finally:
        server.stop()


def test_models_drift_endpoint_empty():
    pipeline, server = _start(19009)
    try:
        status, body = _get(19009, "/models/drift")
        assert status == 200
        assert body["count"] == 0
    finally:
        server.stop()


def test_models_train_history_missing_param():
    pipeline, server = _start(19010)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(19010, "/models/train/history")
        assert exc.value.code == 400
    finally:
        server.stop()


def test_models_train_history_unknown_model():
    pipeline, server = _start(19011)
    try:
        status, body = _get(19011, "/models/train/history?model_id=ghost")
        assert status == 200
        assert body["enabled"] is False
    finally:
        server.stop()


def test_models_train_trigger_unknown_404():
    pipeline, server = _start(19012)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(19012, "/models/train/trigger", {"model_id": "nope"})
        assert exc.value.code == 404
    finally:
        server.stop()


# ------------------------------------------------------------------
# /reports
# ------------------------------------------------------------------

def test_reports_list_empty():
    pipeline, server = _start(19020)
    try:
        status, body = _get(19020, "/reports")
        assert status == 200
        assert body["count"] == 0
    finally:
        server.stop()


def test_reports_generate_endpoint():
    pipeline, server = _start(19021)
    try:
        status, body = _post(19021, "/reports/generate", {
            "report_type": "executive",
            "format": "json",
            "lookback_s": 3600,
        })
        assert status == 201
        assert body["status"] == "complete"
        assert "sections" in body
    finally:
        server.stop()


def test_reports_generate_and_list():
    pipeline, server = _start(19022)
    try:
        _post(19022, "/reports/generate", {"report_type": "executive", "format": "json"})
        status, body = _get(19022, "/reports")
        assert status == 200
        assert body["count"] == 1
    finally:
        server.stop()


def test_reports_get_endpoint():
    pipeline, server = _start(19023)
    try:
        _, created = _post(19023, "/reports/generate", {"report_type": "operational", "format": "json"})
        report_id = created["report_id"]
        status, body = _get(19023, f"/reports/get?id={report_id}")
        assert status == 200
        assert body["report_id"] == report_id
    finally:
        server.stop()


def test_reports_get_missing_404():
    pipeline, server = _start(19024)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(19024, "/reports/get?id=RPT-GHOST")
        assert exc.value.code == 404
    finally:
        server.stop()


def test_reports_get_missing_id_400():
    pipeline, server = _start(19025)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(19025, "/reports/get")
        assert exc.value.code == 400
    finally:
        server.stop()


def test_reports_stats_endpoint():
    pipeline, server = _start(19026)
    try:
        _post(19026, "/reports/generate", {"report_type": "executive", "format": "json"})
        status, body = _get(19026, "/reports/stats")
        assert status == 200
        assert body["total"] == 1
    finally:
        server.stop()


def test_reports_html_format():
    pipeline, server = _start(19027)
    try:
        status, body = _post(19027, "/reports/generate", {
            "report_type": "executive",
            "format": "html",
        })
        assert status == 201
    finally:
        server.stop()


# ------------------------------------------------------------------
# /reports/schedules
# ------------------------------------------------------------------

def test_schedules_list_empty():
    pipeline, server = _start(19030)
    try:
        status, body = _get(19030, "/reports/schedules")
        assert status == 200
        assert body["count"] == 0
    finally:
        server.stop()


def test_schedules_create_endpoint():
    pipeline, server = _start(19031)
    try:
        status, body = _post(19031, "/reports/schedules", {
            "name": "Daily Report",
            "report_type": "executive",
            "format": "json",
            "interval_s": 86400,
            "lookback_s": 86400,
        })
        assert status == 201
        assert body["name"] == "Daily Report"
        assert body["schedule_id"].startswith("SCH-")
    finally:
        server.stop()


def test_schedules_list_after_create():
    pipeline, server = _start(19032)
    try:
        _post(19032, "/reports/schedules", {"name": "A", "interval_s": 3600})
        _post(19032, "/reports/schedules", {"name": "B", "interval_s": 7200})
        status, body = _get(19032, "/reports/schedules")
        assert status == 200
        assert body["count"] == 2
    finally:
        server.stop()


def test_schedules_delete_endpoint():
    pipeline, server = _start(19033)
    try:
        _, created = _post(19033, "/reports/schedules", {"name": "del_me"})
        status, body = _post(19033, "/reports/schedules/delete", {
            "schedule_id": created["schedule_id"]
        })
        assert status == 200
        assert body["removed"] is True
        _, list_body = _get(19033, "/reports/schedules")
        assert list_body["count"] == 0
    finally:
        server.stop()


def test_schedules_run_endpoint():
    pipeline, server = _start(19034)
    try:
        _, created = _post(19034, "/reports/schedules", {
            "name": "OnDemand",
            "report_type": "executive",
            "format": "json",
            "lookback_s": 3600,
        })
        status, body = _post(19034, "/reports/schedules/run", {
            "schedule_id": created["schedule_id"]
        })
        assert status == 200
        assert body["status"] == "complete"
    finally:
        server.stop()


def test_schedules_run_unknown_404():
    pipeline, server = _start(19035)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(19035, "/reports/schedules/run", {"schedule_id": "SCH-NOPE"})
        assert exc.value.code == 404
    finally:
        server.stop()


def test_schedules_delete_missing_id_400():
    pipeline, server = _start(19036)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(19036, "/reports/schedules/delete", {})
        assert exc.value.code == 400
    finally:
        server.stop()
