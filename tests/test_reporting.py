"""Tests for the reporting engine: builder, renderer, store, scheduler."""

import time

import pytest

from threatpipe.reporting.builder import ReportBuilder
from threatpipe.reporting.model import (
    Report,
    ReportFormat,
    ReportSchedule,
    ReportSection,
    ReportStatus,
    ReportType,
)
from threatpipe.reporting.renderer import (
    HtmlRenderer,
    JsonRenderer,
    TextRenderer,
    render_report,
)
from threatpipe.reporting.scheduler import ReportScheduler, default_schedules
from threatpipe.reporting.store import ReportStore


# ------------------------------------------------------------------
# helper
# ------------------------------------------------------------------

def _minimal_pipeline():
    """A duck-typed object that satisfies ReportBuilder's attr lookups."""

    class FakePipeline:
        _stats = {"events_in": 1000}
        graph = None
        forensics_sink = None
        _forensics_store = None
        incident_aggregator = None
        _incident_store = None
        _hunt_store = None
        model_registry = None
        _report_builder = None
        report_store = None
        report_scheduler = None
        _auto_trainers = {}

        def recent(self, limit=50):
            return []

    return FakePipeline()


def _sample_report(fmt=ReportFormat.JSON, rtype=ReportType.EXECUTIVE) -> Report:
    r = Report(title="Test Report", format=fmt, report_type=rtype)
    r.sections = [
        ReportSection(
            section_id="summary", title="Summary",
            data={"events_total": 100, "detections_total": 10, "incidents_total": 2,
                  "period_start_iso": "2026-01-01T00:00:00Z",
                  "period_end_iso": "2026-01-02T00:00:00Z"},
            order=0, render_hint="prose",
        ),
        ReportSection(
            section_id="detections", title="Detections",
            data={"count": 10, "top_hosts": [{"key": "web1", "count": 8}],
                  "by_severity": {"high": 3, "low": 7}},
            order=1, render_hint="table",
        ),
    ]
    r.status = ReportStatus.COMPLETE
    return r


# ------------------------------------------------------------------
# Report model
# ------------------------------------------------------------------

def test_report_id_generated():
    r = Report()
    assert r.report_id.startswith("RPT-")


def test_report_to_dict_keys():
    r = _sample_report()
    d = r.to_dict()
    assert "report_id" in d
    assert "sections" in d
    assert "summary" in d
    assert "status" in d


def test_report_to_dict_include_rendered():
    r = _sample_report()
    r.rendered = "<html>test</html>"
    d = r.to_dict(include_rendered=True)
    assert d["rendered"] == "<html>test</html>"
    d2 = r.to_dict(include_rendered=False)
    assert "rendered" not in d2


def test_schedule_to_dict():
    sch = ReportSchedule(name="Daily", interval_s=86400)
    d = sch.to_dict()
    assert d["name"] == "Daily"
    assert d["interval_s"] == 86400


# ------------------------------------------------------------------
# ReportBuilder
# ------------------------------------------------------------------

def test_builder_produces_complete_report():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    report = builder.build(lookback_s=3600)
    assert report.status == ReportStatus.COMPLETE
    assert len(report.sections) >= 5
    assert report.title != ""


def test_builder_section_ids():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    report = builder.build()
    ids = {s.section_id for s in report.sections}
    assert "summary" in ids
    assert "detections" in ids
    assert "incidents" in ids
    assert "graph" in ids


def test_builder_compliance_type_adds_section():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    report = builder.build(report_type=ReportType.COMPLIANCE)
    ids = {s.section_id for s in report.sections}
    assert "compliance" in ids


def test_builder_summary_has_key_fields():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    report = builder.build(lookback_s=86400)
    summary_sec = next(s for s in report.sections if s.section_id == "summary")
    assert "detections_total" in summary_sec.data
    assert "events_total" in summary_sec.data


def test_builder_period_defaults():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    t0 = time.time()
    report = builder.build(lookback_s=3600)
    assert report.period_end >= t0
    assert report.period_start == pytest.approx(report.period_end - 3600, abs=5)


# ------------------------------------------------------------------
# Renderers
# ------------------------------------------------------------------

def test_json_renderer_is_valid_json():
    import json
    r = _sample_report(fmt=ReportFormat.JSON)
    out = JsonRenderer().render(r)
    parsed = json.loads(out)
    assert parsed["report_id"] == r.report_id


def test_text_renderer_has_title():
    r = _sample_report(fmt=ReportFormat.TEXT)
    out = TextRenderer().render(r)
    assert "Test Report" in out
    assert "Summary" in out


def test_text_renderer_has_sections():
    r = _sample_report()
    out = TextRenderer().render(r)
    assert "Detections" in out
    assert "events_total" in out or "detections_total" in out


def test_html_renderer_produces_html():
    r = _sample_report(fmt=ReportFormat.HTML)
    out = HtmlRenderer().render(r)
    assert "<!DOCTYPE html>" in out
    assert "Test Report" in out
    assert "<table>" in out or "kv-item" in out


def test_html_renderer_escapes_xss():
    r = _sample_report(fmt=ReportFormat.HTML)
    r.title = "<script>alert(1)</script>"
    out = HtmlRenderer().render(r)
    assert "<script>" not in out


def test_render_report_dispatch_json():
    import json
    r = _sample_report(fmt=ReportFormat.JSON)
    out = render_report(r)
    assert json.loads(out)["report_id"] == r.report_id


def test_render_report_dispatch_html():
    r = _sample_report(fmt=ReportFormat.HTML)
    out = render_report(r)
    assert "<!DOCTYPE" in out


def test_render_report_dispatch_text():
    r = _sample_report(fmt=ReportFormat.TEXT)
    out = render_report(r)
    assert "Test Report" in out


def test_html_renderer_chart_section():
    r = Report(title="Trend")
    r.status = ReportStatus.COMPLETE
    r.sections = [
        ReportSection(
            section_id="trend", title="Trend",
            data={"trend_direction": "increasing",
                  "buckets": [{"bucket": "2026-01-01", "bucket_iso": "2026-01-01T00:00:00Z", "count": 5}]},
            order=0, render_hint="chart",
        )
    ]
    out = HtmlRenderer().render(r)
    assert "bar-chart" in out
    assert "increasing" in out


# ------------------------------------------------------------------
# ReportStore
# ------------------------------------------------------------------

def test_store_in_memory_save_get():
    store = ReportStore(":memory:")
    r = _sample_report()
    store.save(r)
    fetched = store.get(r.report_id)
    assert fetched is not None
    assert fetched.report_id == r.report_id


def test_store_list_all():
    store = ReportStore(":memory:")
    store.save(_sample_report())
    store.save(_sample_report())
    items = store.list_reports()
    assert len(items) == 2


def test_store_list_filter_by_type():
    store = ReportStore(":memory:")
    r1 = _sample_report(rtype=ReportType.EXECUTIVE)
    r2 = _sample_report(rtype=ReportType.COMPLIANCE)
    store.save(r1)
    store.save(r2)
    items = store.list_reports(report_type=ReportType.COMPLIANCE)
    assert len(items) == 1


def test_store_count():
    store = ReportStore(":memory:")
    assert store.count() == 0
    store.save(_sample_report())
    assert store.count() == 1


def test_store_stats():
    store = ReportStore(":memory:")
    store.save(_sample_report())
    s = store.stats()
    assert s["total"] == 1
    assert "executive" in s["by_type"]


def test_store_eviction(tmp_path):
    store = ReportStore(":memory:", max_reports=3)
    for _ in range(5):
        store.save(_sample_report())
        time.sleep(0.001)
    assert store.count() == 3


def test_store_get_missing():
    store = ReportStore(":memory:")
    assert store.get("RPT-NOSUCH") is None


def test_store_file_backed(tmp_path):
    path = str(tmp_path / "reports")
    store = ReportStore(path)
    r = _sample_report()
    r.rendered = "<html/>"
    store.save(r)
    # reload
    store2 = ReportStore(path)
    fetched = store2.get(r.report_id)
    assert fetched is not None
    assert fetched.report_id == r.report_id


# ------------------------------------------------------------------
# ReportScheduler
# ------------------------------------------------------------------

def test_scheduler_add_and_list():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    store = ReportStore(":memory:")
    scheduler = ReportScheduler(builder, store, poll_interval_s=3600)
    sch = ReportSchedule(name="Test", interval_s=3600)
    scheduler.add_schedule(sch)
    schedules = scheduler.list_schedules()
    assert len(schedules) == 1
    assert schedules[0].name == "Test"


def test_scheduler_remove():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    store = ReportStore(":memory:")
    scheduler = ReportScheduler(builder, store)
    sch = ReportSchedule(name="Test")
    scheduler.add_schedule(sch)
    removed = scheduler.remove_schedule(sch.schedule_id)
    assert removed is True
    assert len(scheduler.list_schedules()) == 0


def test_scheduler_remove_nonexistent():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    store = ReportStore(":memory:")
    scheduler = ReportScheduler(builder, store)
    assert scheduler.remove_schedule("SCH-NOPE") is False


def test_scheduler_run_now():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    store = ReportStore(":memory:")
    scheduler = ReportScheduler(builder, store)
    sch = ReportSchedule(name="OnDemand", interval_s=86400, lookback_s=3600)
    scheduler.add_schedule(sch)
    report = scheduler.run_now(sch.schedule_id)
    assert report is not None
    assert report.status == ReportStatus.COMPLETE
    assert store.count() == 1


def test_scheduler_run_now_unknown():
    p = _minimal_pipeline()
    scheduler = ReportScheduler(ReportBuilder(p), ReportStore(":memory:"))
    result = scheduler.run_now("SCH-GHOST")
    assert result is None


def test_scheduler_increments_run_count():
    p = _minimal_pipeline()
    builder = ReportBuilder(p)
    store = ReportStore(":memory:")
    scheduler = ReportScheduler(builder, store)
    sch = ReportSchedule(name="X")
    scheduler.add_schedule(sch)
    scheduler.run_now(sch.schedule_id)
    scheduler.run_now(sch.schedule_id)
    assert scheduler.get_schedule(sch.schedule_id).run_count == 2


def test_scheduler_on_report_callback():
    p = _minimal_pipeline()
    received = []
    scheduler = ReportScheduler(
        ReportBuilder(p), ReportStore(":memory:"),
        on_report=lambda r: received.append(r.report_id),
    )
    sch = ReportSchedule(name="cb")
    scheduler.add_schedule(sch)
    scheduler.run_now(sch.schedule_id)
    assert len(received) == 1


def test_scheduler_enable_disable():
    p = _minimal_pipeline()
    scheduler = ReportScheduler(ReportBuilder(p), ReportStore(":memory:"))
    sch = ReportSchedule(name="x")
    scheduler.add_schedule(sch)
    ok = scheduler.enable_schedule(sch.schedule_id, False)
    assert ok is True
    assert not scheduler.get_schedule(sch.schedule_id).enabled


def test_default_schedules():
    schedules = default_schedules()
    assert len(schedules) >= 3
    types = {s.report_type for s in schedules}
    assert ReportType.EXECUTIVE in types
    assert ReportType.COMPLIANCE in types


def test_scheduler_start_stop():
    p = _minimal_pipeline()
    scheduler = ReportScheduler(ReportBuilder(p), ReportStore(":memory:"), poll_interval_s=60)
    scheduler.start()
    assert scheduler._running
    scheduler.stop(timeout=1.0)
    assert not scheduler._running
