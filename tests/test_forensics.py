import os
import tempfile
import zipfile
from pathlib import Path

import pytest

from threatpipe.detection import Detection, Severity
from threatpipe.forensics import (
    ForensicsQuery,
    ForensicsSink,
    ForensicsStore,
    RetentionPolicy,
    RetentionSweeper,
    TimeRange,
    export_csv,
    export_jsonl,
    export_zip_bundle,
)
from threatpipe.ingestion import Event, EventType


def _event(i, host="h0", ts=1_700_000_000):
    return Event(host=host, process="bash", pid=10 + i, event_type=EventType.PROCESS,
                 timestamp=ts + i * 10)


def _det(event, score=0.8, severity=Severity.HIGH):
    return Detection(event=event, detector="rule", score=score, severity=severity,
                     reasons=["r"], tags=["t"])


def test_store_records_and_reads_event():
    store = ForensicsStore(":memory:")
    ev = _event(1)
    store.record_event(ev)
    rec = store.event_by_id(ev.event_id)
    assert rec is not None
    assert rec.host == "h0"


def test_store_event_insert_is_idempotent():
    store = ForensicsStore(":memory:")
    ev = _event(1)
    id1 = store.record_event(ev)
    id2 = store.record_event(ev)
    assert id1 == id2
    assert store.stats()["events"]["count"] == 1


def test_store_records_detection_and_links_to_event():
    store = ForensicsStore(":memory:")
    ev = _event(1)
    det = _det(ev)
    store.record_event(ev)
    store.record_detection(det)
    found = store.detections_for_event(ev.event_id)
    assert len(found) == 1
    assert found[0].detector == "rule"


def test_store_stats_severity_breakdown():
    store = ForensicsStore(":memory:")
    for i in range(6):
        ev = _event(i)
        store.record_detection(_det(ev, severity=Severity.CRITICAL if i % 2 else Severity.LOW))
    stats = store.stats()
    assert stats["detections"]["count"] == 6
    assert stats["detections_by_severity"]["critical"] == 3


def test_store_time_range_filter():
    store = ForensicsStore(":memory:")
    for i in range(10):
        store.record_detection(_det(_event(i)))
    items = list(store.iter_detections(since=1_700_000_000, until=1_700_000_030, limit=100))
    # events at ts 0,10,20,30 -> 4 detections in window
    assert len(items) == 4


def test_sink_buffers_and_flushes():
    store = ForensicsStore(":memory:")
    sink = ForensicsSink(store, buffer_size=5)
    for i in range(3):
        sink.on_event(_event(i))
    # buffered, not yet written
    assert store.stats()["events"]["count"] == 0
    sink.flush()
    assert store.stats()["events"]["count"] == 3


def test_sink_writes_through_when_unbuffered():
    store = ForensicsStore(":memory:")
    sink = ForensicsSink(store, buffer_size=0)
    sink.on_event(_event(1))
    assert store.stats()["events"]["count"] == 1


def test_query_histogram():
    store = ForensicsStore(":memory:")
    for i in range(10):
        store.record_detection(_det(_event(i)))
    q = ForensicsQuery(store)
    agg = q.detections_histogram(range=TimeRange(since=1_700_000_000, until=1_700_000_100), bin_seconds=30)
    assert agg.total == 10
    assert len(agg.buckets) >= 3


def test_query_top_hosts():
    store = ForensicsStore(":memory:")
    for i in range(5):
        store.record_detection(_det(_event(i, host="a")))
    for i in range(2):
        store.record_detection(_det(_event(i + 100, host="b")))
    q = ForensicsQuery(store)
    agg = q.top_hosts(range=TimeRange())
    assert agg.buckets[0]["host"] == "a"
    assert agg.buckets[0]["count"] == 5


def test_export_jsonl_and_csv(tmp_path: Path):
    store = ForensicsStore(":memory:")
    for i in range(4):
        store.record_detection(_det(_event(i)))
    jpath = tmp_path / "d.jsonl"
    n = export_jsonl(store.iter_detections(limit=100), jpath)
    assert n == 4
    assert len(jpath.read_text().splitlines()) == 4
    cpath = tmp_path / "d.csv"
    n = export_csv(store.iter_detections(limit=100), cpath)
    assert n == 4


def test_export_zip_bundle(tmp_path: Path):
    store = ForensicsStore(":memory:")
    for i in range(3):
        ev = _event(i)
        store.record_event(ev)
        store.record_detection(_det(ev))
    zpath = tmp_path / "bundle.zip"
    manifest = export_zip_bundle(store, zpath)
    assert manifest["counts"]["detections"] == 3
    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
        assert "detections.jsonl" in names
        assert "manifest.json" in names


def test_retention_sweeper_removes_old_rows():
    store = ForensicsStore(":memory:")
    for i in range(5):
        store.record_event(_event(i))
    policy = RetentionPolicy(event_retention_days=0, detection_retention_days=0, incident_retention_days=0)
    sweeper = RetentionSweeper(store, policy, interval_s=999)
    removed = sweeper.sweep_now()
    assert removed["events"] == 5
    assert store.stats()["events"]["count"] == 0


def test_disk_backed_store_persists(tmp_path: Path):
    db = tmp_path / "forensics.db"
    store = ForensicsStore(db)
    ev = _event(1)
    store.record_event(ev)
    store.close()
    store2 = ForensicsStore(db)
    assert store2.event_by_id(ev.event_id) is not None
