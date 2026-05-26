import io
import json
import time

import pytest

from threatpipe.alerts import (
    FileSink,
    MultiSink,
    NullSink,
    RateLimitedSink,
    StdoutSink,
    severity_at_least,
)
from threatpipe.alerts.base import SeverityFilterSink
from threatpipe.alerts.factory import build_alert_sink
from threatpipe.detection import Detection, Severity
from threatpipe.ingestion import Event
from threatpipe.utils.config import AlertConfig


def _det(severity: Severity = Severity.HIGH) -> Detection:
    return Detection(
        event=Event(host="h"),
        detector="t",
        score=0.8,
        severity=severity,
        reasons=["because"],
    )


def test_severity_at_least():
    assert severity_at_least(Severity.HIGH, Severity.MEDIUM)
    assert not severity_at_least(Severity.LOW, Severity.HIGH)


def test_null_sink_does_nothing():
    NullSink()(_det())  # no exception


def test_stdout_sink_human():
    buf = io.StringIO()
    sink = StdoutSink(stream=buf, color=False)
    sink(_det(Severity.CRITICAL))
    assert "CRITICAL" in buf.getvalue()
    assert "host=h" in buf.getvalue()


def test_stdout_sink_json():
    buf = io.StringIO()
    sink = StdoutSink(stream=buf, json_mode=True, color=False)
    sink(_det())
    payload = json.loads(buf.getvalue())
    assert payload["severity"] == "high"


def test_file_sink_writes_jsonl(tmp_path):
    path = tmp_path / "alerts.jsonl"
    sink = FileSink(path=path)
    for _ in range(3):
        sink(_det())
    sink.close()
    lines = path.read_text().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["severity"] == "high"


def test_severity_filter_drops_low():
    captured = []
    inner = lambda d: captured.append(d)
    sink = SeverityFilterSink(_FuncSink(captured), min_severity=Severity.HIGH)
    sink(_det(Severity.LOW))
    sink(_det(Severity.CRITICAL))
    assert len(captured) == 1
    assert captured[0].severity == Severity.CRITICAL


def test_rate_limited_drops_excess():
    captured = []
    rl = RateLimitedSink(_FuncSink(captured), per_minute=2)
    for _ in range(5):
        rl(_det())
    assert len(captured) == 2
    assert rl.dropped == 3


def test_multi_sink_forwards_to_all():
    a, b = [], []
    sink = MultiSink([_FuncSink(a), _FuncSink(b)])
    sink(_det())
    assert len(a) == 1 and len(b) == 1


def test_factory_builds_chain():
    cfg = AlertConfig(channels=["null"], min_severity="low", rate_limit_per_min=10)
    sink = build_alert_sink(cfg)
    sink(_det())  # no crash


def test_factory_warns_on_missing_credentials(caplog):
    cfg = AlertConfig(channels=["slack"], min_severity="low")
    sink = build_alert_sink(cfg)
    sink(_det())  # ends up at NullSink


class _FuncSink:
    name = "func"

    def __init__(self, target):
        self.target = target

    def __call__(self, d):
        self.target.append(d)

    def emit(self, d):
        self.target.append(d)
