import json
import re
from pathlib import Path

import pytest

from threatpipe.detection import Rule, RuleEngine, Severity
from threatpipe.ingestion import Event, EventType


def test_default_rule_catalog_loads():
    engine = RuleEngine()
    assert engine.rules
    ids = {r.id for r in engine.rules}
    assert "T1486.RANSOMWARE_EXT" in ids


def test_encoded_payload_triggers():
    engine = RuleEngine()
    ev = Event(
        event_type=EventType.PROCESS,
        command_line="powershell -enc " + "A" * 64,
    )
    det = engine.detect(ev)
    assert det is not None
    assert det.score >= 0.8
    assert det.severity == Severity.HIGH


def test_sensitive_file_read_triggers():
    engine = RuleEngine()
    ev = Event(event_type=EventType.FILE, file_path="/etc/shadow", action="read")
    det = engine.detect(ev)
    assert det is not None
    assert det.severity == Severity.HIGH


def test_ransomware_extension_triggers_critical():
    engine = RuleEngine()
    ev = Event(event_type=EventType.FILE, file_path="docs/secret.locked", action="write")
    det = engine.detect(ev)
    assert det is not None
    assert det.severity == Severity.CRITICAL


def test_benign_event_does_not_trigger():
    engine = RuleEngine()
    ev = Event(event_type=EventType.PROCESS, command_line="ls -l")
    assert engine.detect(ev) is None


def test_multiple_hits_increase_score():
    engine = RuleEngine(rules=[
        Rule(id="A", name="a", score=0.6, severity=Severity.MEDIUM,
             where={"event_type": EventType.PROCESS.value}),
        Rule(id="B", name="b", score=0.6, severity=Severity.MEDIUM,
             where={"command_line": re.compile(r"ls")}),
    ])
    ev = Event(event_type=EventType.PROCESS, command_line="ls -la")
    det = engine.detect(ev)
    assert det is not None
    assert det.score > 0.6
    assert len(det.reasons) == 2


def test_callable_matcher():
    rule = Rule(
        id="C", name="callable", score=0.9, severity=Severity.HIGH,
        where={"pid": lambda ev: ev.pid is not None and ev.pid > 1000},
    )
    engine = RuleEngine(rules=[rule])
    assert engine.detect(Event(pid=1500)) is not None
    assert engine.detect(Event(pid=10)) is None


def test_rule_engine_from_json(tmp_path: Path):
    cfg = {
        "rules": [
            {
                "id": "TEST.001",
                "name": "Test regex",
                "score": 0.7,
                "severity": "medium",
                "where": {
                    "command_line": {"regex": "evil"},
                    "event_type": "process",
                },
                "tags": ["test"],
            }
        ]
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(cfg))
    engine = RuleEngine.from_json(path)
    assert len(engine.rules) == 1
    det = engine.detect(Event(event_type=EventType.PROCESS, command_line="run-evil-thing"))
    assert det is not None


def test_comparison_op_matcher():
    rule = Rule(
        id="D", name="big bytes", score=0.7, severity=Severity.MEDIUM,
        where={"bytes_sent": (">", 1000)},
    )
    engine = RuleEngine(rules=[rule])
    assert engine.detect(Event(bytes_sent=2000)) is not None
    assert engine.detect(Event(bytes_sent=10)) is None
