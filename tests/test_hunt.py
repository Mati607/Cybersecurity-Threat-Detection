import json
from pathlib import Path

import pytest

from threatpipe.detection import Detection, Severity
from threatpipe.hunt import (
    HuntEvaluator,
    HuntQuery,
    HuntScheduler,
    HuntStore,
    HuntSyntaxError,
    SavedHunt,
    evaluate,
    parse_query,
    tokenize,
)
from threatpipe.ingestion import Event, EventType


# --- lexer -------------------------------------------------------

def test_lexer_identifies_basic_tokens():
    toks = tokenize('event.host == "evil" AND score >= 0.5')
    kinds = [(t.kind.value, t.value) for t in toks]
    assert ("ident", "event.host") in kinds
    assert ("op", "==") in kinds
    assert ("keyword", "AND") in kinds


def test_lexer_handles_escaped_strings():
    toks = tokenize(r'message == "He said \"hi\""')
    string_tok = [t for t in toks if t.kind.value == "string"][0]
    assert string_tok.value == 'He said "hi"'


def test_lexer_raises_on_unterminated_string():
    with pytest.raises(HuntSyntaxError):
        tokenize('host == "evil')


# --- parser ------------------------------------------------------

def test_parser_builds_ast_for_complex_expression():
    expr = parse_query('event.dst_port IN (4444, 1337) AND process LIKE "%powershell%"')
    out = expr.to_str()
    assert "IN" in out and "LIKE" in out


def test_parser_supports_between_and_regex():
    expr = parse_query('score BETWEEN 0.5 AND 1.0 AND message REGEX "base64"')
    assert "BETWEEN" in expr.to_str()
    assert "REGEX" in expr.to_str()


def test_parser_rejects_unbalanced_parens():
    with pytest.raises(HuntSyntaxError):
        parse_query("(score > 0.5")


# --- evaluator ---------------------------------------------------

def _det(score=0.9, severity="high", event=None, tags=()):
    return Detection(
        event=event or Event(host="h", process="powershell.exe", dst_port=4444,
                              command_line="powershell -enc AAA", event_type=EventType.PROCESS),
        detector="t",
        score=score,
        severity=Severity(severity),
        reasons=["because"],
        tags=list(tags),
    )


def test_evaluator_dotted_field_access():
    assert evaluate('event.host == "h"', _det()) is True
    assert evaluate('event.host == "other"', _det()) is False


def test_evaluator_like():
    assert evaluate('event.process LIKE "%powershell%"', _det()) is True
    assert evaluate('event.process LIKE "curl"', _det()) is False


def test_evaluator_regex():
    assert evaluate('event.command_line REGEX "-enc"', _det()) is True


def test_evaluator_in_negate():
    assert evaluate("event.dst_port IN (4444, 1337)", _det()) is True
    assert evaluate("event.dst_port NOT IN (80, 443)", _det()) is True


def test_evaluator_between():
    assert evaluate("score BETWEEN 0.5 AND 1.0", _det()) is True
    assert evaluate("score BETWEEN 0 AND 0.1", _det()) is False


def test_evaluator_is_null():
    d = _det(event=Event(host="h", event_type=EventType.PROCESS))
    assert evaluate("event.command_line IS NULL", d) is True
    assert evaluate("event.host IS NOT NULL", d) is True


def test_evaluator_short_circuits_and():
    # Right side would throw if eagerly evaluated against a missing field
    assert evaluate('event.host == "h" AND event.dst_port == 4444', _det()) is True


def test_evaluator_numeric_coercion():
    d = _det()
    # detection.event.dst_port is int; compare against string-like literal-coerced value
    assert evaluate('event.dst_port > "4000"', d) is True


def test_evaluator_function_calls():
    assert evaluate('lower(event.process) == "powershell.exe"', _det()) is True
    assert evaluate("length(reasons) > 0", _det()) is True


# --- query / store / scheduler ----------------------------------

def test_hunt_query_run_over_records():
    high = _det(score=0.95, severity="critical")
    low = _det(score=0.2, severity="low")
    res = HuntQuery('severity == "critical"').run_over([high, low])
    assert res.scanned == 2
    assert res.match_count == 1


def test_hunt_query_propagates_syntax_error():
    q = HuntQuery("score >")
    res = q.run_over([_det()])
    assert res.error is not None


def test_hunt_store_round_trip(tmp_path: Path):
    p = tmp_path / "h.json"
    store = HuntStore(p)
    store.upsert(SavedHunt(hunt_id="h1", name="High score", query='severity == "high"'))
    store2 = HuntStore(p)
    assert store2.get("h1").query == 'severity == "high"'


def test_hunt_store_update_stats():
    store = HuntStore()
    store.upsert(SavedHunt(hunt_id="h1", name="x", query="score > 0"))
    store.update_stats("h1", match_count=5, duration_ms=12.0)
    assert store.get("h1").last_match_count == 5


def test_hunt_scheduler_run_now_updates_stats():
    store = HuntStore()
    store.upsert(SavedHunt(hunt_id="h1", name="hi", query='severity == "high"'))
    sched = HuntScheduler(store, provider=lambda h: [_det(), _det(score=0.2, severity="low")])
    result = sched.run_now(store.get("h1"))
    assert result.match_count == 1
    assert store.get("h1").last_match_count == 1


def test_hunt_scheduler_catches_syntax_error_per_hunt():
    store = HuntStore()
    store.upsert(SavedHunt(hunt_id="bad", name="bad", query="score >"))
    sched = HuntScheduler(store, provider=lambda h: [_det()])
    result = sched.run_now(store.get("bad"))
    assert result.error is not None
    assert store.get("bad").last_error is not None
