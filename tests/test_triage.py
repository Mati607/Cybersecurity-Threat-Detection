"""Tests for the alert triage subsystem.

Covers fingerprint stability, deduplication, suppression (including the
severity ceiling and expiry), priority scoring/banding, the store's
filtering and eviction, and the end-to-end engine including downstream
forwarding and escalation.
"""

from __future__ import annotations

import time

import pytest

from threatpipe.detection import Detection, Severity
from threatpipe.ingestion import Event, EventType
from threatpipe.triage import (
    PriorityScorer,
    SuppressionList,
    SuppressionRule,
    TriageDisposition,
    TriageEngine,
    TriagePriority,
    TriageStatus,
    TriageStore,
    TriagedAlert,
    describe,
    fingerprint,
)


def _det(
    score=0.8,
    detector="rule",
    *,
    host="host0",
    user="alice",
    process="sshd",
    event_type=EventType.PROCESS,
    ts=1_700_000_000.0,
    tags=(),
    reasons=("because",),
    metadata=None,
    **event_kwargs,
):
    event = Event(
        timestamp=ts,
        event_type=event_type,
        host=host,
        user=user,
        process=process,
        **event_kwargs,
    )
    return Detection(
        event=event,
        detector=detector,
        score=score,
        severity=Severity.from_score(score),
        reasons=list(reasons),
        tags=list(tags),
        metadata=metadata or {},
    )


# --- fingerprint -----------------------------------------------------------

def test_fingerprint_is_stable_for_same_identity():
    a = _det(ts=1.0, pid=10)
    b = _det(ts=9999.0, pid=99)  # volatile fields differ
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_by_detector():
    assert fingerprint(_det(detector="rule")) != fingerprint(_det(detector="statistical"))


def test_fingerprint_independent_of_host():
    # host is tracked as spread, not a fingerprint discriminator, so the
    # same signature across the fleet collapses into one alert.
    assert fingerprint(_det(host="host0")) == fingerprint(_det(host="host1"))


def test_fingerprint_network_uses_dst():
    a = _det(event_type=EventType.NETWORK, process=None, dst_ip="1.1.1.1", dst_port=443)
    b = _det(event_type=EventType.NETWORK, process=None, dst_ip="2.2.2.2", dst_port=443)
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_extra_fields_widen_identity():
    a = _det(command_line="a")
    b = _det(command_line="b")
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a, extra_fields=["command_line"]) != fingerprint(b, extra_fields=["command_line"])


def test_describe_mentions_detector_and_discriminator():
    text = describe(_det(process="sshd"))
    assert "rule" in text
    assert "sshd" in text


# --- suppression rule matching ---------------------------------------------

def test_rule_matches_exact_field():
    rule = SuppressionRule(rule_id="r1", match={"host": "host0"})
    assert rule.matches(_det(host="host0"))
    assert not rule.matches(_det(host="host1"))


def test_rule_matches_wildcard_prefix():
    rule = SuppressionRule(rule_id="r1", match={"process": "/usr/bin/*"})
    assert rule.matches(_det(process="/usr/bin/curl"))
    assert not rule.matches(_det(process="/opt/evil"))


def test_rule_matches_synthetic_detector_field():
    rule = SuppressionRule(rule_id="r1", match={"detector": "statistical"})
    assert rule.matches(_det(detector="statistical"))
    assert not rule.matches(_det(detector="rule"))


def test_rule_matches_tag_membership():
    rule = SuppressionRule(rule_id="r1", match={"tag": "scanner"})
    assert rule.matches(_det(tags=["scanner", "low_priority"]))
    assert not rule.matches(_det(tags=["c2"]))


def test_rule_requires_all_conditions():
    rule = SuppressionRule(rule_id="r1", match={"host": "host0", "process": "sshd"})
    assert rule.matches(_det(host="host0", process="sshd"))
    assert not rule.matches(_det(host="host0", process="bash"))


def test_empty_match_never_suppresses():
    assert not SuppressionRule(rule_id="r1", match={}).matches(_det())


def test_severity_ceiling_protects_critical():
    rule = SuppressionRule(rule_id="r1", match={"host": "host0"}, max_severity=Severity.MEDIUM)
    assert rule.matches(_det(host="host0", score=0.3))     # low -> suppressed
    assert not rule.matches(_det(host="host0", score=0.95))  # critical -> protected


def test_rule_roundtrip_dict():
    rule = SuppressionRule(rule_id="r1", name="n", match={"host": "h"}, max_severity=Severity.HIGH)
    restored = SuppressionRule.from_dict(rule.to_dict())
    assert restored.rule_id == "r1"
    assert restored.max_severity == Severity.HIGH
    assert restored.match == {"host": "h"}


def test_from_dict_requires_rule_id():
    with pytest.raises(ValueError):
        SuppressionRule.from_dict({"match": {"host": "h"}})


# --- suppression list ------------------------------------------------------

def test_list_match_bumps_hit_count():
    sl = SuppressionList()
    sl.add(SuppressionRule(rule_id="r1", match={"host": "host0"}))
    assert sl.match(_det(host="host0")) is not None
    assert sl.match(_det(host="host0")) is not None
    assert sl.get("r1").hit_count == 2


def test_list_skips_disabled_rules():
    sl = SuppressionList()
    sl.add(SuppressionRule(rule_id="r1", match={"host": "host0"}, enabled=False))
    assert sl.match(_det(host="host0")) is None


def test_list_skips_and_prunes_expired():
    sl = SuppressionList()
    sl.add(SuppressionRule(rule_id="r1", match={"host": "host0"}, expires_at=time.time() - 1))
    assert sl.match(_det(host="host0")) is None
    assert sl.prune_expired() == 1
    assert len(sl) == 0


def test_list_newest_rule_wins():
    sl = SuppressionList()
    sl.add(SuppressionRule(rule_id="old", match={"host": "host0"}, created_at=1.0))
    sl.add(SuppressionRule(rule_id="new", match={"host": "host0"}, created_at=2.0))
    assert sl.match(_det(host="host0")).rule_id == "new"


def test_list_export_load_roundtrip(tmp_path):
    sl = SuppressionList()
    sl.add(SuppressionRule(rule_id="r1", match={"host": "host0"}))
    path = tmp_path / "rules.json"
    assert sl.export_json(path) == 1
    sl2 = SuppressionList()
    assert sl2.load_json(path) == 1
    assert sl2.get("r1") is not None


# --- priority scoring ------------------------------------------------------

def test_priority_critical_single_beats_threshold():
    scorer = PriorityScorer()
    alert = TriagedAlert(alert_id="a", fingerprint="f", title="t", detector="d",
                         first_seen=0, last_seen=0, severity=Severity.CRITICAL,
                         count=1, max_score=0.95)
    scorer.assign(alert)
    assert alert.priority.at_least(TriagePriority.P3)


def test_priority_volume_escalates_low_severity():
    scorer = PriorityScorer()
    quiet = TriagedAlert(alert_id="a", fingerprint="f", title="t", detector="d",
                         first_seen=0, last_seen=0, severity=Severity.MEDIUM,
                         count=1, max_score=0.5)
    loud = TriagedAlert(alert_id="b", fingerprint="g", title="t", detector="d",
                        first_seen=0, last_seen=0, severity=Severity.MEDIUM,
                        count=200, max_score=0.5, hosts={f"h{i}" for i in range(30)})
    assert scorer.score(loud) > scorer.score(quiet)
    assert loud.fingerprint  # sanity
    assert scorer.band(scorer.score(loud)).at_least(scorer.band(scorer.score(quiet)))


def test_priority_intel_hit_raises_score():
    scorer = PriorityScorer()
    alert = TriagedAlert(alert_id="a", fingerprint="f", title="t", detector="d",
                         first_seen=0, last_seen=0, severity=Severity.MEDIUM,
                         count=1, max_score=0.5)
    base = scorer.score(alert)
    boosted = scorer.score(alert, intel_hit=True)
    assert boosted > base


def test_priority_band_monotonic():
    scorer = PriorityScorer()
    assert scorer.band(0.9) == TriagePriority.P1
    assert scorer.band(0.7) == TriagePriority.P2
    assert scorer.band(0.5) == TriagePriority.P3
    assert scorer.band(0.25) == TriagePriority.P4
    assert scorer.band(0.05) == TriagePriority.P5


def test_priority_score_stays_normalized():
    scorer = PriorityScorer()
    alert = TriagedAlert(alert_id="a", fingerprint="f", title="t", detector="d",
                         first_seen=0, last_seen=0, severity=Severity.CRITICAL,
                         count=10_000, max_score=1.0, hosts={f"h{i}" for i in range(500)})
    assert 0.0 <= scorer.score(alert, intel_hit=True) <= 1.0


def test_priority_degenerate_weights_fall_back():
    scorer = PriorityScorer(severity_w=0, volume_w=0, spread_w=0, intel_w=0, confidence_w=0)
    alert = TriagedAlert(alert_id="a", fingerprint="f", title="t", detector="d",
                         first_seen=0, last_seen=0, severity=Severity.CRITICAL,
                         count=1, max_score=1.0)
    # severity-only fallback -> critical severity weight is 1.0
    assert scorer.score(alert) == pytest.approx(1.0)


# --- alert model -----------------------------------------------------------

def test_alert_absorb_dedups_event_ids():
    d = _det()
    alert = TriagedAlert(alert_id="a", fingerprint="f", title="t", detector="d",
                         first_seen=d.event.timestamp, last_seen=d.event.timestamp)
    alert.absorb(d)
    alert.absorb(d)  # same event id, ignored
    assert alert.count == 1


def test_alert_absorb_tracks_hosts_and_severity():
    alert = TriagedAlert(alert_id="a", fingerprint="f", title="t", detector="d",
                         first_seen=0, last_seen=0)
    alert.absorb(_det(host="h1", score=0.4))
    alert.absorb(_det(host="h2", score=0.95, process="x"))
    assert alert.distinct_hosts == 2
    assert alert.severity == Severity.CRITICAL


def test_priority_at_least_semantics():
    assert TriagePriority.P1.at_least(TriagePriority.P3)
    assert not TriagePriority.P4.at_least(TriagePriority.P2)


# --- store -----------------------------------------------------------------

def _alert(alert_id, *, priority=TriagePriority.P3, status=TriageStatus.NEW,
           severity=Severity.MEDIUM, host="h", last_seen=1.0, fingerprint="fp"):
    a = TriagedAlert(alert_id=alert_id, fingerprint=fingerprint + alert_id, title="t",
                     detector="d", first_seen=0.0, last_seen=last_seen,
                     severity=severity, priority=priority, status=status)
    a.hosts.add(host)
    return a


def test_store_get_by_fingerprint():
    store = TriageStore()
    a = _alert("a1", fingerprint="abc")
    store.upsert(a)
    assert store.get_by_fingerprint("abca1") is a
    assert store.get("a1") is a


def test_store_filter_by_status_and_priority():
    store = TriageStore()
    store.upsert(_alert("a1", priority=TriagePriority.P1, status=TriageStatus.NEW))
    store.upsert(_alert("a2", priority=TriagePriority.P4, status=TriageStatus.CLOSED))
    p1 = store.list(min_priority=TriagePriority.P2)
    assert {a.alert_id for a in p1} == {"a1"}
    closed = store.list(status=TriageStatus.CLOSED)
    assert {a.alert_id for a in closed} == {"a2"}


def test_store_active_only_and_host_filter():
    store = TriageStore()
    store.upsert(_alert("a1", status=TriageStatus.NEW, host="web"))
    store.upsert(_alert("a2", status=TriageStatus.SUPPRESSED, host="db"))
    assert {a.alert_id for a in store.list(active_only=True)} == {"a1"}
    assert {a.alert_id for a in store.list(host="db")} == {"a2"}


def test_store_sorts_most_urgent_first():
    store = TriageStore()
    store.upsert(_alert("low", priority=TriagePriority.P4))
    store.upsert(_alert("high", priority=TriagePriority.P1))
    assert [a.alert_id for a in store.list()][0] == "high"


def test_store_eviction_prefers_inactive():
    store = TriageStore(max_size=2)
    store.upsert(_alert("closed", status=TriageStatus.CLOSED, last_seen=1.0))
    store.upsert(_alert("open1", status=TriageStatus.NEW, last_seen=2.0))
    store.upsert(_alert("open2", status=TriageStatus.NEW, last_seen=3.0))
    ids = {a.alert_id for a in store.list(limit=10)}
    assert "closed" not in ids
    assert ids == {"open1", "open2"}


def test_store_update_status_and_disposition():
    store = TriageStore()
    store.upsert(_alert("a1"))
    updated = store.update("a1", status=TriageStatus.CLOSED,
                           disposition=TriageDisposition.FALSE_POSITIVE, note="benign")
    assert updated.status == TriageStatus.CLOSED
    assert updated.disposition == TriageDisposition.FALSE_POSITIVE
    assert "benign" in updated.notes


def test_store_stats_dedup_ratio():
    store = TriageStore()
    a = _alert("a1")
    a.count = 10
    store.upsert(a)
    stats = store.stats()
    assert stats["total_alerts"] == 1
    assert stats["total_detections"] == 10
    assert stats["dedup_ratio"] == 10.0


# --- engine end to end -----------------------------------------------------

def test_engine_dedups_recurring_detections():
    engine = TriageEngine()
    r1 = engine.ingest(_det(ts=1000.0))
    r2 = engine.ingest(_det(ts=1001.0))
    assert r1.is_new
    assert not r2.is_new
    assert r1.alert.alert_id == r2.alert.alert_id
    assert r2.alert.count == 2
    assert len(engine.store) == 1


def test_engine_separate_fingerprints_separate_alerts():
    engine = TriageEngine()
    engine.ingest(_det(detector="rule"))
    engine.ingest(_det(detector="statistical"))
    assert len(engine.store) == 2


def test_engine_collapses_same_signature_across_hosts():
    engine = TriageEngine()
    r1 = engine.ingest(_det(host="h1", ts=1000.0))
    r2 = engine.ingest(_det(host="h2", ts=1001.0))
    assert r1.alert.alert_id == r2.alert.alert_id
    assert r2.alert.distinct_hosts == 2


def test_engine_dedup_window_opens_new_alert():
    engine = TriageEngine(dedup_window_s=60.0)
    engine.ingest(_det(ts=1000.0))
    r = engine.ingest(_det(ts=2000.0))  # far outside window
    assert r.is_new
    assert len(engine.store) == 2


def test_engine_suppresses_matching_detection():
    engine = TriageEngine()
    engine.suppressions.add(SuppressionRule(rule_id="r1", match={"host": "host0"}))
    result = engine.ingest(_det(host="host0"))
    assert result.suppressed
    assert result.alert.status == TriageStatus.SUPPRESSED
    assert result.alert.suppressed_by == "r1"
    assert not result.forwarded


def test_engine_forwards_new_actionable_to_downstream():
    seen = []
    engine = TriageEngine(downstream=seen.append)
    result = engine.ingest(_det(score=0.95))
    assert result.forwarded
    assert seen and seen[0].alert_id == result.alert.alert_id


def test_engine_does_not_forward_suppressed():
    seen = []
    engine = TriageEngine(downstream=seen.append)
    engine.suppressions.add(SuppressionRule(rule_id="r1", match={"detector": "rule"}))
    engine.ingest(_det())
    assert seen == []


def test_engine_does_not_reforward_recurrence_without_escalation():
    seen = []
    engine = TriageEngine(downstream=seen.append)
    engine.ingest(_det(score=0.95, ts=1.0))
    engine.ingest(_det(score=0.95, ts=2.0))
    assert len(seen) == 1  # only the first


def test_engine_forwards_on_escalation():
    seen = []
    # A quiet single medium starts at P4; as the same signature spreads
    # across hosts and recurs, volume+spread push it past the P3 floor.
    engine = TriageEngine(downstream=seen.append, escalate_at=TriagePriority.P3)
    base_ts = 1000.0
    escalated_any = False
    for i in range(30):
        r = engine.ingest(_det(score=0.5, host=f"host{i}", ts=base_ts + i, process="sshd"))
        escalated_any = escalated_any or r.escalated
    assert escalated_any
    # first forward (new) + at least one escalation forward
    assert len(seen) >= 2


def test_engine_intel_match_flagged():
    engine = TriageEngine()
    result = engine.ingest(_det(tags=["intel:malware"]))
    assert result.alert.metadata.get("intel_hit") is True


def test_engine_callable_interface_swallows_errors():
    engine = TriageEngine()
    # __call__ should not raise even though ingest runs fully.
    engine(_det())
    assert len(engine.store) == 1


def test_engine_stats_reports_dedup_and_forwarded():
    seen = []
    engine = TriageEngine(downstream=seen.append)
    for i in range(5):
        engine.ingest(_det(score=0.95, ts=1000.0 + i))
    stats = engine.stats()
    assert stats["total_alerts"] == 1
    assert stats["total_detections"] == 5
    assert stats["forwarded_downstream"] == 1
    assert "suppression" in stats
