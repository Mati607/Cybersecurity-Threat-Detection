import json
from pathlib import Path

import pytest

from threatpipe.detection import Detection, Severity
from threatpipe.incidents import Incident, IncidentStatus
from threatpipe.ingestion import Event, EventType
from threatpipe.response import (
    ActionContext,
    ActionStatus,
    AuditLog,
    BlockIPAction,
    KillProcessAction,
    NotifyAction,
    Playbook,
    PlaybookCondition,
    PlaybookStep,
    PlaybookTrigger,
    ResponseEngine,
    ShellAction,
    SnapshotGraphAction,
    TagIncidentAction,
    UpdateIncidentStatusAction,
    load_playbooks,
)


def _det(score=0.9, severity=Severity.HIGH, tags=(), event=None):
    return Detection(
        event=event or Event(host="h", process="p", pid=1, dst_ip="1.2.3.4",
                              event_type=EventType.NETWORK, timestamp=1),
        detector="t",
        score=score,
        severity=severity,
        reasons=["because"],
        tags=list(tags),
    )


def _incident(severity=Severity.HIGH, tags=()):
    return Incident(
        incident_id="INC-1",
        title="x",
        first_seen=1,
        last_seen=2,
        severity=severity,
        score=0.8,
        status=IncidentStatus.OPEN,
        affected_hosts={"h"},
        tags=set(tags),
    )


# --- actions ------------------------------------------------------

def test_block_ip_dry_run_when_no_backend():
    BlockIPAction._backends.pop("firewall", None)
    action = BlockIPAction()
    result = action(ActionContext(detection=_det()))
    assert result.status == ActionStatus.DRY_RUN
    assert "1.2.3.4" in result.detail


def test_block_ip_invokes_backend():
    calls = []
    BlockIPAction.bind_backend("firewall", lambda ip: calls.append(ip))
    try:
        result = BlockIPAction()(ActionContext(detection=_det()))
        assert result.status == ActionStatus.SUCCESS
        assert calls == ["1.2.3.4"]
    finally:
        BlockIPAction._backends.pop("firewall", None)


def test_kill_process_skipped_when_missing_args():
    KillProcessAction._backends.pop("edr", None)
    result = KillProcessAction()(ActionContext(detection=Detection(
        event=Event(event_type=EventType.PROCESS), detector="t", score=0.5,
        severity=Severity.MEDIUM, reasons=[],
    )))
    assert result.status == ActionStatus.SKIPPED


def test_notify_dry_run_renders_template():
    NotifyAction._backends.pop("notify", None)
    ctx = ActionContext(detection=_det(),
                         args={"message": "host={event.host} score={detection.score}"})
    result = NotifyAction()(ctx)
    assert result.status == ActionStatus.DRY_RUN
    assert "host=h" in result.detail


def test_shell_action_blocks_without_allow_list():
    ShellAction._backends.pop("shell_allow", None)
    result = ShellAction()(ActionContext(args={"cmd": "ls /"}))
    assert result.status == ActionStatus.SKIPPED


def test_tag_incident_action_updates_set():
    inc = _incident()
    result = TagIncidentAction()(ActionContext(incident=inc, args={"tag": "auto"}))
    assert result.status == ActionStatus.SUCCESS
    assert "auto" in inc.tags


def test_update_incident_status_validates():
    inc = _incident()
    ok = UpdateIncidentStatusAction()(ActionContext(incident=inc, args={"status": "contained"}))
    assert ok.status == ActionStatus.SUCCESS
    assert inc.status == IncidentStatus.CONTAINED
    bad = UpdateIncidentStatusAction()(ActionContext(incident=inc, args={"status": "nope"}))
    assert bad.status == ActionStatus.FAILURE


def test_snapshot_graph_skipped_without_graph():
    result = SnapshotGraphAction()(ActionContext(detection=_det()))
    assert result.status == ActionStatus.SKIPPED


# --- playbook model ----------------------------------------------

def test_playbook_condition_resolves_dotted_path():
    cond = PlaybookCondition("event.host", "==", "h")
    assert cond.evaluate({"event": Event(host="h")}) is True
    assert cond.evaluate({"event": Event(host="x")}) is False


def test_playbook_is_applicable_checks_severity_floor():
    pb = Playbook(playbook_id="p", name="p", trigger=PlaybookTrigger.DETECTION,
                  steps=[], min_severity="high")
    assert pb.is_applicable({"severity": "critical"})
    assert not pb.is_applicable({"severity": "low"})


def test_playbook_is_applicable_checks_tags_required():
    pb = Playbook(playbook_id="p", name="p", trigger=PlaybookTrigger.DETECTION,
                  steps=[], tags_required=["c2"])
    assert pb.is_applicable({"severity": "low", "tags": ["c2", "lateral"]})
    assert not pb.is_applicable({"severity": "low", "tags": ["other"]})


def test_playbook_from_dict_round_trip():
    raw = {
        "id": "pb1",
        "name": "pb1",
        "trigger": "incident_opened",
        "min_severity": "medium",
        "steps": [{"id": "s1", "action": "notify", "args": {"channel": "ops"}}],
    }
    pb = Playbook.from_dict(raw)
    out = pb.to_dict()
    assert out["playbook_id"] == "pb1"
    assert out["steps"][0]["action"] == "notify"


# --- engine ------------------------------------------------------

def test_response_engine_fires_matching_playbook():
    engine = ResponseEngine()
    pb = Playbook(playbook_id="pb", name="pb",
                  trigger=PlaybookTrigger.DETECTION,
                  steps=[PlaybookStep(step_id="s1", action="notify", args={"message": "hi"})])
    engine.register_playbooks([pb])
    results = engine.on_detection(_det())
    assert len(results) == 1
    assert results[0].action == "notify"
    assert engine.audit_log.list()[0].playbook_id == "pb"


def test_response_engine_skips_when_severity_too_low():
    engine = ResponseEngine()
    pb = Playbook(playbook_id="pb", name="pb",
                  trigger=PlaybookTrigger.DETECTION,
                  steps=[PlaybookStep(step_id="s1", action="notify")],
                  min_severity="critical")
    engine.register_playbooks([pb])
    results = engine.on_detection(_det(severity=Severity.LOW))
    assert results == []


def test_response_engine_rate_limits_playbook():
    engine = ResponseEngine()
    pb = Playbook(playbook_id="rl", name="rl",
                  trigger=PlaybookTrigger.DETECTION,
                  steps=[PlaybookStep(step_id="s1", action="notify")],
                  max_per_minute=2)
    engine.register_playbooks([pb])
    fires = 0
    for _ in range(5):
        if engine.on_detection(_det()):
            fires += 1
    assert fires == 2


def test_response_engine_aborts_on_failure_without_continue():
    engine = ResponseEngine()
    pb = Playbook(playbook_id="pb", name="pb",
                  trigger=PlaybookTrigger.INCIDENT_OPENED, steps=[
        PlaybookStep(step_id="s1", action="update_incident_status", args={"status": "bogus"}),
        PlaybookStep(step_id="s2", action="notify"),
    ])
    engine.register_playbooks([pb])
    results = engine.on_incident(_incident(), new=True)
    # incident steps: s1 fails (unknown status), s2 must not run
    assert any(r.action == "update_incident_status" for r in results)
    assert all(r.action != "notify" for r in results)


def test_response_engine_global_dry_run_overrides_backend():
    BlockIPAction.bind_backend("firewall", lambda ip: (_ for _ in ()).throw(RuntimeError("should not run")))
    try:
        engine = ResponseEngine(global_dry_run=True)
        pb = Playbook(playbook_id="pb", name="pb", trigger=PlaybookTrigger.DETECTION,
                      steps=[PlaybookStep(step_id="s1", action="block_ip")])
        engine.register_playbooks([pb])
        results = engine.on_detection(_det())
        assert results[0].status == ActionStatus.DRY_RUN
    finally:
        BlockIPAction._backends.pop("firewall", None)


# --- audit log + persistence -------------------------------------

def test_audit_log_records_and_filters():
    engine = ResponseEngine()
    pb = Playbook(playbook_id="pb", name="pb", trigger=PlaybookTrigger.DETECTION,
                  steps=[PlaybookStep(step_id="s1", action="notify")])
    engine.register_playbooks([pb])
    for _ in range(3):
        engine.on_detection(_det())
    assert len(engine.audit_log) == 3
    by_action = engine.audit_log.list(action="notify")
    assert len(by_action) == 3


def test_load_playbooks_skips_invalid(tmp_path: Path):
    raw = {
        "playbooks": [
            {"id": "good", "trigger": "detection", "steps": [{"action": "notify"}]},
            {"trigger": "detection"},  # missing id - should be skipped
        ]
    }
    p = tmp_path / "pbs.json"
    p.write_text(json.dumps(raw))
    pbs = load_playbooks(p)
    assert [pb.playbook_id for pb in pbs] == ["good"]
