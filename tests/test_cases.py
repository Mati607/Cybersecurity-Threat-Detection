import time
from pathlib import Path

import pytest

from threatpipe.cases import (
    CaseManager,
    CasePriority,
    CaseStatus,
    CaseStore,
    EvidenceType,
    SLAPolicy,
    evaluate_sla,
)


def test_open_case_seeds_custody():
    mgr = CaseManager()
    case = mgr.open_case("Test", reporter="alice", priority=CasePriority.P2,
                         incident_ids=["INC-1"])
    assert case.custody  # at least the CREATED entry
    assert case.custody_is_valid()
    assert "INC-1" in case.incident_ids


def test_priority_from_severity():
    assert CasePriority.from_severity("critical") == CasePriority.P1
    assert CasePriority.from_severity("low") == CasePriority.P4


def test_assign_and_status_change_append_custody():
    mgr = CaseManager()
    case = mgr.open_case("Test")
    before = len(case.custody)
    mgr.assign(case.case_id, "bob")
    mgr.change_status(case.case_id, CaseStatus.IN_PROGRESS, actor="bob")
    case = mgr.get(case.case_id)
    assert len(case.custody) == before + 2
    assert case.assignee == "bob"
    assert case.status == CaseStatus.IN_PROGRESS


def test_close_sets_closed_at():
    mgr = CaseManager()
    case = mgr.open_case("Test")
    mgr.change_status(case.case_id, CaseStatus.CLOSED_RESOLVED, reason="fixed")
    case = mgr.get(case.case_id)
    assert case.is_closed
    assert case.closed_at is not None


def test_reopen_clears_closed_at():
    mgr = CaseManager()
    case = mgr.open_case("Test")
    mgr.change_status(case.case_id, CaseStatus.CLOSED_RESOLVED)
    mgr.change_status(case.case_id, CaseStatus.IN_PROGRESS, reason="reopened")
    case = mgr.get(case.case_id)
    assert not case.is_closed
    assert case.closed_at is None


def test_evidence_hashing():
    mgr = CaseManager()
    case = mgr.open_case("Test")
    ev = mgr.add_evidence(case.case_id, type=EvidenceType.FILE, label="dump",
                          ref="/tmp/x", added_by="bob", content=b"abc")
    assert ev.sha256 is not None
    assert len(ev.sha256) == 64


def test_custody_tamper_detection():
    mgr = CaseManager()
    case = mgr.open_case("Test")
    mgr.add_note(case.case_id, "bob", "first note")
    mgr.add_note(case.case_id, "bob", "second note")
    case = mgr.get(case.case_id)
    assert case.custody_is_valid()
    # tamper a middle entry
    case.custody[1].detail = "EVIL"
    assert not case.custody_is_valid()


def test_remove_evidence():
    mgr = CaseManager()
    case = mgr.open_case("Test")
    ev = mgr.add_evidence(case.case_id, type=EvidenceType.IOC, label="ip", ref="1.2.3.4")
    assert mgr.remove_evidence(case.case_id, ev.evidence_id)
    case = mgr.get(case.case_id)
    assert len(case.evidence) == 0
    assert case.custody_is_valid()


def test_open_from_incident_dedupes():
    class _Inc:
        incident_id = "INC-9"
        title = "demo"
        severity = type("S", (), {"value": "high"})()
        tags = {"malware"}
        detection_count = 2

    mgr = CaseManager()
    a = mgr.open_from_incident(_Inc())
    b = mgr.open_from_incident(_Inc())
    assert a.case_id == b.case_id
    assert a.priority == CasePriority.P2


def test_store_persistence_round_trip(tmp_path: Path):
    path = tmp_path / "cases.json"
    mgr = CaseManager(CaseStore(path))
    case = mgr.open_case("Persisted", priority=CasePriority.P1)
    mgr.add_note(case.case_id, "alice", "note")
    reloaded = CaseStore(path).get(case.case_id)
    assert reloaded is not None
    assert len(reloaded.notes) == 1
    assert reloaded.custody_is_valid()


def test_store_filters():
    mgr = CaseManager()
    mgr.open_case("a", priority=CasePriority.P1)
    c2 = mgr.open_case("b", priority=CasePriority.P4)
    mgr.change_status(c2.case_id, CaseStatus.CLOSED_RESOLVED)
    open_only = mgr.store.list(open_only=True)
    assert all(not c.is_closed for c in open_only)
    p1 = mgr.store.list(priority=CasePriority.P1)
    assert all(c.priority == CasePriority.P1 for c in p1)


def test_sla_on_track_for_fresh_case():
    mgr = CaseManager()
    case = mgr.open_case("Fresh", priority=CasePriority.P1)
    sla = evaluate_sla(case, SLAPolicy())
    assert sla["response"]["status"] in ("on_track", "met")


def test_sla_breached_for_old_case():
    mgr = CaseManager()
    case = mgr.open_case("Old", priority=CasePriority.P1)
    # backdate creation well beyond the P1 resolve window
    case.created_at = time.time() - 10 * 86400
    sla = evaluate_sla(case, SLAPolicy())
    assert sla["resolution"]["status"] == "breached"
