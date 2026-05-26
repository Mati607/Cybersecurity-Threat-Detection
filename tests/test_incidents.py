from threatpipe.detection import Detection, Severity
from threatpipe.graph import GraphBuilder, GraphCorrelator, ProvenanceGraph
from threatpipe.incidents import (
    Incident,
    IncidentAggregator,
    IncidentStatus,
    IncidentStore,
    KillChainPhase,
    build_timeline,
    infer_phase,
    project_killchain,
)
from threatpipe.ingestion import Event, EventType


def _det(score, tags=(), event=None):
    return Detection(
        event=event or Event(host="h", event_type=EventType.PROCESS, timestamp=1),
        detector="t",
        score=score,
        severity=Severity.from_score(score),
        reasons=["because"],
        tags=list(tags),
    )


# --- kill-chain inference ---

def test_infer_phase_from_mitre_tag():
    assert infer_phase(_det(0.5, tags=["mitre:T1059"])) == KillChainPhase.EXPLOITATION
    assert infer_phase(_det(0.5, tags=["mitre:T1486"])) == KillChainPhase.ACTIONS_ON_OBJECTIVES


def test_infer_phase_from_free_form_tag():
    assert infer_phase(_det(0.5, tags=["persistence"])) == KillChainPhase.INSTALLATION
    assert infer_phase(_det(0.5, tags=["c2"])) == KillChainPhase.COMMAND_AND_CONTROL


def test_infer_phase_falls_back_to_event_type():
    ev = Event(event_type=EventType.NETWORK)
    assert infer_phase(_det(0.5, event=ev)) == KillChainPhase.COMMAND_AND_CONTROL


def test_project_killchain_sorts_by_timestamp():
    a = _det(0.5, event=Event(event_type=EventType.NETWORK, timestamp=10))
    b = _det(0.6, event=Event(event_type=EventType.PROCESS, timestamp=5))
    steps = project_killchain([a, b])
    assert steps[0].timestamp == 5
    assert steps[1].timestamp == 10


# --- timeline ---

def test_timeline_emits_escalation_entries():
    low = _det(0.4)
    high = _det(0.95)
    entries = build_timeline([low, high])
    kinds = [e.kind for e in entries]
    assert "escalation" in kinds


# --- store ---

def test_incident_store_filter_by_status():
    store = IncidentStore()
    a = Incident(incident_id="a", title="x", first_seen=1, last_seen=1, status=IncidentStatus.OPEN)
    b = Incident(incident_id="b", title="y", first_seen=1, last_seen=2, status=IncidentStatus.RESOLVED)
    store.upsert(a)
    store.upsert(b)
    assert {i.incident_id for i in store.list(status=IncidentStatus.OPEN)} == {"a"}
    assert {i.incident_id for i in store.list(status=IncidentStatus.RESOLVED)} == {"b"}


def test_incident_store_filter_by_min_severity():
    store = IncidentStore()
    store.upsert(Incident(incident_id="lo", title="x", first_seen=1, last_seen=1, score=0.1, severity=Severity.LOW))
    store.upsert(Incident(incident_id="hi", title="x", first_seen=1, last_seen=2, score=0.95, severity=Severity.CRITICAL))
    items = store.list(min_severity="high")
    assert {i.incident_id for i in items} == {"hi"}


def test_incident_store_update_status_appends_notes():
    store = IncidentStore()
    store.upsert(Incident(incident_id="a", title="x", first_seen=1, last_seen=1))
    updated = store.update_status("a", IncidentStatus.RESOLVED, note="fixed")
    assert updated.status == IncidentStatus.RESOLVED
    assert "fixed" in updated.notes


def test_incident_store_evicts_resolved_first_on_overflow():
    store = IncidentStore(max_size=2)
    store.upsert(Incident(incident_id="resolved", title="x", first_seen=1, last_seen=1, status=IncidentStatus.RESOLVED))
    store.upsert(Incident(incident_id="open1", title="x", first_seen=1, last_seen=2))
    store.upsert(Incident(incident_id="open2", title="x", first_seen=1, last_seen=3))
    ids = {i.incident_id for i in store.list()}
    assert "resolved" not in ids


# --- aggregator ---

def _correlator_setup():
    g = ProvenanceGraph()
    b = GraphBuilder(g)
    corr = GraphCorrelator(g, radius=2)
    return g, b, corr


def test_aggregator_promotes_on_high_score():
    g, b, corr = _correlator_setup()
    store = IncidentStore()
    agg = IncidentAggregator(store, min_score=0.5, min_severity=Severity.MEDIUM)
    ev = Event(host="h", process="p", event_type=EventType.PROCESS, timestamp=1)
    det = _det(0.95, event=ev)
    group = corr.correlate(det, b.absorb(ev))
    incident = agg.ingest(group, det)
    assert incident is not None
    assert store.get(incident.incident_id) is not None


def test_aggregator_does_not_promote_single_low_score():
    g, b, corr = _correlator_setup()
    store = IncidentStore()
    agg = IncidentAggregator(store, min_score=0.9, min_severity=Severity.HIGH, min_detections_low_score=10)
    ev = Event(host="h", process="p", event_type=EventType.PROCESS, timestamp=1)
    det = _det(0.3, event=ev)
    group = corr.correlate(det, b.absorb(ev))
    assert agg.ingest(group, det) is None
    assert len(store) == 0


def test_aggregator_collects_kill_chain_phases():
    g, b, corr = _correlator_setup()
    store = IncidentStore()
    agg = IncidentAggregator(store, min_score=0.3, min_severity=Severity.LOW)
    events = [
        (Event(host="h", process="bash", pid=10, event_type=EventType.PROCESS, timestamp=1), ["mitre:T1059"]),
        (Event(host="h", process="curl", pid=11, parent_pid=10, dst_ip="1.2.3.4", dst_port=4444,
               event_type=EventType.NETWORK, timestamp=2), ["mitre:T1071"]),
        (Event(host="h", process="bash", pid=10, file_path="x.locked", action="write",
               event_type=EventType.FILE, timestamp=3), ["mitre:T1486"]),
    ]
    last_incident = None
    for ev, tags in events:
        det = _det(0.7, tags=tags, event=ev)
        group = corr.correlate(det, b.absorb(ev))
        last_incident = agg.ingest(group, det)
    assert last_incident is not None
    phases = {p.value for p in last_incident.covered_phases}
    assert {"exploitation", "command_and_control", "actions_on_objectives"} <= phases
