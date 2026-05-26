from threatpipe.detection import Detection, Severity
from threatpipe.graph import (
    GraphBuilder,
    GraphCorrelator,
    ProvenanceGraph,
)
from threatpipe.ingestion import Event, EventType


def _make_detection(score: float = 0.8, event: Event = None, tag: str = "execution") -> Detection:
    return Detection(
        event=event or Event(host="h", process="p", pid=1, event_type=EventType.PROCESS),
        detector="t",
        score=score,
        severity=Severity.from_score(score),
        reasons=["because"],
        tags=[tag],
    )


def test_correlator_creates_new_group_on_first_detection():
    g = ProvenanceGraph()
    b = GraphBuilder(g)
    ev = Event(host="h", process="curl", pid=11, event_type=EventType.PROCESS, timestamp=1)
    touched = b.absorb(ev)
    corr = GraphCorrelator(g)
    group = corr.correlate(_make_detection(event=ev), touched)
    assert group.group_id.startswith("G-")
    assert len(group.detections) == 1


def test_correlator_merges_related_detections():
    g = ProvenanceGraph()
    b = GraphBuilder(g)
    ev1 = Event(host="h", process="bash", pid=10, event_type=EventType.PROCESS, timestamp=1)
    ev2 = Event(host="h", process="curl", pid=11, parent_pid=10,
                event_type=EventType.PROCESS, timestamp=2)
    t1 = b.absorb(ev1)
    t2 = b.absorb(ev2)
    corr = GraphCorrelator(g, radius=2)
    g1 = corr.correlate(_make_detection(event=ev1), t1)
    g2 = corr.correlate(_make_detection(event=ev2), t2)
    assert g1.group_id == g2.group_id
    assert len(g2.detections) == 2


def test_correlator_boosts_score_for_repeat_hits():
    g = ProvenanceGraph()
    b = GraphBuilder(g)
    ev = Event(host="h", process="x", pid=1, event_type=EventType.PROCESS)
    touched = b.absorb(ev)
    corr = GraphCorrelator(g, score_boost=0.2)
    g1 = corr.correlate(_make_detection(score=0.5, event=ev), touched)
    base_score = g1.score
    g2 = corr.correlate(_make_detection(score=0.5, event=Event(host="h", process="x", pid=1, event_type=EventType.PROCESS)), touched)
    assert g2.score >= base_score


def test_correlator_expires_window():
    g = ProvenanceGraph()
    b = GraphBuilder(g)
    ev1 = Event(host="h", process="p1", pid=1, event_type=EventType.PROCESS, timestamp=0)
    ev2 = Event(host="h2", process="p2", pid=2, event_type=EventType.PROCESS, timestamp=10_000)
    corr = GraphCorrelator(g, window_seconds=1.0)
    corr.correlate(_make_detection(event=ev1), b.absorb(ev1))
    # ev2 timestamp is far in the future relative to window: ev1's group should expire
    corr.correlate(_make_detection(event=ev2), b.absorb(ev2))
    active = corr.active_groups()
    assert len(active) == 1
    assert active[0].first_seen == ev2.timestamp
