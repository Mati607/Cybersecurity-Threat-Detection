from threatpipe.detection import StatisticalDetector
from threatpipe.ingestion import Event, EventType


def _benign_stream(n=400):
    base = 1_700_000_000
    for i in range(n):
        yield Event(
            timestamp=base + (i // 5) * 60,        # ~5 events per minute
            event_type=EventType.NETWORK,
            host="h0",
            dst_port=443,
            bytes_sent=1000,
        )


def test_statistical_warmup_no_detections():
    det = StatisticalDetector(warmup_events=10_000)
    for ev in _benign_stream(50):
        assert det.detect(ev) is None


def test_statistical_flags_sudden_burst():
    det = StatisticalDetector(z_threshold=2.5, warmup_events=50)
    for ev in _benign_stream(200):
        det.detect(ev)
    # Now spike the rate within a single minute.
    spike_minute = 1_700_000_000 + 200 * 60
    flagged = None
    for i in range(200):
        ev = Event(
            timestamp=spike_minute + 1,
            event_type=EventType.NETWORK,
            host="h0",
            dst_port=4444 + (i % 50),               # also bumps unique ports
            bytes_sent=1_000_000,
        )
        flagged = det.detect(ev) or flagged
    assert flagged is not None
    assert flagged.score > 0
    assert flagged.tags == ["anomaly", "statistical"]


def test_statistical_snapshot_records_state():
    det = StatisticalDetector(warmup_events=10)
    for ev in _benign_stream(60):
        det.detect(ev)
    snap = det.snapshot()
    assert "h0" in snap
    assert snap["h0"]["buckets_observed"] >= 1
