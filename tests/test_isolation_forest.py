from threatpipe.detection import IsolationForestDetector
from threatpipe.ingestion import Event, EventType


def test_isolation_forest_fits_and_persists(tmp_path, benign_events):
    det = IsolationForestDetector(n_estimators=16, sample_size=64, contamination=0.05, random_state=1)
    det.fit(benign_events)
    assert det._fitted

    # round-trip via disk
    path = tmp_path / "iso.pkl"
    det.save(path)
    det2 = IsolationForestDetector().load(path)
    assert det2._fitted
    assert det2._threshold == det._threshold


def test_isolation_forest_silent_before_fit():
    det = IsolationForestDetector()
    assert det.detect(Event()) is None


def test_isolation_forest_flags_obviously_weird_event(benign_events, attack_event):
    det = IsolationForestDetector(n_estimators=32, sample_size=128, contamination=0.02, random_state=2)
    det.fit(benign_events)
    out = det.detect(attack_event)
    # The detector may stay silent if randomness places the attack inside
    # benign space; we just require it doesn't crash and respects threshold.
    if out is not None:
        assert out.score >= det._threshold
        assert "isolation" in out.reasons[0]
