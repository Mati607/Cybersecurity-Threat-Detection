"""Tests for concept drift detection: CUSUM, PSI, KS, AutoTrainer."""

import time

import pytest

from threatpipe.models.drift import (
    DriftDetector,
    DriftSeverity,
    _cusum,
    _histogram,
    _ks_statistic,
    _psi,
)
from threatpipe.models.metrics import MetricsTracker
from threatpipe.models.trainer import AutoTrainer, TrainReason


# ------------------------------------------------------------------
# DriftSeverity
# ------------------------------------------------------------------

def test_severity_from_score():
    assert DriftSeverity.from_score(0.0) == DriftSeverity.NONE
    assert DriftSeverity.from_score(0.05) == DriftSeverity.NONE
    assert DriftSeverity.from_score(0.15) == DriftSeverity.LOW
    assert DriftSeverity.from_score(0.35) == DriftSeverity.MEDIUM
    assert DriftSeverity.from_score(0.6) == DriftSeverity.HIGH
    assert DriftSeverity.from_score(0.9) == DriftSeverity.CRITICAL


# ------------------------------------------------------------------
# algorithm helpers
# ------------------------------------------------------------------

def test_cusum_stable_returns_low():
    scores = [0.5 + 0.01 * (i % 3) for i in range(50)]
    ref_mean = sum(scores) / len(scores)
    result = _cusum(scores, ref_mean, ref_std=0.1)
    assert result < 1.0


def test_cusum_shifted_returns_high():
    ref_scores = [0.1] * 50
    shifted_scores = [0.9] * 50
    ref_mean = 0.1
    ref_std = 0.05
    result = _cusum(shifted_scores, ref_mean, ref_std)
    assert result > 5.0


def test_histogram_bins():
    scores = [float(i) / 100 for i in range(100)]
    edges, freqs = _histogram(scores, n_bins=10)
    assert len(edges) == 11
    assert len(freqs) == 10
    assert abs(sum(freqs) - 1.0) < 0.01


def test_histogram_single_value():
    edges, freqs = _histogram([0.5], n_bins=5)
    assert len(freqs) == 5


def test_psi_identical_distributions():
    scores = [float(i) / 100 for i in range(100)]
    edges, hist = _histogram(scores, n_bins=10)
    psi = _psi(hist, edges, scores, 10)
    assert psi < 0.05


def test_psi_shifted_distribution():
    ref_scores = [0.1] * 100
    cur_scores = [0.9] * 100
    _, ref_hist = _histogram(ref_scores, n_bins=10)
    edges, _ = _histogram(ref_scores, n_bins=10)
    psi = _psi(ref_hist, edges, cur_scores, 10)
    assert psi > 0.5


def test_ks_identical():
    scores = [float(i) / 100 for i in range(100)]
    ks = _ks_statistic(scores, scores)
    assert ks == pytest.approx(0.0)


def test_ks_different():
    ref = [0.1] * 50
    cur = [0.9] * 50
    ks = _ks_statistic(ref, cur)
    assert ks > 0.8


def test_ks_empty():
    assert _ks_statistic([], [0.5]) == 0.0
    assert _ks_statistic([0.5], []) == 0.0


# ------------------------------------------------------------------
# DriftDetector
# ------------------------------------------------------------------

def test_detector_no_reference():
    d = DriftDetector()
    alert = d.evaluate("iforest", 1, [0.5, 0.6, 0.7])
    assert alert.composite_score == 0.0
    assert not alert.triggered


def test_detector_stable_no_drift():
    import random
    rng = random.Random(0)
    ref = [0.5 + rng.gauss(0, 0.05) for _ in range(200)]
    cur = [0.5 + rng.gauss(0, 0.05) for _ in range(100)]
    d = DriftDetector(cusum_threshold=10.0, psi_threshold=2.0, ks_threshold=0.8)
    d.set_reference(ref)
    alert = d.evaluate("m", 1, cur)
    assert not alert.triggered


def test_detector_drift_triggers():
    ref = [0.1 + 0.01 * (i % 5) for i in range(500)]
    cur = [0.9 + 0.01 * (i % 3) for i in range(200)]
    d = DriftDetector(cusum_threshold=1.0, psi_threshold=0.1, ks_threshold=0.2)
    d.set_reference(ref)
    alert = d.evaluate("m", 1, cur)
    assert alert.triggered
    assert alert.severity in (DriftSeverity.HIGH, DriftSeverity.CRITICAL)
    assert alert.current_mean > alert.reference_mean


def test_detector_alert_has_description_on_trigger():
    ref = [0.1] * 300
    cur = [0.95] * 200
    d = DriftDetector()
    d.set_reference(ref)
    alert = d.evaluate("m", 1, cur)
    if alert.triggered:
        assert "Drift detected" in alert.description


def test_detector_to_dict_structure():
    d = DriftDetector()
    d.set_reference([0.5] * 100)
    alert = d.evaluate("m", 1, [0.5] * 50)
    data = alert.to_dict()
    assert "composite_score" in data
    assert "severity" in data
    assert "ks_score" in data
    assert "psi_score" in data
    assert "timestamp_iso" in data


def test_detector_has_reference():
    d = DriftDetector()
    assert not d.has_reference()
    d.set_reference([0.5] * 10)
    assert d.has_reference()


# ------------------------------------------------------------------
# AutoTrainer
# ------------------------------------------------------------------

def test_autotrainer_manual_trigger():
    tracker = MetricsTracker("m", 1)
    for i in range(200):
        tracker.record(0.5 + 0.1 * (i % 3))
    detector = DriftDetector()
    detector.set_reference(tracker.score_buffer())

    called = []

    def retrain(model_id, reason, old_ver):
        called.append((model_id, reason))
        return old_ver + 1

    trainer = AutoTrainer(
        "m", tracker, detector,
        retrain_fn=retrain,
        check_interval_s=3600,
        min_samples=10,
    )
    event = trainer.trigger()
    assert event.success
    assert event.reason == TrainReason.MANUAL
    assert len(called) == 1
    assert trainer._current_version == 2


def test_autotrainer_history_accumulates():
    tracker = MetricsTracker("m", 1)
    detector = DriftDetector()
    trainer = AutoTrainer("m", tracker, detector, min_samples=5)
    trainer.trigger()
    trainer.trigger()
    assert len(trainer.history()) == 2


def test_autotrainer_history_limit():
    tracker = MetricsTracker("m", 1)
    detector = DriftDetector()
    trainer = AutoTrainer("m", tracker, detector, min_samples=5, history_limit=3)
    for _ in range(5):
        trainer.trigger()
    assert len(trainer.history()) == 3


def test_autotrainer_check_drift_no_reference():
    tracker = MetricsTracker("m", 1)
    for i in range(200):
        tracker.record(0.5)
    detector = DriftDetector()
    trainer = AutoTrainer("m", tracker, detector, min_samples=10)
    result = trainer.check_drift()
    assert result is None   # no reference set


def test_autotrainer_check_drift_with_reference():
    tracker = MetricsTracker("m", 1)
    for i in range(200):
        tracker.record(0.5)
    detector = DriftDetector()
    detector.set_reference([0.5] * 200)
    trainer = AutoTrainer("m", tracker, detector, min_samples=10)
    alert = trainer.check_drift()
    assert alert is not None
    assert not alert.triggered    # stable distribution


def test_autotrainer_status_structure():
    tracker = MetricsTracker("m", 1)
    detector = DriftDetector()
    trainer = AutoTrainer("m", tracker, detector)
    s = trainer.status()
    assert "model_id" in s
    assert "current_version" in s
    assert "samples_collected" in s


def test_autotrainer_start_stop():
    tracker = MetricsTracker("m", 1)
    detector = DriftDetector()
    trainer = AutoTrainer("m", tracker, detector, check_interval_s=60)
    trainer.start()
    assert trainer._running
    trainer.stop(timeout=1.0)
    assert not trainer._running


def test_autotrainer_failed_retrain_recorded():
    tracker = MetricsTracker("m", 1)
    detector = DriftDetector()

    def bad_retrain(model_id, reason, old_ver):
        raise RuntimeError("training data corrupt")

    trainer = AutoTrainer("m", tracker, detector, retrain_fn=bad_retrain)
    event = trainer.trigger()
    assert not event.success
    assert "corrupt" in event.error
