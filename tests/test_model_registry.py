"""Tests for the ML model registry and metrics tracking."""

import pytest

from threatpipe.models.metrics import (
    ConfusionMatrix,
    MetricsTracker,
    _percentile,
    _trapezoidal_auc,
)
from threatpipe.models.registry import ModelRegistry, ModelStatus, ModelVersion
from threatpipe.models.store import ModelStore


# ------------------------------------------------------------------
# ModelRegistry
# ------------------------------------------------------------------

def test_register_first_version():
    reg = ModelRegistry()
    mv = reg.register("iforest", "isolation_forest", train_samples=500)
    assert mv.version == 1
    assert mv.model_id == "iforest"
    assert mv.status == ModelStatus.SHADOW
    assert mv.train_samples == 500


def test_register_increments_version():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    mv2 = reg.register("iforest", "isolation_forest")
    assert mv2.version == 2


def test_register_separate_models_independent():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    mv = reg.register("ae", "autoencoder")
    assert mv.version == 1


def test_promote_to_production():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    mv = reg.promote("iforest", 1, to=ModelStatus.PRODUCTION)
    assert mv.status == ModelStatus.PRODUCTION
    assert mv.promoted_at is not None


def test_promote_retires_previous_production():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    reg.promote("iforest", 1, to=ModelStatus.PRODUCTION)
    reg.register("iforest", "isolation_forest")
    reg.promote("iforest", 2, to=ModelStatus.PRODUCTION)
    v1 = reg.get_version("iforest", 1)
    assert v1.status == ModelStatus.RETIRED


def test_retire_model():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    mv = reg.retire("iforest", 1)
    assert mv.status == ModelStatus.RETIRED
    assert mv.retired_at is not None


def test_production_version_returns_live():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    assert reg.production_version("iforest") is None
    reg.promote("iforest", 1, to=ModelStatus.PRODUCTION)
    assert reg.production_version("iforest").version == 1


def test_list_versions():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    reg.register("iforest", "isolation_forest")
    versions = reg.list_versions("iforest")
    assert len(versions) == 2
    assert versions[0].version == 1


def test_list_models():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    reg.register("ae", "autoencoder")
    models = reg.list_models()
    assert "iforest" in models
    assert "ae" in models


def test_record_metrics():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    tracker = MetricsTracker("iforest", 1)
    for i in range(100):
        tracker.record(0.8 if i % 10 == 0 else 0.2, label=1.0 if i % 10 == 0 else 0.0)
    snap = tracker.snapshot(threshold=0.5)
    ok = reg.record_metrics("iforest", 1, snap)
    assert ok is True
    mv = reg.get_version("iforest", 1)
    assert mv.latest_metrics is not None
    assert mv.latest_metrics.sample_count == 100


def test_summary_structure():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    reg.promote("iforest", 1, to=ModelStatus.PRODUCTION)
    s = reg.summary()
    assert s["model_count"] == 1
    assert s["models"]["iforest"]["production_version"] == 1


def test_hook_is_called():
    events = []
    reg = ModelRegistry()
    reg.add_hook(lambda ev, mv: events.append((ev, mv.model_id)))
    reg.register("iforest", "isolation_forest")
    reg.promote("iforest", 1, to=ModelStatus.PRODUCTION)
    assert ("registered", "iforest") in events
    assert ("promoted", "iforest") in events


def test_promote_nonexistent_returns_none():
    reg = ModelRegistry()
    result = reg.promote("ghost", 99, to=ModelStatus.PRODUCTION)
    assert result is None


def test_all_versions():
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest")
    reg.register("ae", "autoencoder")
    reg.register("iforest", "isolation_forest")
    assert len(reg.all_versions()) == 3


# ------------------------------------------------------------------
# MetricsTracker
# ------------------------------------------------------------------

def test_tracker_empty_snapshot():
    t = MetricsTracker("m", 1)
    snap = t.snapshot()
    assert snap.sample_count == 0
    assert snap.auc_roc == 0.0


def test_tracker_records_scores():
    t = MetricsTracker("m", 1)
    t.record(0.9, label=1.0)
    t.record(0.1, label=0.0)
    assert len(t) == 2
    snap = t.snapshot(threshold=0.5)
    assert snap.sample_count == 2
    assert snap.confusion.tp == 1
    assert snap.confusion.tn == 1


def test_tracker_window_evicts_old():
    t = MetricsTracker("m", 1, window=5)
    for i in range(10):
        t.record(float(i) / 10)
    assert len(t) == 5


def test_tracker_batch():
    t = MetricsTracker("m", 1)
    t.record_batch([(0.9, 1.0), (0.1, 0.0), (0.8, 1.0)])
    assert len(t) == 3


def test_confusion_matrix_metrics():
    cm = ConfusionMatrix(tp=80, fp=10, tn=90, fn=20)
    assert cm.precision == pytest.approx(80 / 90, rel=1e-3)
    assert cm.recall == pytest.approx(80 / 100, rel=1e-3)
    assert cm.f1 > 0
    assert cm.accuracy > 0
    assert cm.fpr == pytest.approx(10 / 100, rel=1e-3)


def test_auc_roc_perfect():
    # perfect classifier: high score -> positive
    labeled = [(0.9, 1.0), (0.8, 1.0), (0.2, 0.0), (0.1, 0.0)]
    auc = _trapezoidal_auc(labeled)
    assert auc > 0.9


def test_auc_roc_random():
    import random
    random.seed(42)
    labeled = [(random.random(), round(random.random())) for _ in range(200)]
    auc = _trapezoidal_auc(labeled)
    assert 0.3 < auc < 0.7   # near-random


def test_percentile():
    vals = sorted(range(100))
    assert _percentile(vals, 50) == pytest.approx(49.5, rel=0.01)
    assert _percentile(vals, 95) == pytest.approx(94.05, rel=0.01)
    assert _percentile([], 50) == 0.0


# ------------------------------------------------------------------
# ModelStore
# ------------------------------------------------------------------

def test_store_save_and_load(tmp_path):
    path = str(tmp_path / "registry.json")
    store = ModelStore(path)
    reg = ModelRegistry()
    reg.register("iforest", "isolation_forest", train_samples=100)
    reg.promote("iforest", 1, to=ModelStatus.PRODUCTION)
    store.save(reg)

    reg2 = ModelRegistry()
    store.load(reg2)
    assert "iforest" in reg2.list_models()
    mv = reg2.get_version("iforest", 1)
    assert mv.status == ModelStatus.PRODUCTION
    assert mv.train_samples == 100


def test_store_load_nonexistent(tmp_path):
    path = str(tmp_path / "nope.json")
    store = ModelStore(path)
    reg = store.load()
    assert isinstance(reg, ModelRegistry)
    assert reg.list_models() == []


def test_store_exists(tmp_path):
    path = str(tmp_path / "reg.json")
    store = ModelStore(path)
    assert not store.exists()
    store.save(ModelRegistry())
    assert store.exists()
