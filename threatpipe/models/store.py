"""Disk persistence for model registry state.

The store serialises the full registry to a JSON file and supports
atomic writes (write-to-temp + rename) so a crash during flush never
leaves a partially-written file.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any, Dict, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import now_epoch
from .metrics import ConfusionMatrix, MetricsSnapshot
from .registry import ModelRegistry, ModelStatus, ModelVersion

_log = get_logger(__name__)


class ModelStore:
    """Persist and restore a :class:`ModelRegistry` from a JSON file."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # save
    # ------------------------------------------------------------------

    def save(self, registry: ModelRegistry) -> None:
        data = _registry_to_dict(registry)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(self.path) or ".")
        try:
            with os.fdopen(tmp_fd, "w") as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp_path, self.path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # load
    # ------------------------------------------------------------------

    def load(self, registry: Optional[ModelRegistry] = None) -> ModelRegistry:
        if registry is None:
            registry = ModelRegistry()
        if not os.path.exists(self.path):
            return registry
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            _dict_to_registry(data, registry)
        except Exception as exc:
            _log.warning("failed to load model store %s: %s", self.path, exc)
        return registry

    def exists(self) -> bool:
        return os.path.exists(self.path)


# ------------------------------------------------------------------
# serialisation helpers
# ------------------------------------------------------------------

def _registry_to_dict(registry: ModelRegistry) -> Dict[str, Any]:
    versions = []
    for mv in registry.all_versions():
        versions.append(_version_to_dict(mv))
    return {
        "saved_at": now_epoch(),
        "versions": versions,
    }


def _version_to_dict(mv: ModelVersion) -> Dict[str, Any]:
    return {
        "model_id": mv.model_id,
        "version": mv.version,
        "detector_type": mv.detector_type,
        "status": mv.status.value,
        "created_at": mv.created_at,
        "promoted_at": mv.promoted_at,
        "retired_at": mv.retired_at,
        "train_samples": mv.train_samples,
        "hyperparams": mv.hyperparams,
        "tags": mv.tags,
        "notes": mv.notes,
        "metrics": [m.to_dict() for m in mv.metrics],
    }


def _dict_to_registry(data: Dict[str, Any], registry: ModelRegistry) -> None:
    for v_data in data.get("versions", []):
        mv = ModelVersion(
            model_id=v_data["model_id"],
            version=v_data["version"],
            detector_type=v_data.get("detector_type", "unknown"),
            status=ModelStatus(v_data.get("status", "shadow")),
            created_at=v_data.get("created_at", now_epoch()),
            promoted_at=v_data.get("promoted_at"),
            retired_at=v_data.get("retired_at"),
            train_samples=v_data.get("train_samples", 0),
            hyperparams=v_data.get("hyperparams", {}),
            tags=v_data.get("tags", []),
            notes=v_data.get("notes", ""),
        )
        for m_data in v_data.get("metrics", []):
            cm_data = m_data.get("confusion", {})
            cm = ConfusionMatrix(
                tp=cm_data.get("tp", 0),
                fp=cm_data.get("fp", 0),
                tn=cm_data.get("tn", 0),
                fn=cm_data.get("fn", 0),
            )
            snap = MetricsSnapshot(
                model_id=mv.model_id,
                version=mv.version,
                timestamp=m_data.get("timestamp", now_epoch()),
                sample_count=m_data.get("sample_count", 0),
                positive_count=m_data.get("positive_count", 0),
                threshold=m_data.get("threshold", 0.5),
                confusion=cm,
                auc_roc=m_data.get("auc_roc", 0.0),
                mean_score=m_data.get("mean_score", 0.0),
                score_std=m_data.get("score_std", 0.0),
                score_p50=m_data.get("score_p50", 0.0),
                score_p95=m_data.get("score_p95", 0.0),
                score_p99=m_data.get("score_p99", 0.0),
                drift_score=m_data.get("drift_score", 0.0),
                notes=m_data.get("notes", ""),
            )
            mv.metrics.append(snap)
        registry._versions.setdefault(mv.model_id, []).append(mv)
