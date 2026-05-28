"""Model registry: version control for ML detectors.

Every time a detector is trained or loaded from disk a new ``ModelVersion``
is registered here.  The registry tracks metadata, metrics snapshots, and
promotion state (shadow → staging → production → retired) so operators can
roll back, compare performance, and audit the full lifecycle of every model
that has ever been active in the pipeline.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import format_iso, now_epoch
from .metrics import MetricsSnapshot

_log = get_logger(__name__)


class ModelStatus(str, Enum):
    SHADOW = "shadow"          # training / warm-up, not scoring live events
    STAGING = "staging"        # scoring but not alerting
    PRODUCTION = "production"  # fully live
    RETIRED = "retired"        # superseded or drifted out


@dataclass
class ModelVersion:
    model_id: str
    version: int
    detector_type: str              # e.g. "isolation_forest", "autoencoder"
    status: ModelStatus = ModelStatus.SHADOW
    created_at: float = field(default_factory=now_epoch)
    promoted_at: Optional[float] = None
    retired_at: Optional[float] = None
    train_samples: int = 0
    hyperparams: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metrics: List[MetricsSnapshot] = field(default_factory=list)
    notes: str = ""

    # latest snapshot shortcut
    @property
    def latest_metrics(self) -> Optional[MetricsSnapshot]:
        return self.metrics[-1] if self.metrics else None

    @property
    def is_live(self) -> bool:
        return self.status in (ModelStatus.STAGING, ModelStatus.PRODUCTION)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "version": self.version,
            "detector_type": self.detector_type,
            "status": self.status.value,
            "created_at": self.created_at,
            "created_iso": format_iso(self.created_at),
            "promoted_at": self.promoted_at,
            "retired_at": self.retired_at,
            "train_samples": self.train_samples,
            "hyperparams": dict(self.hyperparams),
            "tags": list(self.tags),
            "latest_metrics": self.latest_metrics.to_dict() if self.latest_metrics else None,
            "metrics_history": [m.to_dict() for m in self.metrics],
            "notes": self.notes,
        }


class ModelRegistry:
    """Central registry for all model versions in the pipeline.

    Thread-safe; all mutations go through this class so the audit trail
    stays consistent.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # model_id -> sorted list of ModelVersion (ascending version)
        self._versions: Dict[str, List[ModelVersion]] = {}
        self._hooks: List[Any] = []   # callables(event_name, version)

    # ------------------------------------------------------------------
    # registration
    # ------------------------------------------------------------------

    def register(
        self,
        model_id: str,
        detector_type: str,
        *,
        train_samples: int = 0,
        hyperparams: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        notes: str = "",
        status: ModelStatus = ModelStatus.SHADOW,
    ) -> ModelVersion:
        with self._lock:
            existing = self._versions.get(model_id, [])
            version_num = (existing[-1].version + 1) if existing else 1
            mv = ModelVersion(
                model_id=model_id,
                version=version_num,
                detector_type=detector_type,
                status=status,
                train_samples=train_samples,
                hyperparams=dict(hyperparams or {}),
                tags=list(tags or []),
                notes=notes,
            )
            self._versions.setdefault(model_id, []).append(mv)
            _log.info("registered %s v%d (%s)", model_id, version_num, detector_type)
            self._fire("registered", mv)
            return mv

    # ------------------------------------------------------------------
    # promotion / retirement
    # ------------------------------------------------------------------

    def promote(self, model_id: str, version: int, *, to: ModelStatus) -> Optional[ModelVersion]:
        with self._lock:
            mv = self._get(model_id, version)
            if mv is None:
                return None
            if to == ModelStatus.PRODUCTION:
                # retire current production
                cur = self.production_version(model_id)
                if cur is not None and cur.version != version:
                    cur.status = ModelStatus.RETIRED
                    cur.retired_at = now_epoch()
                    _log.info("retired %s v%d", model_id, cur.version)
                    self._fire("retired", cur)
            mv.status = to
            mv.promoted_at = now_epoch()
            _log.info("promoted %s v%d → %s", model_id, version, to.value)
            self._fire("promoted", mv)
            return mv

    def retire(self, model_id: str, version: int) -> Optional[ModelVersion]:
        return self.promote(model_id, version, to=ModelStatus.RETIRED)

    # ------------------------------------------------------------------
    # metrics recording
    # ------------------------------------------------------------------

    def record_metrics(self, model_id: str, version: int, snapshot: MetricsSnapshot) -> bool:
        with self._lock:
            mv = self._get(model_id, version)
            if mv is None:
                return False
            mv.metrics.append(snapshot)
            self._fire("metrics_recorded", mv)
            return True

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------

    def production_version(self, model_id: str) -> Optional[ModelVersion]:
        with self._lock:
            for mv in reversed(self._versions.get(model_id, [])):
                if mv.status == ModelStatus.PRODUCTION:
                    return mv
            return None

    def latest_version(self, model_id: str) -> Optional[ModelVersion]:
        with self._lock:
            versions = self._versions.get(model_id, [])
            return versions[-1] if versions else None

    def list_versions(self, model_id: str) -> List[ModelVersion]:
        with self._lock:
            return list(self._versions.get(model_id, []))

    def list_models(self) -> List[str]:
        with self._lock:
            return list(self._versions.keys())

    def all_versions(self) -> List[ModelVersion]:
        with self._lock:
            result = []
            for versions in self._versions.values():
                result.extend(versions)
            return result

    def get_version(self, model_id: str, version: int) -> Optional[ModelVersion]:
        with self._lock:
            return self._get(model_id, version)

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            models: Dict[str, Any] = {}
            for mid, versions in self._versions.items():
                prod = next((v for v in reversed(versions) if v.status == ModelStatus.PRODUCTION), None)
                models[mid] = {
                    "total_versions": len(versions),
                    "production_version": prod.version if prod else None,
                    "production_metrics": prod.latest_metrics.to_dict() if (prod and prod.latest_metrics) else None,
                    "latest_version": versions[-1].version if versions else None,
                    "latest_status": versions[-1].status.value if versions else None,
                }
            return {
                "model_count": len(self._versions),
                "total_versions": sum(len(v) for v in self._versions.values()),
                "models": models,
            }

    # ------------------------------------------------------------------
    # hooks
    # ------------------------------------------------------------------

    def add_hook(self, fn: Any) -> None:
        self._hooks.append(fn)

    def _fire(self, event: str, version: ModelVersion) -> None:
        for fn in self._hooks:
            try:
                fn(event, version)
            except Exception as exc:  # pragma: no cover
                _log.warning("registry hook error: %s", exc)

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _get(self, model_id: str, version: int) -> Optional[ModelVersion]:
        for mv in self._versions.get(model_id, []):
            if mv.version == version:
                return mv
        return None
