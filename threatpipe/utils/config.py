"""Pipeline configuration.

The CLI and the API both load the same :class:`PipelineConfig`. We use a
plain ``dataclass`` so the config is trivially serializable for the
``/config`` endpoint and easy to override from environment variables in
container deployments.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class IngestionConfig:
    source: str = "file"  # file | syslog | jsonl | stdin
    path: Optional[str] = None
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    follow: bool = True
    batch_size: int = 256
    poll_interval_s: float = 0.25


@dataclass
class DetectionConfig:
    engines: List[str] = field(
        default_factory=lambda: ["rule", "statistical", "isolation_forest"]
    )
    score_threshold: float = 0.65
    ensemble_strategy: str = "weighted_mean"  # weighted_mean | max | majority
    weights: Dict[str, float] = field(
        default_factory=lambda: {
            "rule": 1.0,
            "statistical": 0.8,
            "isolation_forest": 1.0,
            "autoencoder": 1.2,
        }
    )
    rules_path: Optional[str] = None
    isolation_forest_contamination: float = 0.02
    autoencoder_hidden: List[int] = field(default_factory=lambda: [64, 32, 64])


@dataclass
class AlertConfig:
    channels: List[str] = field(default_factory=lambda: ["stdout"])
    min_severity: str = "medium"  # low | medium | high | critical
    webhook_url: Optional[str] = None
    slack_token: Optional[str] = None
    slack_channel: Optional[str] = None
    email_smtp_host: Optional[str] = None
    email_smtp_port: int = 587
    email_from: Optional[str] = None
    email_to: List[str] = field(default_factory=list)
    rate_limit_per_min: int = 60


@dataclass
class ApiConfig:
    host: str = "127.0.0.1"
    port: int = 8088
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    api_key: Optional[str] = None


@dataclass
class PipelineConfig:
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    log_level: str = "INFO"
    log_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "PipelineConfig":
        def _merge(base: Any, override: Dict[str, Any]) -> Any:
            for key, value in override.items():
                if hasattr(base, key):
                    current = getattr(base, key)
                    if hasattr(current, "__dataclass_fields__") and isinstance(value, dict):
                        _merge(current, value)
                    else:
                        setattr(base, key, value)
            return base

        cfg = cls()
        _merge(cfg, raw or {})
        return cfg


def _coerce(value: str) -> Any:
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def load_config(path: Optional[str | os.PathLike[str]] = None) -> PipelineConfig:
    """Load config from JSON, then apply ``THREATPIPE_*`` env overrides.

    Env overrides follow the convention ``THREATPIPE_<SECTION>_<FIELD>``
    in uppercase, e.g. ``THREATPIPE_API_PORT=9090``.
    """
    raw: Dict[str, Any] = {}
    if path:
        p = Path(path)
        if p.exists():
            raw = json.loads(p.read_text())
    cfg = PipelineConfig.from_dict(raw)

    prefix = "THREATPIPE_"
    sections = {
        "INGESTION": cfg.ingestion,
        "DETECTION": cfg.detection,
        "ALERTS": cfg.alerts,
        "API": cfg.api,
    }
    for env_key, env_value in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        rest = env_key[len(prefix):]
        for section_name, section in sections.items():
            if rest.startswith(section_name + "_"):
                field_name = rest[len(section_name) + 1:].lower()
                if hasattr(section, field_name):
                    setattr(section, field_name, _coerce(env_value))
                break
        else:
            top = rest.lower()
            if hasattr(cfg, top):
                setattr(cfg, top, _coerce(env_value))
    return cfg
