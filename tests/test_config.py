import json
import os
from pathlib import Path

from threatpipe.utils.config import PipelineConfig, load_config


def test_default_config_engines():
    cfg = PipelineConfig()
    assert "rule" in cfg.detection.engines
    assert cfg.api.port == 8088


def test_from_dict_merges_only_known_fields():
    cfg = PipelineConfig.from_dict({
        "log_level": "DEBUG",
        "api": {"port": 9090, "host": "0.0.0.0"},
        "detection": {"score_threshold": 0.4},
        "garbage_section": {"x": 1},
    })
    assert cfg.log_level == "DEBUG"
    assert cfg.api.port == 9090
    assert cfg.api.host == "0.0.0.0"
    assert cfg.detection.score_threshold == 0.4


def test_load_config_reads_json(tmp_path: Path):
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps({"api": {"port": 12345}}))
    cfg = load_config(cfg_path)
    assert cfg.api.port == 12345


def test_load_config_env_override(monkeypatch):
    monkeypatch.setenv("THREATPIPE_API_PORT", "9876")
    monkeypatch.setenv("THREATPIPE_DETECTION_SCORE_THRESHOLD", "0.81")
    monkeypatch.setenv("THREATPIPE_LOG_LEVEL", "WARNING")
    cfg = load_config()
    assert cfg.api.port == 9876
    assert abs(cfg.detection.score_threshold - 0.81) < 1e-9
    assert cfg.log_level == "WARNING"


def test_load_config_handles_missing_file(tmp_path: Path):
    cfg = load_config(tmp_path / "does_not_exist.json")
    assert cfg.api.port == 8088
