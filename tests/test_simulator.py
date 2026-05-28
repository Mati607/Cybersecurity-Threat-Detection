import pytest

from threatpipe.detection import DetectionPipeline
from threatpipe.simulator import (
    SimulationEngine,
    benign_background,
    evaluate_detection_coverage,
    get_scenario,
    list_scenarios,
)
from threatpipe.utils.config import PipelineConfig


def _pipeline():
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    return DetectionPipeline(cfg)


def test_scenario_library_populated():
    scenarios = list_scenarios()
    ids = {s.scenario_id for s in scenarios}
    assert {"ransomware", "c2_beacon", "credential_dumping",
            "lateral_movement", "data_exfiltration"} <= ids


def test_get_scenario_unknown_raises():
    with pytest.raises(KeyError):
        get_scenario("does-not-exist")


def test_scenario_techniques_listed():
    rw = get_scenario("ransomware")
    assert "T1486" in rw.techniques
    assert rw.to_dict()["step_count"] == len(rw.steps)


def test_generate_events_is_deterministic():
    eng = SimulationEngine()
    rw = get_scenario("ransomware")
    a = eng.generate_events(rw, base_ts=1_700_000_000)
    b = eng.generate_events(rw, base_ts=1_700_000_000)
    assert len(a) == len(b)
    assert [e.event_type for e in a] == [e.event_type for e in b]


def test_run_scenario_produces_detections():
    eng = SimulationEngine(_pipeline())
    rw = get_scenario("ransomware")
    result = eng.run(rw)
    assert result.events_emitted > 0
    assert len(result.step_results) == len(rw.steps)
    # ransomware encryption step must be detected
    encrypt = next(s for s in result.step_results if s.step_id == "rw-5")
    assert encrypt.detected


def test_coverage_report_grades():
    eng = SimulationEngine(_pipeline())
    rw = get_scenario("ransomware")
    result = eng.run(rw)
    report = evaluate_detection_coverage(rw, result)
    assert 0.0 <= report.coverage_fraction <= 1.0
    assert report.grade in ("A", "B", "C", "D", "F")
    assert report.expected_steps >= 1


def test_coverage_technique_map():
    eng = SimulationEngine(_pipeline())
    sc = get_scenario("credential_dumping")
    result = eng.run(sc)
    report = evaluate_detection_coverage(sc, result)
    assert "T1003" in report.technique_coverage


def test_benign_background_is_low_noise():
    pipeline = _pipeline()
    events = benign_background(count=50, seed=1)
    detections = pipeline.run_once(events)
    # benign traffic should produce few/no detections
    assert len(detections) <= 2


def test_engine_requires_pipeline_to_run():
    eng = SimulationEngine(None)
    with pytest.raises(RuntimeError):
        eng.run(get_scenario("ransomware"))
