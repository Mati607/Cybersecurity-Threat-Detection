from threatpipe.detection import DetectionPipeline
from threatpipe.utils.config import PipelineConfig
from threatpipe.ingestion import Event, EventType


def _cfg() -> PipelineConfig:
    cfg = PipelineConfig()
    cfg.detection.engines = ["rule"]
    cfg.detection.score_threshold = 0.5
    return cfg


def test_pipeline_records_severity(attack_event, ransomware_event):
    pipe = DetectionPipeline(_cfg())
    detections = pipe.run_once([attack_event, ransomware_event])
    assert len(detections) == 2
    sevs = {d.severity.value for d in detections}
    assert sevs <= {"high", "critical"}
    assert "critical" in sevs


def test_pipeline_status_reports_counters(attack_event):
    pipe = DetectionPipeline(_cfg())
    pipe.run_once([attack_event])
    status = pipe.status()
    assert status["events_in"] == 1
    assert status["detections_out"] == 1
    assert status["by_severity"]["high"] + status["by_severity"]["critical"] >= 1


def test_pipeline_recent_buffer_bounded():
    cfg = _cfg()
    pipe = DetectionPipeline(cfg)
    pipe._recent_limit = 5
    big_attack = Event(event_type=EventType.FILE, file_path="x.locked", action="write")
    pipe.run_once([big_attack] * 20)
    assert len(pipe.recent(limit=100)) == 5


def test_alert_sink_called(attack_event):
    received = []

    def sink(d):
        received.append(d.severity.value)

    pipe = DetectionPipeline(_cfg(), alert_sink=sink)
    pipe.run_once([attack_event])
    assert len(received) == 1
    assert received[0] in ("high", "critical")


def test_pipeline_filters_below_threshold():
    cfg = _cfg()
    cfg.detection.score_threshold = 0.99
    pipe = DetectionPipeline(cfg)
    # The encoded-payload rule is score 0.85; below 0.99 it should be filtered.
    ev = Event(event_type=EventType.PROCESS, command_line="powershell -enc " + "A" * 64)
    assert pipe.run_once([ev]) == []
