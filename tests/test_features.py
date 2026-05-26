from threatpipe.detection import FeatureExtractor
from threatpipe.ingestion import Event, EventType


def test_feature_vector_has_expected_dimension():
    fx = FeatureExtractor()
    fx.fit([Event(event_type=EventType.PROCESS, pid=1)])
    vec = fx.transform(Event(event_type=EventType.PROCESS, pid=1))
    assert len(vec) == fx.dim


def test_feature_vector_changes_with_input():
    fx = FeatureExtractor()
    fx.fit([Event(event_type=EventType.PROCESS), Event(event_type=EventType.NETWORK)])
    a = fx.transform(Event(event_type=EventType.PROCESS, process="curl"))
    b = fx.transform(Event(event_type=EventType.PROCESS, process="wget"))
    assert a != b


def test_text_field_normalized():
    fx = FeatureExtractor()
    fx.fit([Event()])
    vec = fx.transform(Event(command_line="alpha beta gamma"))
    text_dim = fx.n_text_buckets
    text_section = vec[-text_dim:]
    norm_sq = sum(v * v for v in text_section)
    assert abs(norm_sq - 1.0) < 1e-6 or norm_sq == 0.0
