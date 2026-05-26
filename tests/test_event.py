import json

from threatpipe.ingestion import Event, EventType


def test_event_to_dict_includes_iso_timestamp():
    ev = Event(timestamp=1_700_000_000.0, event_type=EventType.PROCESS, host="h0")
    d = ev.to_dict()
    assert d["event_type"] == "process"
    assert d["timestamp_iso"].startswith("2023-11-")


def test_event_round_trip_through_dict():
    ev = Event(event_type=EventType.NETWORK, dst_ip="1.2.3.4", dst_port=4444)
    raw = ev.to_dict()
    ev2 = Event.from_dict(raw)
    assert ev2.event_type == EventType.NETWORK
    assert ev2.dst_ip == "1.2.3.4"
    assert ev2.dst_port == 4444


def test_event_from_dict_with_unknown_type_falls_back():
    ev = Event.from_dict({"event_type": "not-a-real-type"})
    assert ev.event_type == EventType.UNKNOWN


def test_event_to_json_is_valid_json():
    ev = Event(event_type=EventType.PROCESS, host="x", message="hi")
    parsed = json.loads(ev.to_json())
    assert parsed["host"] == "x"
    assert parsed["message"] == "hi"


def test_event_id_is_unique():
    seen = {Event().event_id for _ in range(50)}
    assert len(seen) == 50
