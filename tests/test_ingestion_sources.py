import json
import time
from pathlib import Path

from threatpipe.ingestion import FileTailSource, JSONLSource
from threatpipe.ingestion.base import EventQueue


def test_jsonl_source_drain(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join([
        json.dumps({"event_type": "process", "host": "h1"}),
        json.dumps({"event_type": "network", "host": "h2"}),
        "",
        json.dumps({"event_type": "file", "host": "h3"}),
    ]))
    q = EventQueue()
    src = JSONLSource(q, path=path)
    events = list(src.drain())
    assert [e.host for e in events] == ["h1", "h2", "h3"]


def test_event_queue_get_batch_returns_available_immediately(tmp_path):
    q = EventQueue(maxsize=10)
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join([json.dumps({"event_type": "process", "host": f"h{i}"}) for i in range(3)]))
    src = JSONLSource(q, path=path)
    src.start()
    time.sleep(0.2)
    batch = q.get_batch(max_items=10, timeout=0.5)
    assert len(batch) == 3
    src.stop()


def test_file_tail_reads_appended_lines(tmp_path: Path):
    path = tmp_path / "live.log"
    path.write_text("")  # ensure exists
    q = EventQueue()
    src = FileTailSource(q, path=path, poll_interval=0.05, from_start=True)
    src.start()
    time.sleep(0.1)
    with path.open("a") as fh:
        fh.write(json.dumps({"event_type": "process", "host": "added"}) + "\n")
        fh.write(json.dumps({"event_type": "process", "host": "added2"}) + "\n")
    time.sleep(0.4)
    src.stop()
    batch = q.get_batch(max_items=10, timeout=0.1)
    hosts = {ev.host for ev in batch}
    assert "added" in hosts
    assert "added2" in hosts
