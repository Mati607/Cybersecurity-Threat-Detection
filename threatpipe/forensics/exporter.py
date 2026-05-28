"""Bulk exporters for the forensics store.

These cover the three common analyst export shapes: JSONL for piping
into a SIEM / Splunk / Elasticsearch, CSV for ad-hoc spreadsheet
analysis, and a small ZIP bundle that wraps detections, events, and
incidents together for offline review or evidence preservation.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path
from typing import Any, Iterable, List, Optional

from .query import TimeRange
from .store import (
    DetectionRecord,
    EventRecord,
    ForensicsStore,
    IncidentRecord,
)


def _to_dict(record: Any) -> Any:
    if hasattr(record, "to_dict") and callable(record.to_dict):
        return record.to_dict()
    return record


def export_jsonl(records: Iterable[Any], path: str | Path) -> int:
    n = 0
    with Path(path).open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(_to_dict(record), default=str) + "\n")
            n += 1
    return n


def export_csv(records: Iterable[Any], path: str | Path,
               *, columns: Optional[List[str]] = None) -> int:
    rows = [_to_dict(r) for r in records]
    if not rows:
        Path(path).write_text("", encoding="utf-8")
        return 0
    cols = columns or _stable_columns(rows)
    with Path(path).open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            flat = {k: _flatten(row.get(k)) for k in cols}
            writer.writerow(flat)
    return len(rows)


def _stable_columns(rows: List[dict]) -> List[str]:
    seen: List[str] = []
    seen_set: set = set()
    for row in rows:
        for key in row.keys():
            if key in seen_set:
                continue
            if isinstance(row[key], (dict, list)):
                continue
            seen.append(key)
            seen_set.add(key)
    return seen


def _flatten(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return value


def export_zip_bundle(
    store: ForensicsStore,
    path: str | Path,
    *,
    range: Optional[TimeRange] = None,
    include_payload: bool = True,
) -> dict:
    """Write a single .zip with detections.jsonl + events.jsonl + incidents.jsonl + manifest.json."""
    range = range or TimeRange()

    detections: List[DetectionRecord] = list(store.iter_detections(
        since=range.since, until=range.until, limit=1_000_000,
    ))
    events: List[EventRecord] = list(store.iter_events(
        since=range.since, until=range.until, limit=1_000_000,
    ))
    incidents = _all_incidents(store)

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("detections.jsonl", _jsonl_bytes(detections, include_payload))
        zf.writestr("events.jsonl",     _jsonl_bytes(events, include_payload))
        zf.writestr("incidents.jsonl",  _jsonl_bytes(incidents, include_payload))
        manifest = {
            "range": {"since": range.since, "until": range.until},
            "counts": {
                "detections": len(detections),
                "events": len(events),
                "incidents": len(incidents),
            },
            "schema_version": 1,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    return manifest


def _all_incidents(store: ForensicsStore) -> List[IncidentRecord]:
    seen: dict = {}
    # iter_incidents not exposed publicly — use a quick scan
    with store._lock:                                       # type: ignore[attr-defined]
        cur = store._conn.execute("SELECT * FROM incidents ORDER BY snapshot_ts")
        from .store import _incident_from_row
        for row in cur.fetchall():
            rec = _incident_from_row(row)
            seen[(rec.incident_id, rec.id)] = rec
    return list(seen.values())


def _jsonl_bytes(records: Iterable[Any], include_payload: bool) -> bytes:
    buf = io.StringIO()
    for r in records:
        d = _to_dict(r)
        if not include_payload and isinstance(d, dict):
            d.pop("payload", None)
        buf.write(json.dumps(d, default=str))
        buf.write("\n")
    return buf.getvalue().encode("utf-8")
