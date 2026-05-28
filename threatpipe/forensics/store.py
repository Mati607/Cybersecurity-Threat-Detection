"""SQLite-backed forensics store.

The pipeline's in-memory ring buffer is great for "what happened in the
last hour" but it loses everything on restart and can't answer "show
me every detection on host web1 in March". The forensics store closes
that gap with a small SQLite schema:

* ``events``      — every normalized event (source field, timestamps,
  full JSON blob)
* ``detections``  — every detection with severity, score, detector,
  reasons (JSON)
* ``incidents``   — every incident snapshot (status transitions land
  here in append-only form, see :class:`IncidentRecord`)

SQLite is intentionally the lowest-common-denominator backend — it's
in the stdlib, single-file, queryable by analysts with sqlite3 CLI,
and survives restarts. Real deployments can swap the backend by
replacing :class:`ForensicsStore` with anything that satisfies the
public methods used by :mod:`threatpipe.forensics.sink`.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..detection.base import Detection, Severity
from ..ingestion.event import Event
from ..utils.logging_setup import get_logger
from ..utils.timeutil import format_iso, now_epoch

_log = get_logger(__name__)


_SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL UNIQUE,
    timestamp       REAL    NOT NULL,
    event_type      TEXT    NOT NULL,
    host            TEXT,
    user            TEXT,
    process         TEXT,
    pid             INTEGER,
    src_ip          TEXT,
    dst_ip          TEXT,
    file_path       TEXT,
    action          TEXT,
    source          TEXT,
    payload         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

CREATE TABLE IF NOT EXISTS detections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_uid   TEXT    NOT NULL UNIQUE,
    event_id        TEXT    NOT NULL,
    timestamp       REAL    NOT NULL,
    detector        TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    score           REAL    NOT NULL,
    host            TEXT,
    user            TEXT,
    tags            TEXT,
    payload         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS idx_detections_detector ON detections(detector);
CREATE INDEX IF NOT EXISTS idx_detections_host ON detections(host);
CREATE INDEX IF NOT EXISTS idx_detections_event_id ON detections(event_id);

CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT    NOT NULL,
    snapshot_ts     REAL    NOT NULL,
    severity        TEXT    NOT NULL,
    score           REAL    NOT NULL,
    status          TEXT    NOT NULL,
    affected_hosts  TEXT,
    title           TEXT,
    payload         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_snapshot_ts ON incidents(snapshot_ts);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
"""


@dataclass
class EventRecord:
    id: int
    event_id: str
    timestamp: float
    event_type: str
    host: Optional[str]
    user: Optional[str]
    process: Optional[str]
    pid: Optional[int]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    file_path: Optional[str]
    action: Optional[str]
    source: Optional[str]
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d["timestamp_iso"] = format_iso(self.timestamp)
        return d


@dataclass
class DetectionRecord:
    id: int
    detection_uid: str
    event_id: str
    timestamp: float
    detector: str
    severity: str
    score: float
    host: Optional[str]
    user: Optional[str]
    tags: List[str]
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d["timestamp_iso"] = format_iso(self.timestamp)
        return d


@dataclass
class IncidentRecord:
    id: int
    incident_id: str
    snapshot_ts: float
    severity: str
    score: float
    status: str
    affected_hosts: List[str]
    title: str
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d["snapshot_iso"] = format_iso(self.snapshot_ts)
        return d


class ForensicsStore:
    """Thread-safe SQLite store for events, detections, and incident snapshots."""

    def __init__(self, path: str | Path = ":memory:", *, journal_mode: str = "WAL") -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        # ``check_same_thread=False`` is safe because every write/read
        # is wrapped in the instance lock — single shared connection
        # avoids the WAL "database is locked" thrash of separate ones.
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            try:
                self._conn.execute(f"PRAGMA journal_mode = {journal_mode}")
            except sqlite3.Error:                          # pragma: no cover
                pass
        self._init_schema()

    # --- internals ----------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            cur = self._conn.execute("SELECT version FROM schema_meta")
            row = cur.fetchone()
            if row is None:
                self._conn.execute("INSERT INTO schema_meta (version) VALUES (?)", (_SCHEMA_VERSION,))

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            try:
                self._conn.execute("BEGIN")
                yield self._conn.cursor()
                self._conn.execute("COMMIT")
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK")
                raise

    # --- writers ------------------------------------------------------

    def record_event(self, event: Event) -> int:
        data = event.to_dict()
        payload = json.dumps(data, default=str)
        with self._tx() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO events
                    (event_id, timestamp, event_type, host, user, process, pid,
                     src_ip, dst_ip, file_path, action, source, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id, event.timestamp,
                        event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
                        event.host, event.user, event.process, event.pid,
                        event.src_ip, event.dst_ip, event.file_path, event.action, event.source,
                        payload,
                    ),
                )
            except sqlite3.IntegrityError:
                cur.execute("SELECT id FROM events WHERE event_id = ?", (event.event_id,))
                row = cur.fetchone()
                return int(row["id"]) if row else 0
            return int(cur.lastrowid or 0)

    def record_detection(self, detection: Detection) -> int:
        event = detection.event
        detection_uid = f"{event.event_id}:{detection.detector}"
        payload = json.dumps(detection.to_dict(), default=str)
        with self._tx() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO detections
                    (detection_uid, event_id, timestamp, detector, severity, score,
                     host, user, tags, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        detection_uid, event.event_id, event.timestamp,
                        detection.detector, detection.severity.value, float(detection.score),
                        event.host, event.user, json.dumps(list(detection.tags)),
                        payload,
                    ),
                )
            except sqlite3.IntegrityError:
                cur.execute("SELECT id FROM detections WHERE detection_uid = ?", (detection_uid,))
                row = cur.fetchone()
                return int(row["id"]) if row else 0
            return int(cur.lastrowid or 0)

    def record_incident(self, incident: Any) -> int:
        """Snapshot an incident as an append-only row.

        Re-recording the same incident inserts a new row so callers can
        reconstruct the status timeline post-hoc.
        """
        if not hasattr(incident, "to_dict"):
            raise TypeError("incident must implement to_dict()")
        d = incident.to_dict()
        with self._tx() as cur:
            cur.execute(
                """
                INSERT INTO incidents
                (incident_id, snapshot_ts, severity, score, status,
                 affected_hosts, title, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    d.get("incident_id"), now_epoch(),
                    d.get("severity", "low"), float(d.get("score", 0.0)),
                    d.get("status", "open"),
                    json.dumps(d.get("affected_hosts") or []),
                    d.get("title", ""),
                    json.dumps(d, default=str),
                ),
            )
            return int(cur.lastrowid or 0)

    # --- readers ------------------------------------------------------

    def event_by_id(self, event_id: str) -> Optional[EventRecord]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
            row = cur.fetchone()
            return _event_from_row(row) if row else None

    def detection_by_uid(self, detection_uid: str) -> Optional[DetectionRecord]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM detections WHERE detection_uid = ?", (detection_uid,))
            row = cur.fetchone()
            return _detection_from_row(row) if row else None

    def detections_for_event(self, event_id: str) -> List[DetectionRecord]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM detections WHERE event_id = ? ORDER BY timestamp", (event_id,)
            )
            return [_detection_from_row(r) for r in cur.fetchall()]

    def incident_history(self, incident_id: str) -> List[IncidentRecord]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ? ORDER BY snapshot_ts",
                (incident_id,),
            )
            return [_incident_from_row(r) for r in cur.fetchall()]

    def iter_events(self, *, since: Optional[float] = None, until: Optional[float] = None,
                    host: Optional[str] = None, limit: int = 1000) -> Iterator[EventRecord]:
        return self._iter_filtered("events", _event_from_row, since=since, until=until,
                                     host=host, limit=limit, severity=None, detector=None)

    def iter_detections(self, *, since: Optional[float] = None, until: Optional[float] = None,
                        host: Optional[str] = None, severity: Optional[str] = None,
                        detector: Optional[str] = None, limit: int = 1000) -> Iterator[DetectionRecord]:
        return self._iter_filtered("detections", _detection_from_row, since=since, until=until,
                                     host=host, severity=severity, detector=detector, limit=limit)

    def _iter_filtered(self, table: str, fn, *, since, until, host, severity, detector, limit) -> Iterator:
        clauses: List[str] = []
        params: List[Any] = []
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until)
        if host is not None:
            clauses.append("host = ?")
            params.append(host)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if detector is not None:
            clauses.append("detector = ?")
            params.append(detector)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM {table} {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            cur = self._conn.execute(sql, params)
            for row in cur.fetchall():
                yield fn(row)

    # --- maintenance --------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        time_columns = {"events": "timestamp", "detections": "timestamp", "incidents": "snapshot_ts"}
        with self._lock:
            out: Dict[str, Any] = {}
            for table, ts_col in time_columns.items():
                cur = self._conn.execute(
                    f"SELECT COUNT(1) AS n, MIN({ts_col}) AS lo, MAX({ts_col}) AS hi FROM {table}"
                )
                row = cur.fetchone()
                out[table] = {
                    "count": int(row["n"] or 0),
                    "first_ts": row["lo"],
                    "last_ts": row["hi"],
                }
            cur = self._conn.execute("SELECT severity, COUNT(1) AS n FROM detections GROUP BY severity")
            out["detections_by_severity"] = {r["severity"]: int(r["n"]) for r in cur.fetchall()}
            return out

    def delete_older_than(self, *, cutoff_ts: float) -> Dict[str, int]:
        removed = {"events": 0, "detections": 0, "incidents": 0}
        with self._tx() as cur:
            cur.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_ts,))
            removed["events"] = cur.rowcount
            cur.execute("DELETE FROM detections WHERE timestamp < ?", (cutoff_ts,))
            removed["detections"] = cur.rowcount
            cur.execute("DELETE FROM incidents WHERE snapshot_ts < ?", (cutoff_ts,))
            removed["incidents"] = cur.rowcount
        return removed

    def vacuum(self) -> None:
        with self._lock:
            self._conn.execute("VACUUM")

    def close(self) -> None:
        with self._lock:
            with contextlib.suppress(sqlite3.Error):
                self._conn.close()


# --- row -> record helpers -------------------------------------------

def _event_from_row(row: sqlite3.Row) -> EventRecord:
    return EventRecord(
        id=int(row["id"]),
        event_id=row["event_id"],
        timestamp=float(row["timestamp"]),
        event_type=row["event_type"],
        host=row["host"], user=row["user"], process=row["process"],
        pid=row["pid"], src_ip=row["src_ip"], dst_ip=row["dst_ip"],
        file_path=row["file_path"], action=row["action"], source=row["source"],
        payload=_safe_json(row["payload"]),
    )


def _detection_from_row(row: sqlite3.Row) -> DetectionRecord:
    return DetectionRecord(
        id=int(row["id"]),
        detection_uid=row["detection_uid"],
        event_id=row["event_id"],
        timestamp=float(row["timestamp"]),
        detector=row["detector"],
        severity=row["severity"],
        score=float(row["score"]),
        host=row["host"], user=row["user"],
        tags=_safe_json(row["tags"], default=[]),
        payload=_safe_json(row["payload"]),
    )


def _incident_from_row(row: sqlite3.Row) -> IncidentRecord:
    return IncidentRecord(
        id=int(row["id"]),
        incident_id=row["incident_id"],
        snapshot_ts=float(row["snapshot_ts"]),
        severity=row["severity"],
        score=float(row["score"]),
        status=row["status"],
        affected_hosts=_safe_json(row["affected_hosts"], default=[]),
        title=row["title"] or "",
        payload=_safe_json(row["payload"]),
    )


def _safe_json(raw: Optional[str], default: Any = None) -> Any:
    if not raw:
        return default if default is not None else {}
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default if default is not None else {}
