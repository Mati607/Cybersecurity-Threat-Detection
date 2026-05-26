"""Normalized event schema used everywhere downstream of ingestion.

We intentionally keep this small. Anything dataset-specific lives in the
``raw`` dict so we don't lose information, but detectors only ever look
at the top-level fields.
"""

from __future__ import annotations

import enum
import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

from ..utils.timeutil import format_iso, now_epoch


class EventType(str, enum.Enum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    AUTH = "auth"
    SYSCALL = "syscall"
    AUDIT = "audit"
    UNKNOWN = "unknown"


@dataclass
class Event:
    """Normalized event passed between ingestion, detection, and alerts."""

    timestamp: float = field(default_factory=now_epoch)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    event_type: EventType = EventType.UNKNOWN
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    file_path: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    source: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["timestamp_iso"] = format_iso(self.timestamp)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        data = dict(data)
        data.pop("timestamp_iso", None)
        if "event_type" in data and not isinstance(data["event_type"], EventType):
            try:
                data["event_type"] = EventType(data["event_type"])
            except ValueError:
                data["event_type"] = EventType.UNKNOWN
        return cls(**data)
