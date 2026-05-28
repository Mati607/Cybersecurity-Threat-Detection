"""Data model for generated reports."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..utils.timeutil import format_iso, now_epoch


class ReportFormat(str, Enum):
    HTML = "html"
    JSON = "json"
    TEXT = "text"


class ReportStatus(str, Enum):
    PENDING = "pending"
    BUILDING = "building"
    COMPLETE = "complete"
    FAILED = "failed"


class ReportType(str, Enum):
    EXECUTIVE = "executive"
    OPERATIONAL = "operational"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    HUNT = "hunt"
    TREND = "trend"


@dataclass
class ReportSection:
    section_id: str
    title: str
    data: Dict[str, Any] = field(default_factory=dict)
    order: int = 0
    render_hint: str = ""        # e.g. "table", "chart", "prose"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "section_id": self.section_id,
            "title": self.title,
            "data": self.data,
            "order": self.order,
            "render_hint": self.render_hint,
        }


@dataclass
class Report:
    report_id: str = field(default_factory=lambda: f"RPT-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    report_type: ReportType = ReportType.EXECUTIVE
    format: ReportFormat = ReportFormat.JSON
    status: ReportStatus = ReportStatus.PENDING
    created_at: float = field(default_factory=now_epoch)
    completed_at: Optional[float] = None
    period_start: float = 0.0
    period_end: float = 0.0
    sections: List[ReportSection] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    rendered: str = ""           # final rendered output
    error: str = ""
    tags: List[str] = field(default_factory=list)
    schedule_id: Optional[str] = None

    def to_dict(self, include_rendered: bool = False) -> Dict[str, Any]:
        d = {
            "report_id": self.report_id,
            "title": self.title,
            "report_type": self.report_type.value,
            "format": self.format.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "created_iso": format_iso(self.created_at),
            "completed_at": self.completed_at,
            "completed_iso": format_iso(self.completed_at) if self.completed_at else None,
            "period_start": self.period_start,
            "period_start_iso": format_iso(self.period_start) if self.period_start else None,
            "period_end": self.period_end,
            "period_end_iso": format_iso(self.period_end) if self.period_end else None,
            "sections": [s.to_dict() for s in self.sections],
            "summary": dict(self.summary),
            "error": self.error,
            "tags": list(self.tags),
            "schedule_id": self.schedule_id,
        }
        if include_rendered:
            d["rendered"] = self.rendered
        return d


@dataclass
class ReportSchedule:
    schedule_id: str = field(default_factory=lambda: f"SCH-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    report_type: ReportType = ReportType.EXECUTIVE
    format: ReportFormat = ReportFormat.JSON
    interval_s: float = 86_400.0    # daily by default
    lookback_s: float = 86_400.0    # report covers last N seconds
    enabled: bool = True
    last_run: Optional[float] = None
    next_run: Optional[float] = None
    run_count: int = 0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "name": self.name,
            "report_type": self.report_type.value,
            "format": self.format.value,
            "interval_s": self.interval_s,
            "lookback_s": self.lookback_s,
            "enabled": self.enabled,
            "last_run": self.last_run,
            "last_run_iso": format_iso(self.last_run) if self.last_run else None,
            "next_run": self.next_run,
            "next_run_iso": format_iso(self.next_run) if self.next_run else None,
            "run_count": self.run_count,
            "tags": list(self.tags),
        }
