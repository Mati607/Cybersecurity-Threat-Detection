"""Persist and retrieve generated reports.

Reports are stored as individual JSON files under a configurable
directory.  The index is kept in memory and rebuilt on startup.

Rendered HTML/text bodies are stored inline in the JSON files so a
separate asset server is not needed for the REST API.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import now_epoch
from .model import Report, ReportFormat, ReportSection, ReportStatus, ReportType

_log = get_logger(__name__)

_MAX_IN_MEMORY = 500


class ReportStore:
    """File-backed store for :class:`Report` objects.

    Parameters
    ----------
    path:
        Directory where report JSON files are written.  Pass ``":memory:"``
        for a pure in-memory store (useful in tests).
    max_reports:
        Maximum number of reports to keep on disk (FIFO eviction).
    """

    def __init__(self, path: str = ":memory:", *, max_reports: int = 200) -> None:
        self.path = path
        self.max_reports = max_reports
        self._lock = threading.Lock()
        self._reports: Dict[str, Report] = {}    # report_id -> Report

        if path != ":memory:":
            os.makedirs(path, exist_ok=True)
            self._load_from_disk()

    # ------------------------------------------------------------------
    # write
    # ------------------------------------------------------------------

    def save(self, report: Report) -> None:
        with self._lock:
            self._reports[report.report_id] = report
            if self.path != ":memory:":
                self._write(report)
            self._evict()

    def _write(self, report: Report) -> None:
        fpath = self._fpath(report.report_id)
        try:
            data = report.to_dict(include_rendered=True)
            tmp = fpath + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh, indent=2, default=str)
            os.replace(tmp, fpath)
        except Exception as exc:
            _log.warning("failed to write report %s: %s", report.report_id, exc)

    # ------------------------------------------------------------------
    # read
    # ------------------------------------------------------------------

    def get(self, report_id: str) -> Optional[Report]:
        with self._lock:
            return self._reports.get(report_id)

    def list_reports(
        self,
        *,
        report_type: Optional[ReportType] = None,
        status: Optional[ReportStatus] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Report]:
        with self._lock:
            items = list(self._reports.values())
        items.sort(key=lambda r: r.created_at, reverse=True)
        if report_type is not None:
            items = [r for r in items if r.report_type == report_type]
        if status is not None:
            items = [r for r in items if r.status == status]
        return items[offset : offset + limit]

    def count(self) -> int:
        with self._lock:
            return len(self._reports)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            reports = list(self._reports.values())
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for r in reports:
            by_type[r.report_type.value] = by_type.get(r.report_type.value, 0) + 1
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        return {
            "total": len(reports),
            "by_type": by_type,
            "by_status": by_status,
            "store_path": self.path,
        }

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _evict(self) -> None:
        if len(self._reports) <= self.max_reports:
            return
        by_time = sorted(self._reports.values(), key=lambda r: r.created_at)
        to_remove = by_time[: len(self._reports) - self.max_reports]
        for r in to_remove:
            del self._reports[r.report_id]
            if self.path != ":memory:":
                try:
                    os.unlink(self._fpath(r.report_id))
                except OSError:
                    pass

    def _fpath(self, report_id: str) -> str:
        return os.path.join(self.path, f"{report_id}.json")

    def _load_from_disk(self) -> None:
        try:
            files = [f for f in os.listdir(self.path) if f.endswith(".json") and not f.endswith(".tmp")]
        except OSError:
            return
        for fname in files:
            fpath = os.path.join(self.path, fname)
            try:
                with open(fpath) as fh:
                    data = json.load(fh)
                r = _report_from_dict(data)
                self._reports[r.report_id] = r
            except Exception as exc:
                _log.warning("skipping corrupt report file %s: %s", fname, exc)


def _report_from_dict(data: Dict[str, Any]) -> Report:
    r = Report(
        report_id=data.get("report_id", f"RPT-UNKNOWN"),
        title=data.get("title", ""),
        report_type=ReportType(data.get("report_type", "executive")),
        format=ReportFormat(data.get("format", "json")),
        status=ReportStatus(data.get("status", "complete")),
        created_at=data.get("created_at", now_epoch()),
        completed_at=data.get("completed_at"),
        period_start=data.get("period_start", 0.0),
        period_end=data.get("period_end", 0.0),
        summary=data.get("summary", {}),
        rendered=data.get("rendered", ""),
        error=data.get("error", ""),
        tags=data.get("tags", []),
        schedule_id=data.get("schedule_id"),
    )
    for s_data in data.get("sections", []):
        r.sections.append(ReportSection(
            section_id=s_data.get("section_id", ""),
            title=s_data.get("title", ""),
            data=s_data.get("data", {}),
            order=s_data.get("order", 0),
            render_hint=s_data.get("render_hint", ""),
        ))
    return r
