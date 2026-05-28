"""Scheduled report generation daemon.

``ReportScheduler`` maintains a list of :class:`ReportSchedule` objects,
each specifying a report type, output format, look-back window, and
repetition interval.  A background thread wakes every
``poll_interval_s`` seconds and fires any schedules whose ``next_run``
has elapsed.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import now_epoch
from .builder import ReportBuilder
from .model import ReportFormat, ReportSchedule, ReportType
from .renderer import render_report
from .store import ReportStore

_log = get_logger(__name__)


class ReportScheduler:
    """Background daemon that generates reports on a configurable schedule.

    Parameters
    ----------
    builder:
        :class:`ReportBuilder` bound to the live pipeline.
    store:
        :class:`ReportStore` where completed reports are persisted.
    poll_interval_s:
        How often the scheduler thread wakes to check for due schedules.
    on_report:
        Optional callback invoked with each completed report; useful for
        e-mailing or pushing to a webhook.
    """

    def __init__(
        self,
        builder: ReportBuilder,
        store: ReportStore,
        *,
        poll_interval_s: float = 60.0,
        on_report: Optional[Callable] = None,
    ) -> None:
        self.builder = builder
        self.store = store
        self.poll_interval_s = poll_interval_s
        self.on_report = on_report

        self._lock = threading.Lock()
        self._schedules: Dict[str, ReportSchedule] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # schedule management
    # ------------------------------------------------------------------

    def add_schedule(self, schedule: ReportSchedule) -> ReportSchedule:
        with self._lock:
            if schedule.next_run is None:
                schedule.next_run = now_epoch()   # fire immediately on first poll
            self._schedules[schedule.schedule_id] = schedule
            _log.info(
                "added report schedule %s (%s every %.0fs)",
                schedule.schedule_id, schedule.report_type.value, schedule.interval_s,
            )
            return schedule

    def remove_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            if schedule_id in self._schedules:
                del self._schedules[schedule_id]
                return True
            return False

    def enable_schedule(self, schedule_id: str, enabled: bool) -> bool:
        with self._lock:
            sch = self._schedules.get(schedule_id)
            if sch is None:
                return False
            sch.enabled = enabled
            return True

    def get_schedule(self, schedule_id: str) -> Optional[ReportSchedule]:
        with self._lock:
            return self._schedules.get(schedule_id)

    def list_schedules(self) -> List[ReportSchedule]:
        with self._lock:
            return list(self._schedules.values())

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="report-scheduler", daemon=True
        )
        self._thread.start()
        _log.info("ReportScheduler started (poll_interval=%.0fs)", self.poll_interval_s)

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # ------------------------------------------------------------------
    # manual trigger
    # ------------------------------------------------------------------

    def run_now(self, schedule_id: str) -> Optional[Any]:
        with self._lock:
            sch = self._schedules.get(schedule_id)
        if sch is None:
            return None
        return self._execute(sch)

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.wait(self.poll_interval_s):
            with self._lock:
                due = [s for s in self._schedules.values()
                       if s.enabled and s.next_run is not None and now_epoch() >= s.next_run]
            for sch in due:
                try:
                    self._execute(sch)
                except Exception as exc:
                    _log.error("schedule %s failed: %s", sch.schedule_id, exc)

    def _execute(self, schedule: ReportSchedule) -> Any:
        _log.info("running report schedule %s (%s)", schedule.schedule_id, schedule.report_type.value)
        report = self.builder.build(
            report_type=schedule.report_type,
            format=schedule.format,
            lookback_s=schedule.lookback_s,
            tags=list(schedule.tags),
            schedule_id=schedule.schedule_id,
        )
        report.rendered = render_report(report)
        self.store.save(report)

        now = now_epoch()
        schedule.last_run = now
        schedule.next_run = now + schedule.interval_s
        schedule.run_count += 1

        if self.on_report is not None:
            try:
                self.on_report(report)
            except Exception as exc:
                _log.warning("on_report callback error: %s", exc)

        _log.info(
            "report %s generated (type=%s, status=%s)",
            report.report_id, report.report_type.value, report.status.value,
        )
        return report


# ------------------------------------------------------------------
# built-in default schedules
# ------------------------------------------------------------------

def default_schedules() -> List[ReportSchedule]:
    """Return a starter set of schedules suitable for most deployments."""
    return [
        ReportSchedule(
            name="Daily Executive Report",
            report_type=ReportType.EXECUTIVE,
            format=ReportFormat.HTML,
            interval_s=86_400.0,
            lookback_s=86_400.0,
            tags=["daily", "executive"],
        ),
        ReportSchedule(
            name="Weekly Compliance Report",
            report_type=ReportType.COMPLIANCE,
            format=ReportFormat.HTML,
            interval_s=604_800.0,
            lookback_s=604_800.0,
            tags=["weekly", "compliance"],
        ),
        ReportSchedule(
            name="Hourly Operational Report",
            report_type=ReportType.OPERATIONAL,
            format=ReportFormat.JSON,
            interval_s=3_600.0,
            lookback_s=3_600.0,
            tags=["hourly", "operational"],
        ),
    ]
