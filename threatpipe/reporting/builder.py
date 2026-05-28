"""Assemble a full report from pipeline state.

``ReportBuilder`` delegates to the individual section builders in
``sections.py`` and stitches the result into a :class:`Report` object.
The builder is intentionally decoupled from the scheduler so it can be
called on-demand (e.g. from the REST API) as well as by the scheduler.
"""

from __future__ import annotations

from typing import Any, List, Optional

from ..utils.timeutil import now_epoch
from .model import Report, ReportFormat, ReportSection, ReportStatus, ReportType
from .sections import (
    build_compliance_section,
    build_detection_section,
    build_graph_section,
    build_hunt_section,
    build_incident_section,
    build_model_section,
    build_summary_section,
    build_trend_section,
)


class ReportBuilder:
    """Build reports from a :class:`DetectionPipeline` (or any duck-typed object).

    The pipeline is accessed via optional attribute lookups so any subset of
    subsystems may be absent without raising.
    """

    def __init__(self, pipeline: Any) -> None:
        self.pipeline = pipeline

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def build(
        self,
        *,
        report_type: ReportType = ReportType.EXECUTIVE,
        format: ReportFormat = ReportFormat.JSON,
        period_start: Optional[float] = None,
        period_end: Optional[float] = None,
        lookback_s: float = 86_400.0,
        title: str = "",
        tags: Optional[List[str]] = None,
        schedule_id: Optional[str] = None,
    ) -> Report:
        now = now_epoch()
        period_end = period_end or now
        period_start = period_start or (period_end - lookback_s)

        report = Report(
            title=title or _default_title(report_type, period_start, period_end),
            report_type=report_type,
            format=format,
            status=ReportStatus.BUILDING,
            period_start=period_start,
            period_end=period_end,
            tags=list(tags or []),
            schedule_id=schedule_id,
        )

        try:
            self._populate(report)
            report.status = ReportStatus.COMPLETE
        except Exception as exc:
            report.status = ReportStatus.FAILED
            report.error = str(exc)

        report.completed_at = now_epoch()
        return report

    # ------------------------------------------------------------------
    # section assembly
    # ------------------------------------------------------------------

    def _populate(self, report: Report) -> None:
        p = self.pipeline
        pipeline_stats = getattr(p, "_stats", {}) or {}

        # gather detections in period
        detections = self._detections_in_period(report.period_start, report.period_end)
        incidents = self._incidents_in_period(report.period_start, report.period_end)

        by_sev: dict = {}
        for d in detections:
            sev = getattr(getattr(d, "severity", None), "value", "unknown")
            by_sev[sev] = by_sev.get(sev, 0) + 1

        sec0 = ReportSection(
            section_id="summary",
            title="Executive Summary",
            order=0,
            render_hint="prose",
            data=build_summary_section(
                period_start=report.period_start,
                period_end=report.period_end,
                events_total=pipeline_stats.get("events_in", 0),
                detections_total=len(detections),
                incidents_total=len(incidents),
                high_severity=by_sev.get("high", 0),
                critical_severity=by_sev.get("critical", 0),
                hosts_observed=len({getattr(d, "host", None) for d in detections if getattr(d, "host", None)}),
            ),
        )

        sec1 = ReportSection(
            section_id="detections",
            title="Detection Analysis",
            order=1,
            render_hint="table",
            data=build_detection_section(
                detections,
                period_start=report.period_start,
                period_end=report.period_end,
            ),
        )

        sec2 = ReportSection(
            section_id="incidents",
            title="Incident Summary",
            order=2,
            render_hint="table",
            data=build_incident_section(incidents),
        )

        sec3 = ReportSection(
            section_id="graph",
            title="Provenance Graph",
            order=3,
            render_hint="stats",
            data=build_graph_section(getattr(p, "graph", None)),
        )

        sec4 = ReportSection(
            section_id="hunt",
            title="Threat Hunt Activity",
            order=4,
            render_hint="table",
            data=build_hunt_section(getattr(p, "_hunt_store", None)),
        )

        sec5 = ReportSection(
            section_id="trend",
            title="Detection Trend",
            order=5,
            render_hint="chart",
            data=build_trend_section(
                self._forensics_store(),
                period_start=report.period_start,
                period_end=report.period_end,
            ),
        )

        sec6 = ReportSection(
            section_id="models",
            title="ML Model Registry",
            order=6,
            render_hint="table",
            data=build_model_section(getattr(p, "model_registry", None)),
        )

        sections = [sec0, sec1, sec2, sec3, sec4, sec5, sec6]

        if report.report_type == ReportType.COMPLIANCE:
            rules = list(getattr(getattr(p, "_rule_engine", None), "rules", {}).values() if hasattr(getattr(p, "_rule_engine", None), "rules") else [])
            sec7 = ReportSection(
                section_id="compliance",
                title="Compliance Coverage",
                order=7,
                render_hint="table",
                data=build_compliance_section(
                    ["nist-800-53", "cis-v8", "pci-dss-v4", "iso-27001"], rules
                ),
            )
            sections.append(sec7)

        report.sections = sections
        report.summary = sec0.data

    # ------------------------------------------------------------------
    # data helpers
    # ------------------------------------------------------------------

    def _detections_in_period(self, start: float, end: float) -> list:
        p = self.pipeline
        # try forensics store first for bounded result
        fs = self._forensics_store()
        if fs is not None:
            from ..forensics.query import ForensicsQuery, TimeRange

            q = ForensicsQuery(fs)
            try:
                return q.detections(TimeRange(start=start, end=end), limit=10_000)
            except Exception:
                pass
        # fallback: in-memory detections deque
        raw = list(getattr(p, "_detections", []) or [])
        return [d for d in raw if start <= getattr(d, "timestamp", 0) <= end]

    def _incidents_in_period(self, start: float, end: float) -> list:
        p = self.pipeline
        store = getattr(getattr(p, "incident_aggregator", None), "_store", None)
        if store is None:
            store = getattr(p, "_incident_store", None)
        if store is None:
            return []
        try:
            all_inc = store.list_incidents()
            return [
                i for i in all_inc
                if start <= getattr(i, "first_seen", 0) <= end
            ]
        except Exception:
            return []

    def _forensics_store(self):
        p = self.pipeline
        sink = getattr(p, "forensics_sink", None)
        if sink is not None:
            return getattr(sink, "store", None)
        return getattr(p, "_forensics_store", None)


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _default_title(report_type: ReportType, period_start: float, period_end: float) -> str:
    from ..utils.timeutil import format_iso

    type_label = {
        ReportType.EXECUTIVE: "Executive",
        ReportType.OPERATIONAL: "Operational",
        ReportType.COMPLIANCE: "Compliance",
        ReportType.INCIDENT: "Incident",
        ReportType.HUNT: "Threat Hunt",
        ReportType.TREND: "Trend",
    }.get(report_type, "Security")
    return f"{type_label} Report — {format_iso(period_start)[:10]} to {format_iso(period_end)[:10]}"
