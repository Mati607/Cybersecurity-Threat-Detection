"""Section builders — each builds one :class:`ReportSection` from pipeline state.

Each function returns a dict that maps directly to ``ReportSection.data``.
They are intentionally side-effect-free so the builder can call them in
any order or skip them when the relevant subsystem is not attached.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from ..utils.timeutil import format_iso, now_epoch


# ------------------------------------------------------------------
# helper
# ------------------------------------------------------------------

def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b else default


def _top_n(counter: Dict[str, int], n: int = 10) -> List[Dict[str, Any]]:
    return [{"key": k, "count": v} for k, v in sorted(counter.items(), key=lambda x: -x[1])[:n]]


# ------------------------------------------------------------------
# summary headline
# ------------------------------------------------------------------

def build_summary_section(
    *,
    period_start: float,
    period_end: float,
    events_total: int,
    detections_total: int,
    incidents_total: int,
    high_severity: int,
    critical_severity: int,
    pipeline_uptime_s: float = 0.0,
    hosts_observed: int = 0,
) -> Dict[str, Any]:
    duration_h = (period_end - period_start) / 3600
    det_rate = _safe_div(detections_total, duration_h)
    return {
        "period_start_iso": format_iso(period_start),
        "period_end_iso": format_iso(period_end),
        "duration_hours": round(duration_h, 2),
        "events_total": events_total,
        "detections_total": detections_total,
        "incidents_total": incidents_total,
        "high_severity": high_severity,
        "critical_severity": critical_severity,
        "detections_per_hour": round(det_rate, 2),
        "pipeline_uptime_s": round(pipeline_uptime_s, 0),
        "hosts_observed": hosts_observed,
        "alert_ratio": round(_safe_div(detections_total, max(events_total, 1)), 4),
    }


# ------------------------------------------------------------------
# detection breakdown
# ------------------------------------------------------------------

def build_detection_section(
    detections: List[Any],
    *,
    period_start: float = 0.0,
    period_end: float = 0.0,
) -> Dict[str, Any]:
    by_severity: Dict[str, int] = {}
    by_engine: Dict[str, int] = {}
    by_host: Dict[str, int] = {}
    by_rule: Dict[str, int] = {}
    scores: List[float] = []

    for d in detections:
        sev = getattr(getattr(d, "severity", None), "value", None) or d.get("severity", "unknown") if isinstance(d, dict) else "unknown"
        engine = getattr(d, "engine", None) or (d.get("engine", "unknown") if isinstance(d, dict) else "unknown")
        host = getattr(d, "host", None) or (d.get("host", "unknown") if isinstance(d, dict) else "unknown")
        score = getattr(d, "score", None) or (d.get("score", 0.0) if isinstance(d, dict) else 0.0)
        rule = getattr(d, "rule_id", None) or (d.get("rule_id") if isinstance(d, dict) else None) or ""

        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_engine[engine] = by_engine.get(engine, 0) + 1
        by_host[host] = by_host.get(host, 0) + 1
        if score:
            scores.append(float(score))
        if rule:
            by_rule[rule] = by_rule.get(rule, 0) + 1

    mean_score = sum(scores) / len(scores) if scores else 0.0
    return {
        "count": len(detections),
        "by_severity": by_severity,
        "by_engine": by_engine,
        "top_hosts": _top_n(by_host),
        "top_rules": _top_n(by_rule),
        "mean_score": round(mean_score, 4),
        "max_score": round(max(scores, default=0.0), 4),
    }


# ------------------------------------------------------------------
# incident summary
# ------------------------------------------------------------------

def build_incident_section(incidents: List[Any]) -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_phase: Dict[str, int] = {}
    by_host: Dict[str, int] = {}
    open_count = 0

    for inc in incidents:
        status = getattr(getattr(inc, "status", None), "value", "unknown")
        sev = getattr(getattr(inc, "severity", None), "value", "unknown")
        phase = getattr(getattr(inc, "kill_chain_phase", None), "value", None) or "unknown"
        host = getattr(inc, "host", "unknown") or "unknown"

        by_status[status] = by_status.get(status, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_phase[phase] = by_phase.get(phase, 0) + 1
        by_host[host] = by_host.get(host, 0) + 1
        if status in ("new", "investigating"):
            open_count += 1

    return {
        "count": len(incidents),
        "open_count": open_count,
        "by_status": by_status,
        "by_severity": by_severity,
        "by_kill_chain_phase": by_phase,
        "top_hosts": _top_n(by_host),
    }


# ------------------------------------------------------------------
# graph stats
# ------------------------------------------------------------------

def build_graph_section(graph: Any) -> Dict[str, Any]:
    if graph is None:
        return {"enabled": False}
    try:
        nodes = len(graph._nodes) if hasattr(graph, "_nodes") else 0
        edges = len(graph._edges) if hasattr(graph, "_edges") else 0
    except Exception:
        nodes = edges = 0
    return {
        "enabled": True,
        "node_count": nodes,
        "edge_count": edges,
    }


# ------------------------------------------------------------------
# hunt activity
# ------------------------------------------------------------------

def build_hunt_section(hunt_store: Any) -> Dict[str, Any]:
    if hunt_store is None:
        return {"enabled": False}
    try:
        hunts = list(hunt_store._hunts.values()) if hasattr(hunt_store, "_hunts") else []
    except Exception:
        hunts = []
    total_runs = sum(getattr(h, "run_count", 0) for h in hunts)
    total_hits = sum(getattr(h, "last_hit_count", 0) for h in hunts)
    return {
        "enabled": True,
        "saved_hunt_count": len(hunts),
        "total_runs": total_runs,
        "total_hits": total_hits,
        "top_hunts": [
            {"name": getattr(h, "name", "?"), "run_count": getattr(h, "run_count", 0)}
            for h in sorted(hunts, key=lambda x: getattr(x, "run_count", 0), reverse=True)[:5]
        ],
    }


# ------------------------------------------------------------------
# compliance posture
# ------------------------------------------------------------------

def build_compliance_section(frameworks: List[str], rules: List[Any]) -> Dict[str, Any]:
    from ..compliance.frameworks import get_framework, list_frameworks
    from ..compliance.mapping import ControlMapper

    postures: List[Dict[str, Any]] = []
    for fwk_id in frameworks:
        try:
            fwk = get_framework(fwk_id)
            mapper = ControlMapper(fwk)
            mapper.add_rules(rules)
            cov = mapper.to_dict()
            summary = cov.get("summary", {})
            postures.append({
                "framework_id": fwk_id,
                "framework_name": fwk.name,
                "coverage_fraction": summary.get("coverage_fraction", 0.0),
                "covered_controls": summary.get("covered_controls", 0),
                "total_controls": summary.get("total_controls", 0),
            })
        except Exception:
            pass
    return {
        "frameworks_checked": len(postures),
        "frameworks": postures,
    }


# ------------------------------------------------------------------
# trend analysis (requires forensics store)
# ------------------------------------------------------------------

def build_trend_section(forensics_store: Any, *, period_start: float, period_end: float, buckets: int = 24) -> Dict[str, Any]:
    if forensics_store is None:
        return {"enabled": False}
    from ..forensics.query import ForensicsQuery, TimeRange, Aggregate

    q = ForensicsQuery(forensics_store)
    tr = TimeRange(start=period_start, end=period_end)
    try:
        hist = q.histogram(tr, bucket_count=buckets)
        trend_direction = "stable"
        if len(hist) >= 4:
            first_half = sum(b.get("count", 0) for b in hist[: len(hist) // 2])
            second_half = sum(b.get("count", 0) for b in hist[len(hist) // 2 :])
            ratio = _safe_div(second_half, max(first_half, 1))
            if ratio > 1.25:
                trend_direction = "increasing"
            elif ratio < 0.75:
                trend_direction = "decreasing"
        return {
            "enabled": True,
            "buckets": hist,
            "trend_direction": trend_direction,
        }
    except Exception:
        return {"enabled": True, "buckets": [], "trend_direction": "unknown"}


# ------------------------------------------------------------------
# model registry
# ------------------------------------------------------------------

def build_model_section(registry: Any) -> Dict[str, Any]:
    if registry is None:
        return {"enabled": False}
    try:
        summary = registry.summary()
        return {
            "enabled": True,
            **summary,
        }
    except Exception:
        return {"enabled": False}
