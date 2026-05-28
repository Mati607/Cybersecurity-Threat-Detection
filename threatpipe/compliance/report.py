"""Assemble a full compliance report for a framework.

Combines the control-coverage map, the gap analysis, and headline
metrics into one document suitable for a JSON API response or for
rendering into an executive summary.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable

from ..detection.rule_engine import Rule
from ..utils.timeutil import format_iso, now_epoch
from .frameworks import Framework
from .gap import analyze_gaps
from .mapping import ControlMapper


def build_compliance_report(framework: Framework, rules: Iterable[Rule]) -> Dict[str, Any]:
    rules = list(rules)
    mapper = ControlMapper(framework)
    mapper.add_rules(rules)
    coverage = mapper.to_dict()
    gaps = analyze_gaps(framework, rules)

    summary = coverage["summary"]
    posture = _posture(summary["coverage_fraction"])

    return {
        "generated_at": now_epoch(),
        "generated_iso": format_iso(now_epoch()),
        "framework": {
            "id": framework.framework_id,
            "name": framework.name,
            "version": framework.version,
        },
        "rule_count": len(rules),
        "posture": posture,
        "summary": summary,
        "controls": coverage["controls"],
        "gaps": gaps.to_dict(),
    }


def _posture(fraction: float) -> str:
    if fraction >= 0.9:
        return "strong"
    if fraction >= 0.66:
        return "moderate"
    if fraction >= 0.33:
        return "developing"
    return "initial"
