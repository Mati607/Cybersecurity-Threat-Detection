"""Gap analysis: which controls are uncovered, and why.

Produces the punch-list a detection engineer works from after a
compliance review - the controls with no detection coverage, the
techniques those controls expect that no rule exercises, and a simple
prioritization by how many controls each missing technique would
unlock.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from ..detection.rule_engine import Rule
from .frameworks import Framework
from .mapping import ControlMapper


@dataclass
class GapAnalysis:
    framework_id: str
    uncovered_controls: List[Dict[str, Any]] = field(default_factory=list)
    partially_covered: List[Dict[str, Any]] = field(default_factory=list)
    missing_techniques: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "uncovered_control_count": len(self.uncovered_controls),
            "partially_covered_count": len(self.partially_covered),
            "uncovered_controls": self.uncovered_controls,
            "partially_covered": self.partially_covered,
            "missing_techniques": self.missing_techniques,
        }


def analyze_gaps(framework: Framework, rules: Iterable[Rule]) -> GapAnalysis:
    rules = list(rules)
    mapper = ControlMapper(framework)
    mapper.add_rules(rules)
    coverage = mapper.coverage()

    uncovered = []
    partial = []
    missing_tech_counter: Counter = Counter()

    for cc in coverage:
        if not cc.covered:
            uncovered.append({
                "control_id": cc.control_id,
                "title": cc.title,
                "family": cc.family,
                "expected_techniques": list(cc.techniques),
            })
            for tech in cc.techniques:
                missing_tech_counter[tech] += 1
        elif cc.coverage_fraction < 1.0:
            missing = sorted(set(cc.techniques) - set(cc.covered_techniques))
            partial.append({
                "control_id": cc.control_id,
                "title": cc.title,
                "coverage_fraction": cc.coverage_fraction,
                "missing_techniques": missing,
            })
            for tech in missing:
                missing_tech_counter[tech] += 1

    missing_techniques = [
        {"technique": tech, "unlocks_controls": count}
        for tech, count in missing_tech_counter.most_common()
    ]

    return GapAnalysis(
        framework_id=framework.framework_id,
        uncovered_controls=uncovered,
        partially_covered=partial,
        missing_techniques=missing_techniques,
    )
