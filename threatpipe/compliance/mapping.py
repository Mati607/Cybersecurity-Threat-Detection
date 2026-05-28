"""Map detection rules onto compliance-framework controls.

The chain is: rule -> ATT&CK technique(s) -> control(s). We reuse the
ATT&CK coverage extractor so a rule only needs its ``mitre:Txxxx`` tags
(or a ``Txxxx.*`` id prefix) to flow through to every control that
references that technique.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Set

from ..attck.coverage import _extract_technique_ids
from ..detection.rule_engine import Rule
from .frameworks import Control, Framework


@dataclass
class ControlCoverage:
    control_id: str
    title: str
    family: str
    techniques: List[str]
    covered_techniques: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return bool(self.rule_ids)

    @property
    def coverage_fraction(self) -> float:
        if not self.techniques:
            return 1.0 if self.rule_ids else 0.0
        return round(len(set(self.covered_techniques)) / len(set(self.techniques)), 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "family": self.family,
            "techniques": list(self.techniques),
            "covered_techniques": sorted(set(self.covered_techniques)),
            "rule_ids": sorted(set(self.rule_ids)),
            "covered": self.covered,
            "coverage_fraction": self.coverage_fraction,
        }


class ControlMapper:
    def __init__(self, framework: Framework) -> None:
        self.framework = framework
        # technique -> set(rule_id)
        self._technique_rules: Dict[str, Set[str]] = defaultdict(set)

    def add_rules(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            for tech in _extract_technique_ids(rule):
                self._technique_rules[tech].add(rule.id)
                # also index the parent technique for sub-techniques
                if "." in tech:
                    self._technique_rules[tech.split(".", 1)[0]].add(rule.id)

    def _rules_for_technique(self, technique: str) -> Set[str]:
        rules = set(self._technique_rules.get(technique, set()))
        # a control referencing a parent technique is satisfied by a
        # rule tagged with any of its sub-techniques
        for tech, rule_ids in self._technique_rules.items():
            if tech.split(".", 1)[0] == technique:
                rules |= rule_ids
        return rules

    def coverage(self) -> List[ControlCoverage]:
        out: List[ControlCoverage] = []
        for control in self.framework.controls:
            cc = ControlCoverage(
                control_id=control.control_id,
                title=control.title,
                family=control.family,
                techniques=list(control.techniques),
            )
            for tech in control.techniques:
                rules = self._rules_for_technique(tech)
                if rules:
                    cc.covered_techniques.append(tech)
                    cc.rule_ids.extend(rules)
            out.append(cc)
        return out

    def summary(self) -> Dict[str, Any]:
        coverage = self.coverage()
        total = len(coverage)
        covered = sum(1 for c in coverage if c.covered)
        by_family: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "covered": 0})
        for c in coverage:
            by_family[c.family]["total"] += 1
            if c.covered:
                by_family[c.family]["covered"] += 1
        return {
            "framework_id": self.framework.framework_id,
            "framework": self.framework.name,
            "version": self.framework.version,
            "controls_total": total,
            "controls_covered": covered,
            "coverage_fraction": round(covered / total, 4) if total else 0.0,
            "by_family": {k: dict(v) for k, v in by_family.items()},
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "controls": [c.to_dict() for c in self.coverage()],
        }
