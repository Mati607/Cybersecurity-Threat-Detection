"""Detection coverage map against the ATT&CK catalog.

Given a list of rules (the bundled catalog plus any custom or
Sigma-imported rules), :class:`CoverageMap` produces an ATT&CK-shaped
view: per-technique counts, per-tactic counts, and per-technique
links back to the contributing rules. The output feeds both the
``/attck/coverage`` API endpoint and a Navigator-compatible JSON
layer for visualization.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

from ..detection.rule_engine import Rule
from .catalog import AttckCatalog, Tactic, Technique


@dataclass
class CoverageEntry:
    technique_id: str
    name: str
    tactics: List[Tactic]
    rule_count: int = 0
    rule_ids: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return self.rule_count > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactics": [t.value for t in self.tactics],
            "rule_count": self.rule_count,
            "rule_ids": list(self.rule_ids),
            "severities": list(self.severities),
            "covered": self.covered,
        }


def _extract_technique_ids(rule: Rule) -> List[str]:
    """Find ATT&CK technique IDs referenced by a rule.

    We look at:
    * ``mitre:Txxxx`` tags (most common in the bundled catalog)
    * raw ``Txxxx`` tags
    * the rule's id prefix when it follows the convention used in the
      bundled catalog (``Txxxx.NAME``)
    """
    ids: Set[str] = set()
    for tag in rule.tags:
        if tag.lower().startswith("mitre:"):
            ids.add(tag.split(":", 1)[1].upper())
        elif tag.upper().startswith("T") and tag[1:5].isdigit():
            ids.add(tag.upper())
    rule_prefix = rule.id.split(".", 1)[0]
    if rule_prefix.startswith("T") and rule_prefix[1:5].isdigit():
        ids.add(rule_prefix.upper())
    return sorted(ids)


class CoverageMap:
    def __init__(self, catalog: Optional[AttckCatalog] = None) -> None:
        self.catalog = catalog or AttckCatalog()
        self._entries: Dict[str, CoverageEntry] = {}
        self._unknown: Dict[str, CoverageEntry] = {}

    def add_rules(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            tech_ids = _extract_technique_ids(rule)
            if not tech_ids:
                continue
            for tech_id in tech_ids:
                tech = self.catalog.get(tech_id)
                if tech is None:
                    target = self._unknown.setdefault(tech_id, CoverageEntry(
                        technique_id=tech_id, name="(unknown)", tactics=[],
                    ))
                else:
                    target = self._entries.setdefault(tech.technique_id, CoverageEntry(
                        technique_id=tech.technique_id, name=tech.name, tactics=list(tech.tactics),
                    ))
                target.rule_count += 1
                target.rule_ids.append(rule.id)
                target.severities.append(rule.severity.value)

    # --- views ---------------------------------------------------

    def coverage(self) -> List[CoverageEntry]:
        items = list(self._entries.values()) + list(self._unknown.values())
        items.sort(key=lambda e: e.technique_id)
        return items

    def covered_techniques(self) -> List[Technique]:
        return [
            t for t in self.catalog.all()
            if t.technique_id in self._entries
        ]

    def uncovered_techniques(self) -> List[Technique]:
        return [
            t for t in self.catalog.all()
            if t.technique_id not in self._entries and not t.is_subtechnique
        ]

    def by_tactic(self) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {t.value: {"total": 0, "covered": 0} for t in self.catalog.tactics()}
        for tech in self.catalog.all():
            for tactic in tech.tactics:
                out[tactic.value]["total"] += 1
        for entry in self._entries.values():
            for tactic in entry.tactics:
                out[tactic.value]["covered"] += 1
        return out

    def summary(self) -> Dict[str, Any]:
        total = sum(1 for _ in self.catalog.all() if not _.is_subtechnique)
        covered_techs = {entry.technique_id.split(".", 1)[0] for entry in self._entries.values()}
        return {
            "techniques_total": total,
            "techniques_covered": len(covered_techs),
            "techniques_covered_fraction": round(len(covered_techs) / max(1, total), 4),
            "unknown_techniques": sorted(self._unknown),
            "by_tactic": self.by_tactic(),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "entries": [e.to_dict() for e in self.coverage()],
        }
