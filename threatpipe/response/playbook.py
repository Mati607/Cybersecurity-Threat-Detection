"""Declarative playbook model + JSON loader.

A playbook fires when a *trigger* matches and all *conditions* pass,
then runs an ordered list of *steps*. Conditions are evaluated against
the triggering detection (or incident) using a small subset of the
hunt-DSL grammar so the same expressions work in both places.

Playbooks are loaded from JSON. Each playbook can be marked
``dry_run`` to inhibit destructive actions until an operator flips
the switch.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from ..utils.logging_setup import get_logger

_log = get_logger(__name__)


class PlaybookTrigger(str, enum.Enum):
    DETECTION = "detection"
    INCIDENT_OPENED = "incident_opened"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_STATUS = "incident_status"


_COMPARATORS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "in": lambda a, b: a in b if hasattr(b, "__contains__") else False,
    "contains": lambda a, b: (b in a) if hasattr(a, "__contains__") else False,
}


@dataclass
class PlaybookCondition:
    field: str
    op: str
    value: Any

    def evaluate(self, scope: Mapping[str, Any]) -> bool:
        op = self._COMPARATORS().get(self.op)
        if op is None:
            return False
        lhs = _resolve(scope, self.field)
        try:
            return bool(op(lhs, self.value))
        except TypeError:
            return False

    @staticmethod
    def _COMPARATORS() -> Mapping[str, Any]:                # noqa: N802
        return _COMPARATORS

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PlaybookCondition":
        return cls(field=str(raw["field"]), op=str(raw.get("op", "==")), value=raw.get("value"))


@dataclass
class PlaybookStep:
    step_id: str
    action: str
    args: Dict[str, Any] = field(default_factory=dict)
    continue_on_failure: bool = False

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], idx: int) -> "PlaybookStep":
        return cls(
            step_id=str(raw.get("id", f"step-{idx + 1}")),
            action=str(raw["action"]),
            args=dict(raw.get("args", {})),
            continue_on_failure=bool(raw.get("continue_on_failure", False)),
        )


@dataclass
class Playbook:
    playbook_id: str
    name: str
    trigger: PlaybookTrigger
    steps: List[PlaybookStep]
    description: str = ""
    enabled: bool = True
    dry_run: bool = False
    conditions: List[PlaybookCondition] = field(default_factory=list)
    tags_required: List[str] = field(default_factory=list)
    min_severity: Optional[str] = None
    max_per_minute: int = 30

    def is_applicable(self, scope: Mapping[str, Any]) -> bool:
        if not self.enabled:
            return False
        if self.tags_required:
            tags = scope.get("tags") or []
            if not any(t in tags for t in self.tags_required):
                return False
        if self.min_severity:
            order = ["low", "medium", "high", "critical"]
            current = str(scope.get("severity", "low")).lower()
            try:
                if order.index(current) < order.index(self.min_severity.lower()):
                    return False
            except ValueError:
                return False
        for condition in self.conditions:
            if not condition.evaluate(scope):
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "trigger": self.trigger.value,
            "enabled": self.enabled,
            "dry_run": self.dry_run,
            "tags_required": list(self.tags_required),
            "min_severity": self.min_severity,
            "max_per_minute": self.max_per_minute,
            "conditions": [c.__dict__ for c in self.conditions],
            "steps": [
                {
                    "id": s.step_id, "action": s.action, "args": dict(s.args),
                    "continue_on_failure": s.continue_on_failure,
                }
                for s in self.steps
            ],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Playbook":
        return cls(
            playbook_id=str(raw["id"]),
            name=str(raw.get("name", raw["id"])),
            trigger=PlaybookTrigger(raw.get("trigger", "detection")),
            steps=[PlaybookStep.from_dict(s, i) for i, s in enumerate(raw.get("steps", []))],
            description=str(raw.get("description", "")),
            enabled=bool(raw.get("enabled", True)),
            dry_run=bool(raw.get("dry_run", False)),
            conditions=[PlaybookCondition.from_dict(c) for c in raw.get("conditions", [])],
            tags_required=list(raw.get("tags_required", [])),
            min_severity=raw.get("min_severity"),
            max_per_minute=int(raw.get("max_per_minute", 30)),
        )


def _resolve(scope: Mapping[str, Any], path: str) -> Any:
    """Walk a dotted path through a nested mapping/object."""
    parts = path.split(".")
    cur: Any = scope
    for part in parts:
        if isinstance(cur, Mapping):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
        if cur is None:
            return None
    return cur


def load_playbooks(path: str | Path) -> List[Playbook]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw.get("playbooks", raw) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError("playbook file must contain a list under 'playbooks' or at top-level")
    playbooks: List[Playbook] = []
    for entry in items:
        try:
            playbooks.append(Playbook.from_dict(entry))
        except (KeyError, ValueError) as exc:
            _log.warning("skipping invalid playbook entry: %s", exc)
    return playbooks
