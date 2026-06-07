"""Suppression rule store.

Holds the active :class:`~threatpipe.triage.model.SuppressionRule`s and
answers the one question the engine asks per detection: *does anything
silence this?* Expired and disabled rules are skipped transparently, and
a matched rule's ``hit_count`` is bumped so analysts can spot a rule
that's swallowing far more than they expected.

The store is thread-safe so the API can add/remove rules while the
detection pipeline reads them on its own thread.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..detection.base import Detection
from ..utils.logging_setup import get_logger
from .model import SuppressionRule

_log = get_logger(__name__)


class SuppressionList:
    def __init__(self) -> None:
        self._rules: Dict[str, SuppressionRule] = {}
        self._lock = threading.RLock()

    def add(self, rule: SuppressionRule) -> SuppressionRule:
        if not rule.created_at:
            rule.created_at = time.time()
        with self._lock:
            self._rules[rule.rule_id] = rule
        _log.info("suppression rule added: %s (%s)", rule.rule_id, rule.match)
        return rule

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def get(self, rule_id: str) -> Optional[SuppressionRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def set_enabled(self, rule_id: str, enabled: bool) -> Optional[SuppressionRule]:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is not None:
                rule.enabled = enabled
            return rule

    def list(self, *, include_expired: bool = True) -> List[SuppressionRule]:
        now = time.time()
        with self._lock:
            rules = list(self._rules.values())
        if not include_expired:
            rules = [r for r in rules if not r.is_expired(now)]
        rules.sort(key=lambda r: r.created_at, reverse=True)
        return rules

    def prune_expired(self, now: Optional[float] = None) -> int:
        """Drop expired rules. Returns the number removed."""
        now = time.time() if now is None else now
        with self._lock:
            expired = [rid for rid, r in self._rules.items() if r.is_expired(now)]
            for rid in expired:
                self._rules.pop(rid, None)
        if expired:
            _log.info("pruned %d expired suppression rule(s)", len(expired))
        return len(expired)

    def match(self, detection: Detection, *, now: Optional[float] = None) -> Optional[SuppressionRule]:
        """Return the first enabled, unexpired rule that matches, or ``None``.

        Bumps the matched rule's ``hit_count`` as a side effect so the
        store doubles as suppression telemetry.
        """
        now = time.time() if now is None else now
        with self._lock:
            # Newest rules first so a fresh, targeted maintenance-window
            # rule wins over an older broad one with the same effect.
            for rule in sorted(self._rules.values(), key=lambda r: r.created_at, reverse=True):
                if not rule.enabled or rule.is_expired(now):
                    continue
                if rule.matches(detection):
                    rule.hit_count += 1
                    return rule
        return None

    def __len__(self) -> int:
        return len(self._rules)

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            rules = list(self._rules.values())
        active = [r for r in rules if r.enabled and not r.is_expired(now)]
        return {
            "total": len(rules),
            "active": len(active),
            "expired": sum(1 for r in rules if r.is_expired(now)),
            "disabled": sum(1 for r in rules if not r.enabled),
            "total_hits": sum(r.hit_count for r in rules),
        }

    def export_json(self, path: str | Path) -> int:
        with self._lock:
            data = [r.to_dict() for r in self._rules.values()]
        Path(path).write_text(json.dumps({"suppression_rules": data}, indent=2))
        return len(data)

    def load_json(self, path: str | Path) -> int:
        raw = json.loads(Path(path).read_text())
        rules = raw.get("suppression_rules", raw) if isinstance(raw, dict) else raw
        loaded = 0
        for entry in rules:
            try:
                self.add(SuppressionRule.from_dict(entry))
                loaded += 1
            except (KeyError, ValueError) as exc:
                _log.warning("skipping invalid suppression rule: %s", exc)
        return loaded
