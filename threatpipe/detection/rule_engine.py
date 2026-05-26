"""Declarative rule engine.

Rules are defined as plain :class:`Rule` objects with a ``where`` mapping
of field name -> matcher. A matcher is one of:

* a string -> exact (case-insensitive) match
* a compiled regex pattern -> ``re.search`` is applied
* a callable ``Event -> bool`` -> arbitrary predicate
* a sequence -> set-containment (event field must be one of the values)
* a tuple ``(op, value)`` with op in ``>``, ``>=``, ``<``, ``<=``, ``!=``

The engine returns one detection per matching rule. The score is the
rule's static ``score`` (a float in ``[0, 1]``), so rules can encode the
operator's confidence directly. We default-load a small catalog of
"common attacker tradecraft" rules so the pipeline produces output out
of the box; users can supply their own catalog via JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Union

from ..ingestion.event import Event, EventType
from ..utils.logging_setup import get_logger
from .base import BaseDetector, Detection, Severity

_log = get_logger(__name__)

Matcher = Union[str, re.Pattern, Sequence, Callable[[Event], bool], tuple]


@dataclass
class Rule:
    id: str
    name: str
    description: str = ""
    score: float = 0.7
    severity: Severity = Severity.MEDIUM
    where: Dict[str, Matcher] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def matches(self, event: Event) -> bool:
        for field_name, matcher in self.where.items():
            value = getattr(event, field_name, None)
            if value is None:
                if callable(matcher) and not isinstance(matcher, (re.Pattern, type)):
                    if matcher(event):
                        continue
                return False
            if not _match(value, matcher, event):
                return False
        return True


def _coerce_str(value: Any) -> str:
    if hasattr(value, "value"):  # enums
        return str(value.value)
    return str(value)


def _match(value: Any, matcher: Matcher, event: Event) -> bool:
    if isinstance(matcher, re.Pattern):
        return bool(matcher.search(_coerce_str(value)))
    if isinstance(matcher, str):
        return _coerce_str(value).lower() == matcher.lower()
    if isinstance(matcher, tuple) and len(matcher) == 2 and matcher[0] in ("<", "<=", ">", ">=", "!="):
        op, target = matcher
        try:
            v = float(value)
            t = float(target)
        except (TypeError, ValueError):
            return False
        return {
            "<": v < t,
            "<=": v <= t,
            ">": v > t,
            ">=": v >= t,
            "!=": v != t,
        }[op]
    if callable(matcher):
        return bool(matcher(event))
    if isinstance(matcher, Sequence):
        s = {_coerce_str(x).lower() for x in matcher}
        return _coerce_str(value).lower() in s
    return False


class RuleEngine(BaseDetector):
    name = "rule"
    stateful = False

    def __init__(self, rules: Optional[Iterable[Rule]] = None) -> None:
        self.rules: List[Rule] = list(rules) if rules is not None else list(default_rules())

    def detect(self, event: Event) -> Optional[Detection]:
        hits: List[Rule] = [r for r in self.rules if r.matches(event)]
        if not hits:
            return None
        primary = max(hits, key=lambda r: r.score)
        return Detection(
            event=event,
            detector=self.name,
            score=min(1.0, primary.score + 0.05 * (len(hits) - 1)),
            severity=primary.severity,
            reasons=[f"{r.id}: {r.name}" for r in hits],
            tags=sorted({tag for r in hits for tag in r.tags}),
            metadata={"rule_count": len(hits), "rule_ids": [r.id for r in hits]},
        )

    @classmethod
    def from_json(cls, path: str | Path) -> "RuleEngine":
        raw = json.loads(Path(path).read_text())
        rules: List[Rule] = []
        for item in raw.get("rules", []):
            where = {}
            for k, v in (item.get("where") or {}).items():
                if isinstance(v, dict) and "regex" in v:
                    where[k] = re.compile(v["regex"], re.IGNORECASE)
                elif isinstance(v, dict) and "op" in v:
                    where[k] = (v["op"], v["value"])
                else:
                    where[k] = v
            rules.append(Rule(
                id=item["id"],
                name=item["name"],
                description=item.get("description", ""),
                score=float(item.get("score", 0.7)),
                severity=Severity(item.get("severity", "medium")),
                where=where,
                tags=list(item.get("tags", [])),
            ))
        _log.info("loaded %d rules from %s", len(rules), path)
        return cls(rules=rules)


# --- baseline rule catalog -------------------------------------------

def default_rules() -> Iterable[Rule]:
    """A minimal set of rules covering recognizable attacker tradecraft.

    These are intentionally generic — production deployments should
    replace them with a curated catalog (e.g. Sigma rules compiled into
    the same schema).
    """
    susp_shell = re.compile(
        r"\b(curl|wget|bash\s+-i|nc\s+-e|powershell|certutil|mshta)\b",
        re.IGNORECASE,
    )
    encoded_payload = re.compile(r"(?:base64|-enc(?:oded)?)\s+[A-Za-z0-9+/=]{40,}", re.IGNORECASE)
    suspicious_dirs = re.compile(r"(/tmp/|\\AppData\\|\\Temp\\|/dev/shm/)", re.IGNORECASE)
    privileged_path = re.compile(r"(/etc/(shadow|passwd)|\\sam\\|sysprep)", re.IGNORECASE)

    return [
        Rule(
            id="T1059.LIVING_OFF_THE_LAND",
            name="Living-off-the-land binary execution",
            description="Common LOLBins used for download/execute chains.",
            score=0.7,
            severity=Severity.MEDIUM,
            where={
                "event_type": EventType.PROCESS.value,
                "command_line": susp_shell,
            },
            tags=["mitre:T1059", "execution"],
        ),
        Rule(
            id="T1027.ENCODED_PAYLOAD",
            name="Encoded payload in command line",
            score=0.85,
            severity=Severity.HIGH,
            where={"command_line": encoded_payload},
            tags=["mitre:T1027", "defense-evasion"],
        ),
        Rule(
            id="T1055.SUSPICIOUS_PARENT",
            name="Shell spawned from Office/Browser parent",
            score=0.9,
            severity=Severity.HIGH,
            where={
                "event_type": EventType.PROCESS.value,
                "process": ("cmd.exe", "bash", "sh", "powershell.exe", "pwsh"),
                "command_line": re.compile(r".+"),
            },
            tags=["mitre:T1055"],
        ),
        Rule(
            id="T1078.ROOT_LOGIN_FAILED",
            name="Failed root/admin login",
            score=0.65,
            severity=Severity.MEDIUM,
            where={
                "message": re.compile(r"failed (login|password) for (root|admin)", re.IGNORECASE),
            },
            tags=["mitre:T1078", "credential-access"],
        ),
        Rule(
            id="T1003.SENSITIVE_FILE_READ",
            name="Sensitive credential file accessed",
            score=0.9,
            severity=Severity.HIGH,
            where={
                "event_type": EventType.FILE.value,
                "file_path": privileged_path,
            },
            tags=["mitre:T1003"],
        ),
        Rule(
            id="T1071.EXTERNAL_BEACON",
            name="Outbound connection on rare port",
            score=0.6,
            severity=Severity.MEDIUM,
            where={
                "event_type": EventType.NETWORK.value,
                "dst_port": ("not in", (80, 443, 53, 22, 3389)),
            },
            tags=["mitre:T1071"],
        ),
        Rule(
            id="T1547.STARTUP_WRITE",
            name="Write to autorun/startup location",
            score=0.8,
            severity=Severity.HIGH,
            where={
                "event_type": EventType.FILE.value,
                "action": ("write", "create"),
                "file_path": re.compile(r"(Startup|Run\\|/etc/cron|/etc/init|systemd/system)", re.IGNORECASE),
            },
            tags=["mitre:T1547", "persistence"],
        ),
        Rule(
            id="T1486.RANSOMWARE_EXT",
            name="Ransomware-style file extension write",
            score=0.95,
            severity=Severity.CRITICAL,
            where={
                "event_type": EventType.FILE.value,
                "file_path": re.compile(r"\.(locked|encrypted|crypted|crypt|wnry|cerber)$", re.IGNORECASE),
            },
            tags=["mitre:T1486", "impact"],
        ),
        Rule(
            id="HEURISTIC.LARGE_EGRESS",
            name="Large outbound transfer",
            score=0.55,
            severity=Severity.MEDIUM,
            where={
                "event_type": EventType.NETWORK.value,
                "bytes_sent": (">", 50_000_000),
            },
            tags=["exfiltration"],
        ),
        Rule(
            id="HEURISTIC.TMP_EXEC",
            name="Execution from temp/world-writable directory",
            score=0.7,
            severity=Severity.MEDIUM,
            where={
                "event_type": EventType.PROCESS.value,
                "command_line": suspicious_dirs,
            },
            tags=["execution"],
        ),
    ]


# Hook ``not in`` matcher onto the engine in a tiny shim so we don't
# bloat the main _match function. We register it lazily on import to
# keep the simple cases fast.
def _not_in(value: Any, matcher: tuple, event: Event) -> bool:
    if matcher[0] != "not in":
        return False
    return value not in set(matcher[1])


_orig_match = _match


def _match_wrapper(value: Any, matcher: Matcher, event: Event) -> bool:
    if isinstance(matcher, tuple) and len(matcher) == 2 and matcher[0] == "not in":
        return _not_in(value, matcher, event)
    return _orig_match(value, matcher, event)


# Re-bind the module-level reference used by Rule.matches.
globals()["_match"] = _match_wrapper
