"""Subset-of-Sigma rule importer.

`Sigma <https://github.com/SigmaHQ/sigma>`_ is the de-facto open
standard for describing detection rules in YAML. The full grammar is
expressive (correlation, aggregation, time windows, OR-of-AND
selections, etc.), but a useful subset maps cleanly onto threatpipe's
:class:`Rule` model:

* a single ``detection`` block with named selections and a boolean
  ``condition`` over them
* selections that match field equality (``CommandLine: foo``), list
  membership (``Image: [a, b]``), or ``|contains|all`` modifiers
* a static ``level`` that becomes the rule severity
* an ``id`` and ``title`` that become the rule's id / name
* ``tags`` of the form ``attack.txxxx`` mapped onto MITRE tags

Anything outside this subset raises :class:`SigmaConversionError` so
operators get a clear failure rather than a silent half-import.

We **do not** depend on PyYAML at runtime - operators can either:

* parse the YAML themselves and call :func:`sigma_to_rules` with a
  ``dict``; or
* point :class:`SigmaImporter` at a file and rely on its tiny
  internal "looks-like-YAML" parser that handles the common Sigma
  syntax (it's strict enough that anything weird in a rule will fail
  loudly).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from ..detection.base import Severity
from ..detection.rule_engine import Rule


class SigmaConversionError(ValueError):
    pass


_SEVERITY_BY_LEVEL = {
    "informational": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_SCORE_BY_LEVEL = {
    "informational": 0.4,
    "low": 0.5,
    "medium": 0.7,
    "high": 0.85,
    "critical": 0.95,
}

_FIELD_ALIASES = {
    "Image": "process",
    "ProcessName": "process",
    "ProcessImage": "process",
    "OriginalFileName": "process",
    "CommandLine": "command_line",
    "ParentImage": "parent_process",
    "ParentProcessName": "parent_process",
    "User": "user",
    "Computer": "host",
    "Hostname": "host",
    "DestinationIp": "dst_ip",
    "SourceIp": "src_ip",
    "DestinationPort": "dst_port",
    "SourcePort": "src_port",
    "DestinationHostname": "dst_ip",
    "TargetFilename": "file_path",
    "FileName": "file_path",
    "ImagePath": "file_path",
    "HashSHA256": "hash",
    "HashMD5": "hash",
    "EventID": "event_id",
}


@dataclass
class SigmaRule:
    sigma_id: str
    title: str
    detection: Dict[str, Any]
    condition: str
    level: str = "medium"
    description: str = ""
    tags: List[str] = field(default_factory=list)
    logsource: Dict[str, Any] = field(default_factory=dict)


# --- public API ------------------------------------------------------

def sigma_to_rules(doc: Mapping[str, Any] | SigmaRule) -> List[Rule]:
    if isinstance(doc, SigmaRule):
        sigma = doc
    else:
        sigma = _parse_sigma_doc(doc)
    selections, condition = sigma.detection, sigma.condition
    plan = _parse_condition(condition, set(selections))
    rules: List[Rule] = []
    severity = _SEVERITY_BY_LEVEL.get((sigma.level or "medium").lower(), Severity.MEDIUM)
    score = _SCORE_BY_LEVEL.get((sigma.level or "medium").lower(), 0.7)
    tags = _normalize_tags(sigma.tags)
    for branch_idx, branch in enumerate(plan):
        merged: Dict[str, Any] = {}
        for sel_name in branch:
            sel = selections.get(sel_name)
            if sel is None:
                raise SigmaConversionError(f"condition references unknown selection '{sel_name}'")
            _merge_selection(merged, sel)
        if not merged:
            continue
        suffix = "" if len(plan) == 1 else f"#{branch_idx + 1}"
        rules.append(Rule(
            id=f"SIGMA.{sigma.sigma_id}{suffix}",
            name=sigma.title,
            description=sigma.description,
            score=score,
            severity=severity,
            where=merged,
            tags=tags,
        ))
    return rules


class SigmaImporter:
    def __init__(self) -> None:
        self.errors: List[str] = []

    def load_file(self, path: str | Path) -> List[Rule]:
        text = Path(path).read_text(encoding="utf-8")
        docs = _split_yaml_docs(text)
        out: List[Rule] = []
        for raw in docs:
            doc = _yaml_minimal_parse(raw)
            if not doc:
                continue
            try:
                out.extend(sigma_to_rules(doc))
            except SigmaConversionError as exc:
                self.errors.append(f"{Path(path).name}: {exc}")
        return out

    def load_dir(self, path: str | Path) -> List[Rule]:
        base = Path(path)
        out: List[Rule] = []
        for f in sorted(base.rglob("*.yml")):
            out.extend(self.load_file(f))
        for f in sorted(base.rglob("*.yaml")):
            out.extend(self.load_file(f))
        return out


# --- helpers --------------------------------------------------------

def _parse_sigma_doc(doc: Mapping[str, Any]) -> SigmaRule:
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaConversionError("missing 'detection' block")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaConversionError("missing 'detection.condition'")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    return SigmaRule(
        sigma_id=str(doc.get("id") or doc.get("title") or "sigma"),
        title=str(doc.get("title", doc.get("id", "Sigma rule"))),
        detection=selections,
        condition=condition,
        level=str(doc.get("level", "medium")),
        description=str(doc.get("description", "")),
        tags=list(doc.get("tags", []) or []),
        logsource=dict(doc.get("logsource", {}) or {}),
    )


def _parse_condition(condition: str, known_selections: set[str]) -> List[List[str]]:
    """Reduce the condition string into a DNF of selection names.

    Supports ``AND``/``OR`` (case-insensitive) and parentheses; rejects
    ``not``, ``1 of``, ``all of``, etc. to keep the importer honest
    about its supported subset.
    """
    norm = condition.strip()
    norm_lower = norm.lower()
    for unsupported in (" not ", " 1 of ", " all of ", "*"):
        if unsupported in (" " + norm_lower + " "):
            raise SigmaConversionError(f"unsupported condition operator: {unsupported.strip()!r}")
    if not norm:
        raise SigmaConversionError("empty condition")
    # Quick tokenize: words, "and", "or", parens
    tokens = re.findall(r"\(|\)|\w+", norm)
    if not tokens:
        raise SigmaConversionError(f"could not tokenize condition: {condition!r}")

    pos = 0

    def parse_or() -> List[List[str]]:
        nonlocal pos
        result = parse_and()
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            result.extend(parse_and())
        return result

    def parse_and() -> List[List[str]]:
        nonlocal pos
        result = parse_atom()
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            rhs = parse_atom()
            result = [a + b for a in result for b in rhs]
        return result

    def parse_atom() -> List[List[str]]:
        nonlocal pos
        if pos >= len(tokens):
            raise SigmaConversionError("unexpected end of condition")
        tok = tokens[pos]
        if tok == "(":
            pos += 1
            inner = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise SigmaConversionError("unbalanced parentheses in condition")
            pos += 1
            return inner
        if tok.lower() in ("and", "or"):
            raise SigmaConversionError(f"unexpected boolean in condition: {tok}")
        if tok not in known_selections:
            raise SigmaConversionError(f"unknown selection '{tok}' in condition")
        pos += 1
        return [[tok]]

    plan = parse_or()
    if pos != len(tokens):
        raise SigmaConversionError(f"trailing tokens in condition near '{tokens[pos]}'")
    return plan


def _merge_selection(target: Dict[str, Any], selection: Any) -> None:
    if not isinstance(selection, dict):
        raise SigmaConversionError("selection must be a mapping")
    for raw_key, value in selection.items():
        if "|" in raw_key:
            field_name, modifier = raw_key.split("|", 1)
            target_key = _FIELD_ALIASES.get(field_name, field_name.lower())
            _merge_modifier(target, target_key, modifier, value)
        else:
            target_key = _FIELD_ALIASES.get(raw_key, raw_key.lower())
            _merge_plain(target, target_key, value)


def _merge_plain(target: Dict[str, Any], key: str, value: Any) -> None:
    if isinstance(value, list):
        target[key] = [str(v) for v in value]
    else:
        target[key] = str(value)


def _merge_modifier(target: Dict[str, Any], key: str, modifier: str, value: Any) -> None:
    parts = modifier.split("|")
    values = value if isinstance(value, list) else [value]
    values = [str(v) for v in values]

    if "all" in parts:
        # logical AND: the same field must match every regex - we OR them
        # into one regex with lookaheads.
        pattern = "".join(f"(?=.*{re.escape(v)})" for v in values)
        target[key] = re.compile(pattern, re.IGNORECASE)
        return

    if "contains" in parts:
        if len(values) == 1:
            target[key] = re.compile(re.escape(values[0]), re.IGNORECASE)
        else:
            target[key] = re.compile("|".join(re.escape(v) for v in values), re.IGNORECASE)
        return

    if "startswith" in parts:
        target[key] = re.compile("^" + "(?:" + "|".join(re.escape(v) for v in values) + ")", re.IGNORECASE)
        return

    if "endswith" in parts:
        target[key] = re.compile("(?:" + "|".join(re.escape(v) for v in values) + ")$", re.IGNORECASE)
        return

    if "re" in parts:
        target[key] = re.compile(values[0])
        return

    # Plain equality with no modifier - fall back to the same rules as _merge_plain.
    _merge_plain(target, key, value)


def _normalize_tags(tags: Iterable[str]) -> List[str]:
    out: List[str] = []
    for tag in tags:
        t = str(tag).lower().strip()
        if t.startswith("attack."):
            mitre = t.split(".", 1)[1].upper()
            out.append(f"mitre:{mitre}")
        else:
            out.append(t)
    return sorted(set(out))


# --- minimal YAML parser --------------------------------------------

def _split_yaml_docs(text: str) -> List[str]:
    docs: List[str] = []
    current: List[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            if current:
                docs.append("\n".join(current))
                current = []
            continue
        current.append(line)
    if current:
        docs.append("\n".join(current))
    return [d for d in docs if d.strip()]


_KEY_RE = re.compile(r"^(\s*)([A-Za-z][\w|.]*)\s*:\s*(.*)$")
_LIST_RE = re.compile(r"^(\s*)-\s+(.*)$")


def _strip_comment(line: str) -> str:
    in_str = False
    quote = ""
    for i, ch in enumerate(line):
        if in_str:
            if ch == quote and (i == 0 or line[i - 1] != "\\"):
                in_str = False
            continue
        if ch in ("'", '"'):
            in_str = True
            quote = ch
            continue
        if ch == "#":
            return line[:i].rstrip()
    return line.rstrip()


def _scalar(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return None
    if raw in ("null", "~"):
        return None
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part) for part in _split_flow(inner)]
    try:
        if "." in raw:
            return float(raw)
        return int(raw)
    except ValueError:
        return raw


def _split_flow(text: str) -> List[str]:
    out: List[str] = []
    depth = 0
    buf: List[str] = []
    in_str = False
    quote = ""
    for ch in text:
        if in_str:
            buf.append(ch)
            if ch == quote:
                in_str = False
            continue
        if ch in ("'", '"'):
            in_str = True
            quote = ch
            buf.append(ch)
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf).strip())
    return out


def _yaml_minimal_parse(text: str) -> Dict[str, Any]:
    """Parse the small Sigma YAML subset we actually need.

    Handles: nested mappings, list scalars (``- value``), flow-style
    lists (``[a, b]``), and inline scalars. Bombs out on the rest.
    """
    lines = [_strip_comment(line) for line in text.splitlines()]
    lines = [line for line in lines if line.strip() != ""]
    if not lines:
        return {}
    root: Dict[str, Any] = {}
    stack: List[tuple[int, Any]] = [(-1, root)]
    last_indent = -1
    last_key: Optional[str] = None

    for line in lines:
        if line.lstrip().startswith("- "):
            list_match = _LIST_RE.match(line)
            if not list_match:
                raise SigmaConversionError(f"malformed list line: {line!r}")
            indent = len(list_match.group(1))
            value = list_match.group(2).strip()
            container = stack[-1][1]
            if not isinstance(container, list):
                # promote pending key to a list
                parent_indent, parent = stack[-2] if len(stack) >= 2 else (None, None)
                if last_key is not None and isinstance(parent, dict):
                    new_list: List[Any] = []
                    parent[last_key] = new_list
                    stack.pop()
                    stack.append((indent, new_list))
                    container = new_list
                else:
                    raise SigmaConversionError("unexpected list item")
            if value.endswith(":"):
                child: Dict[str, Any] = {}
                container.append(child)
                stack.append((indent + 2, child))
                last_indent = indent + 2
                last_key = None
                continue
            container.append(_scalar(value))
            continue

        m = _KEY_RE.match(line)
        if not m:
            raise SigmaConversionError(f"unrecognized line: {line!r}")
        indent = len(m.group(1))
        key = m.group(2)
        value = m.group(3).strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise SigmaConversionError("indentation underflow")
        container = stack[-1][1]
        if isinstance(container, list):
            raise SigmaConversionError("expected mapping, got list context")
        if value == "":
            child = {}
            container[key] = child
            stack.append((indent, child))
            last_indent = indent
            last_key = key
            continue
        container[key] = _scalar(value)
        last_indent = indent
        last_key = key
    return root
