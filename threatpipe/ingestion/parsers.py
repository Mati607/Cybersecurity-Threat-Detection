"""Line-oriented parsers for common log formats.

The detection layer needs structured events, but in the real world we
get a soup of plain JSON, syslog, auditd, and CEF lines mixed together.
:func:`detect_format` sniffs the first non-empty line of each batch and
:func:`parse_line` then dispatches to the right parser.

The parsers are intentionally permissive: a failed parse returns ``None``
and the caller is responsible for emitting an "unknown" event so we
never lose volume metrics for malformed input.
"""

from __future__ import annotations

import abc
import json
import re
from typing import Any, Dict, Optional

from ..utils.logging_setup import get_logger
from ..utils.timeutil import parse_timestamp
from .event import Event, EventType

_log = get_logger(__name__)


# --- format detection -------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_AUDITD_RE = re.compile(r"^type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<ts>[\d.]+):(?P<id>\d+)\):(?P<rest>.*)$")
_CEF_RE = re.compile(r"^CEF:(?P<ver>\d+)\|(?P<rest>.*)$")
_KV_RE = re.compile(r"(?P<k>[A-Za-z_][\w\.\-]*)=(?:\"(?P<qv>[^\"]*)\"|(?P<v>\S+))")


def detect_format(line: str) -> str:
    s = line.lstrip()
    if not s:
        return "unknown"
    if s.startswith("{") and s.rstrip().endswith("}"):
        return "json"
    if s.startswith("CEF:"):
        return "cef"
    if s.startswith("type=") and "msg=audit(" in s:
        return "auditd"
    if _SYSLOG_RE.match(s):
        return "syslog"
    return "unknown"


# --- base -------------------------------------------------------------

class BaseParser(abc.ABC):
    format: str = "unknown"

    @abc.abstractmethod
    def parse(self, line: str) -> Optional[Event]:
        ...

    def _kv(self, blob: str) -> Dict[str, str]:
        return {
            m.group("k"): m.group("qv") if m.group("qv") is not None else m.group("v")
            for m in _KV_RE.finditer(blob)
        }


# --- JSON -------------------------------------------------------------

class JSONParser(BaseParser):
    format = "json"

    _FIELD_ALIASES = {
        "timestamp": ("@timestamp", "ts", "time", "eventTime", "EventTime"),
        "host": ("hostname", "host.name", "computer", "HostName"),
        "user": ("user.name", "username", "user", "TargetUserName"),
        "process": ("process.name", "image", "Image", "comm"),
        "pid": ("process.pid", "ProcessId"),
        "parent_pid": ("process.parent.pid", "ParentProcessId", "ppid"),
        "command_line": ("process.command_line", "CommandLine", "cmd", "cmdline"),
        "src_ip": ("source.ip", "src", "src_ip", "SourceIp"),
        "dst_ip": ("destination.ip", "dst", "dst_ip", "DestinationIp"),
        "src_port": ("source.port", "src_port", "SourcePort"),
        "dst_port": ("destination.port", "dst_port", "DestinationPort"),
        "protocol": ("network.protocol", "proto", "Protocol"),
        "file_path": ("file.path", "path", "TargetFilename"),
        "action": ("event.action", "action", "EventName"),
        "status": ("event.outcome", "status", "result"),
        "bytes_sent": ("source.bytes", "bytes_out"),
        "bytes_recv": ("destination.bytes", "bytes_in"),
        "message": ("message", "msg"),
        "severity": ("event.severity", "severity", "level"),
    }

    def parse(self, line: str) -> Optional[Event]:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        return _event_from_aliased(data, self._FIELD_ALIASES, source="json")


def _resolve_alias(data: Dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data:
            return data[key]
        if "." in key:
            cur: Any = data
            ok = True
            for part in key.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    ok = False
                    break
            if ok:
                return cur
    return None


def _event_from_aliased(
    data: Dict[str, Any],
    aliases: Dict[str, tuple[str, ...]],
    *,
    source: str,
) -> Event:
    kwargs: Dict[str, Any] = {"raw": data, "source": source}
    for field_name, keys in aliases.items():
        value = _resolve_alias(data, keys)
        if value is not None:
            kwargs[field_name] = value

    ts = kwargs.pop("timestamp", None)
    if ts is not None:
        kwargs["timestamp"] = parse_timestamp(ts)

    for int_field in ("pid", "parent_pid", "src_port", "dst_port", "bytes_sent", "bytes_recv"):
        if int_field in kwargs:
            try:
                kwargs[int_field] = int(kwargs[int_field])
            except (TypeError, ValueError):
                kwargs.pop(int_field)

    kwargs["event_type"] = _classify(data, kwargs)
    return Event(**kwargs)


def _classify(data: Dict[str, Any], kw: Dict[str, Any]) -> EventType:
    cat = (data.get("event") or {}).get("category") if isinstance(data.get("event"), dict) else None
    hint = (cat or data.get("category") or data.get("type") or "").lower() if isinstance(cat or data.get("category") or data.get("type") or "", str) else ""

    if "process" in hint or kw.get("process") or kw.get("command_line"):
        return EventType.PROCESS
    if "network" in hint or kw.get("src_ip") or kw.get("dst_ip"):
        return EventType.NETWORK
    if "file" in hint or kw.get("file_path"):
        return EventType.FILE
    if "auth" in hint or kw.get("action") in ("login", "logout", "auth"):
        return EventType.AUTH
    if "audit" in hint:
        return EventType.AUDIT
    return EventType.UNKNOWN


# --- syslog -----------------------------------------------------------

class SyslogParser(BaseParser):
    format = "syslog"

    def parse(self, line: str) -> Optional[Event]:
        m = _SYSLOG_RE.match(line.strip())
        if not m:
            return None
        return Event(
            timestamp=parse_timestamp(m.group("ts")),
            host=m.group("host"),
            process=m.group("tag"),
            pid=int(m.group("pid")) if m.group("pid") else None,
            message=m.group("msg"),
            event_type=EventType.AUDIT,
            source="syslog",
            raw={"line": line, "pri": int(m.group("pri"))},
        )


# --- auditd -----------------------------------------------------------

class AuditdParser(BaseParser):
    format = "auditd"

    def parse(self, line: str) -> Optional[Event]:
        m = _AUDITD_RE.match(line.strip())
        if not m:
            return None
        kv = self._kv(m.group("rest"))
        return Event(
            timestamp=parse_timestamp(m.group("ts")),
            user=kv.get("uid") or kv.get("auid"),
            process=kv.get("comm") or kv.get("exe"),
            pid=int(kv["pid"]) if kv.get("pid", "").isdigit() else None,
            parent_pid=int(kv["ppid"]) if kv.get("ppid", "").isdigit() else None,
            command_line=kv.get("cmd"),
            action=kv.get("op") or m.group("type").lower(),
            event_type=EventType.SYSCALL if m.group("type") == "SYSCALL" else EventType.AUDIT,
            file_path=kv.get("name") or kv.get("path"),
            source="auditd",
            raw={"type": m.group("type"), **kv},
        )


# --- CEF --------------------------------------------------------------

class CEFParser(BaseParser):
    format = "cef"

    def parse(self, line: str) -> Optional[Event]:
        m = _CEF_RE.match(line.strip())
        if not m:
            return None
        parts = m.group("rest").split("|")
        if len(parts) < 6:
            return None
        vendor, product, ver, sig_id, sig_name, severity, *extension = parts
        ext = self._kv(extension[0] if extension else "")
        return Event(
            timestamp=parse_timestamp(ext.get("rt") or ext.get("start")),
            host=ext.get("dvchost"),
            src_ip=ext.get("src"),
            dst_ip=ext.get("dst"),
            src_port=int(ext["spt"]) if ext.get("spt", "").isdigit() else None,
            dst_port=int(ext["dpt"]) if ext.get("dpt", "").isdigit() else None,
            user=ext.get("suser") or ext.get("duser"),
            action=sig_name,
            severity=severity,
            message=sig_name,
            event_type=EventType.NETWORK if ext.get("src") or ext.get("dst") else EventType.AUDIT,
            source=f"cef:{vendor}:{product}",
            raw={"vendor": vendor, "product": product, "version": ver, "sig": sig_id, **ext},
        )


# --- dispatch ---------------------------------------------------------

_PARSERS: Dict[str, BaseParser] = {
    "json": JSONParser(),
    "syslog": SyslogParser(),
    "auditd": AuditdParser(),
    "cef": CEFParser(),
}


def parse_line(line: str, fmt: Optional[str] = None) -> Optional[Event]:
    if not line.strip():
        return None
    use = fmt or detect_format(line)
    parser = _PARSERS.get(use)
    if parser is None:
        return Event(message=line.strip(), source="raw", raw={"line": line})
    try:
        return parser.parse(line)
    except Exception:  # pragma: no cover - defensive: never crash ingestion
        _log.exception("parser %s failed on line: %s", use, line[:200])
        return None
