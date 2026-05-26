"""Event normalization layer.

Parsers produce :class:`Event` objects directly from their wire format,
but the values often need a second pass before they're useful to a
detector: lowercasing categorical fields, stripping ANSI codes, mapping
common synonyms ("EXEC" -> "exec", "Login" -> "login"), and folding
high-cardinality numeric fields into log-scale buckets so the
statistical detector doesn't blow up its histograms.

This is deliberately kept stateless — every method is a pure function
of an event — so the same normalizer can be shared by multiple worker
threads.
"""

from __future__ import annotations

import re
from typing import Optional

from .event import Event

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_ACTION_ALIASES = {
    "exec": "exec",
    "execve": "exec",
    "fork": "fork",
    "clone": "fork",
    "open": "open",
    "openat": "open",
    "read": "read",
    "write": "write",
    "send": "send",
    "recv": "recv",
    "login": "login",
    "logon": "login",
    "logoff": "logout",
    "logout": "logout",
    "auth": "auth",
    "connect": "connect",
    "accept": "accept",
    "kill": "kill",
}
_PROTOCOL_ALIASES = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
}


class Normalizer:
    def __init__(self, *, lowercase: bool = True) -> None:
        self.lowercase = lowercase

    def __call__(self, event: Event) -> Event:
        if event.message:
            event.message = _ANSI_RE.sub("", event.message).strip()

        if event.action:
            a = event.action.lower()
            event.action = _ACTION_ALIASES.get(a, a)

        if event.protocol:
            p = str(event.protocol).lower()
            event.protocol = _PROTOCOL_ALIASES.get(p, p)

        if self.lowercase:
            if event.user:
                event.user = str(event.user).lower()
            if event.host:
                event.host = str(event.host).lower()

        if event.process:
            event.process = _strip_path(event.process)

        if event.severity:
            event.severity = self._normalize_severity(event.severity)

        return event

    @staticmethod
    def _normalize_severity(value) -> str:
        try:
            num = int(value)
        except (TypeError, ValueError):
            return str(value).lower()
        if num <= 2:
            return "low"
        if num <= 5:
            return "medium"
        if num <= 7:
            return "high"
        return "critical"


def _strip_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return path
    # keep the executable name, drop "C:\Windows\System32\" or "/usr/bin/"
    path = path.replace("\\", "/")
    return path.rsplit("/", 1)[-1]
