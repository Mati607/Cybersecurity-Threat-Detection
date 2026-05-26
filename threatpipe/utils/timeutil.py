"""Timestamp helpers.

The ingestion sources produce timestamps in several different formats:
ISO-8601 strings, epoch seconds, epoch nanoseconds (DARPA E5), and
free-form syslog dates. We normalize everything to float epoch seconds
internally and convert back to ISO-8601 only at output boundaries.
"""

from __future__ import annotations

import datetime as _dt
import re
import time
from typing import Union

Number = Union[int, float]

_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?$"
)
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})$"
)
_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}


def now_epoch() -> float:
    """Wall-clock epoch seconds with sub-second precision."""
    return time.time()


def to_epoch(value: Number) -> float:
    """Coerce a number expressed in seconds, milliseconds, microseconds
    or nanoseconds since the epoch into seconds.

    The heuristic uses the magnitude. Any value with more than 12 digits
    is treated as nanoseconds (DARPA E5 traces are in ns).
    """
    v = float(value)
    if v > 1e17:        # nanoseconds
        return v / 1e9
    if v > 1e14:        # microseconds
        return v / 1e6
    if v > 1e11:        # milliseconds
        return v / 1e3
    return v


def parse_timestamp(value: Union[str, Number, None]) -> float:
    """Parse arbitrary timestamps into epoch seconds.

    Returns the current time if the input is ``None`` or unparseable, so
    callers in the hot path never have to guard against ``KeyError``.
    """
    if value is None or value == "":
        return now_epoch()
    if isinstance(value, (int, float)):
        return to_epoch(value)

    s = str(value).strip()

    # numeric string
    if s.lstrip("-").replace(".", "", 1).isdigit():
        return to_epoch(float(s))

    if _ISO_RE.match(s):
        # python's fromisoformat doesn't grok the trailing 'Z' until 3.11
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return _dt.datetime.fromisoformat(s).timestamp()
        except ValueError:
            pass

    m = _SYSLOG_RE.match(s)
    if m:
        mon = _MONTHS.get(m.group("mon"), 1)
        day = int(m.group("day"))
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        year = _dt.datetime.utcnow().year
        return _dt.datetime(year, mon, day, hh, mm, ss).timestamp()

    return now_epoch()


def format_iso(epoch: float) -> str:
    return _dt.datetime.utcfromtimestamp(epoch).isoformat(timespec="milliseconds") + "Z"
