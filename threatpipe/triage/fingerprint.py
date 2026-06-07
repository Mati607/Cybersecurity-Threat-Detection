"""Deduplication fingerprints for detections.

Two detections should collapse into the same :class:`~threatpipe.triage.model.TriagedAlert`
when an analyst would consider them "the same thing happening again." That
is rarely the same *event* — it is the same detector firing on the same
salient entity. A brute-force ``sshd`` against one host produces hundreds
of auth detections a minute; an analyst wants one alert with a count of
hundreds, not hundreds of alerts.

The fingerprint is therefore ``detector`` plus a small, event-type-aware
set of *identity fields* (the process, the destination, the file). We
deliberately exclude ``host`` so the same signature seen across the fleet
collapses into one alert that *tracks* the set of affected hosts — that
host spread is exactly the campaign signal the priority scorer rewards.
Volatile fields (pid, timestamps, byte counts, source port) are excluded
too, so re-runs of the same activity hash identically.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Sequence

from ..detection.base import Detection
from ..ingestion.event import EventType

# Per-event-type identity fields. ``detector`` is always folded in by
# :func:`fingerprint`, so these are the *additional* discriminators that
# make sense for each event class. ``host`` is intentionally absent — it
# is tracked as host spread rather than splitting the fingerprint.
DEFAULT_KEY_FIELDS: Dict[EventType, Sequence[str]] = {
    EventType.PROCESS: ("process",),
    EventType.NETWORK: ("dst_ip", "dst_port", "protocol"),
    EventType.FILE: ("file_path", "action"),
    EventType.AUTH: ("user", "status"),
    EventType.SYSCALL: ("process", "action"),
    EventType.AUDIT: ("action",),
    EventType.UNKNOWN: (),
}

# Fields folded into every fingerprint regardless of event type.
_BASE_FIELDS: Sequence[str] = ("detector",)


def key_fields_for(event_type: EventType) -> List[str]:
    """Return the identity fields used for an event type (base + specific)."""
    return list(_BASE_FIELDS) + list(DEFAULT_KEY_FIELDS.get(event_type, ()))


def fingerprint(
    detection: Detection,
    *,
    extra_fields: Optional[Sequence[str]] = None,
) -> str:
    """Compute the dedup fingerprint for ``detection``.

    ``extra_fields`` lets a caller widen the identity (e.g. add
    ``command_line`` for process events in a high-fidelity deployment)
    without rewriting the defaults. Returns a short, stable hex digest.
    """
    event = detection.event
    parts: List[str] = []
    fields = list(_BASE_FIELDS) + list(DEFAULT_KEY_FIELDS.get(event.event_type, ()))
    if extra_fields:
        fields.extend(f for f in extra_fields if f not in fields)

    for name in fields:
        if name == "detector":
            value = detection.detector
        else:
            value = getattr(event, name, None)
        parts.append(f"{name}={'' if value is None else value}")

    # event_type anchors the fingerprint so a NETWORK and a PROCESS event
    # that happen to share a host never collide on an empty discriminator.
    parts.append(f"type={event.event_type.value}")
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def describe(detection: Detection) -> str:
    """Human-readable, fingerprint-stable title for the alert.

    Mirrors the fields that go into the fingerprint so the title an
    analyst reads matches the grouping logic ("rule process activity
    process=sshd" rather than a one-off "failed login at 12:03:01").
    Host is omitted on purpose — an alert can span many hosts.
    """
    event = detection.event
    sev = detection.severity.value.title()
    bits: List[str] = []
    discriminators = DEFAULT_KEY_FIELDS.get(event.event_type, ())
    for name in discriminators:
        value = getattr(event, name, None)
        if value:
            bits.append(f"{name}={value}")
            break  # one discriminator is enough for a readable title
    tail = " ".join(bits)
    base = f"{sev}: {detection.detector} {event.event_type.value} activity"
    return f"{base} {tail}".strip()
