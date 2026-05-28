"""Event generation helpers shared by the scenario library.

These keep the scenario definitions terse: a scenario step just calls
``proc(ctx, "powershell.exe", "powershell -enc ...")`` and gets a fully
populated :class:`Event` with the host / user / pid lineage wired up
from the shared context.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..ingestion.event import Event, EventType


@dataclass
class EventTemplate:
    event_type: EventType
    fields: Dict[str, Any]

    def materialize(self, ctx: Dict[str, Any]) -> Event:
        base_ts = ctx.get("_clock", 0.0)
        kwargs = dict(self.fields)
        kwargs.setdefault("host", ctx.get("host"))
        kwargs.setdefault("user", ctx.get("user"))
        kwargs.setdefault("timestamp", base_ts)
        return Event(event_type=self.event_type, source="simulator", **kwargs)


def _advance(ctx: Dict[str, Any], seconds: float = 1.0) -> float:
    ctx["_clock"] = ctx.get("_clock", ctx.get("base_ts", 0.0)) + seconds
    return ctx["_clock"]


def _next_pid(ctx: Dict[str, Any]) -> int:
    pid = ctx.get("_pid", 1000)
    pid += 1
    ctx["_pid"] = pid
    return pid


def proc(ctx: Dict[str, Any], image: str, command_line: str, *,
         parent_pid: Optional[int] = None, advance: float = 1.0) -> Event:
    """Generate a process-execution event and track its pid as the new parent."""
    _advance(ctx, advance)
    pid = _next_pid(ctx)
    ev = Event(
        event_type=EventType.PROCESS,
        host=ctx.get("host"),
        user=ctx.get("user"),
        process=image,
        pid=pid,
        parent_pid=parent_pid if parent_pid is not None else ctx.get("_last_pid"),
        command_line=command_line,
        action="exec",
        source="simulator",
        timestamp=ctx["_clock"],
    )
    ctx["_last_pid"] = pid
    return ev


def netconn(ctx: Dict[str, Any], dst_ip: str, dst_port: int, *,
            bytes_sent: int = 0, bytes_recv: int = 0, protocol: str = "tcp",
            advance: float = 1.0) -> Event:
    _advance(ctx, advance)
    return Event(
        event_type=EventType.NETWORK,
        host=ctx.get("host"),
        user=ctx.get("user"),
        process=ctx.get("_last_image", "curl"),
        pid=ctx.get("_last_pid"),
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        action="connect",
        source="simulator",
        timestamp=ctx["_clock"],
    )


def file_event(ctx: Dict[str, Any], path: str, action: str = "write", *,
               advance: float = 0.5) -> Event:
    _advance(ctx, advance)
    return Event(
        event_type=EventType.FILE,
        host=ctx.get("host"),
        user=ctx.get("user"),
        process=ctx.get("_last_image", "bash"),
        pid=ctx.get("_last_pid"),
        file_path=path,
        action=action,
        source="simulator",
        timestamp=ctx["_clock"],
    )


def auth_event(ctx: Dict[str, Any], message: str, *, status: str = "failure",
               advance: float = 1.0) -> Event:
    _advance(ctx, advance)
    return Event(
        event_type=EventType.AUTH,
        host=ctx.get("host"),
        user=ctx.get("user"),
        action="login",
        status=status,
        message=message,
        source="simulator",
        timestamp=ctx["_clock"],
    )


def benign_background(count: int = 100, *, hosts: Optional[List[str]] = None,
                      base_ts: float = 1_700_000_000.0, seed: int = 0) -> List[Event]:
    """Generate plausible benign noise to surround a scenario.

    Useful for evaluating false-positive behavior: feed the background
    through the pipeline and confirm it produces few/no detections.
    """
    rng = random.Random(seed)
    hosts = hosts or ["web1", "web2", "db1", "workstation7"]
    # Deliberately avoid interactive-shell images (bash/sh/cmd/powershell)
    # so the baseline doesn't trip the broad "suspicious shell" rule -
    # benign noise should look like daemons doing daemon things.
    procs = ["python3", "sshd", "nginx", "postgres", "cron", "systemd", "node"]
    cmds = ["python3 app.py", "psql -c 'select 1'",
            "tail -f access.log", "nginx -g daemon off", "node server.js",
            "postgres -D /var/lib/pgsql"]
    out: List[Event] = []
    for i in range(count):
        out.append(Event(
            event_type=EventType.PROCESS,
            host=rng.choice(hosts),
            user=rng.choice(["alice", "bob", "svc_app", "root"]),
            process=rng.choice(procs),
            pid=rng.randint(100, 60000),
            command_line=rng.choice(cmds),
            action="exec",
            source="simulator-benign",
            timestamp=base_ts + i * rng.uniform(0.5, 5.0),
        ))
    return out


def jitter_timestamps(events: List[Event], *, max_jitter_s: float = 0.5, seed: int = 0) -> List[Event]:
    """Add small random offsets so simulated traffic looks less synthetic."""
    rng = random.Random(seed)
    for ev in events:
        ev.timestamp += rng.uniform(0, max_jitter_s)
    events.sort(key=lambda e: e.timestamp)
    return events
