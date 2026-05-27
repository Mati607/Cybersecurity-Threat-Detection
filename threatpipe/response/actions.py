"""Response action contract and built-in handlers.

Actions take an :class:`ActionContext` (the triggering detection or
incident plus a dict of arguments resolved from the playbook step) and
return an :class:`ActionResult`. The default catalog covers the common
SOC tradecraft - block an IP at the firewall, kill a process, isolate
a host, disable a user account, quarantine a file, snapshot the
provenance graph, post a notification, run an arbitrary shell command,
and update incident metadata.

The handlers themselves are stubs that record what they would do
through pluggable backends - we never want a misconfigured playbook to
silently reach out to production infrastructure. Operators register
real backends at startup via :meth:`BaseAction.bind_backend`; without
a backend the action runs in **dry-run** mode and the audit log still
captures the intent.
"""

from __future__ import annotations

import abc
import enum
import os
import shlex
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional

from ..detection.base import Detection
from ..ingestion.event import Event
from ..utils.logging_setup import get_logger
from ..utils.timeutil import now_epoch

_log = get_logger(__name__)


class ActionStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DRY_RUN = "dry_run"
    SKIPPED = "skipped"


@dataclass
class ActionContext:
    detection: Optional[Detection] = None
    incident: Optional[Any] = None
    args: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    playbook_id: Optional[str] = None
    step_id: Optional[str] = None
    dry_run: bool = False

    @property
    def event(self) -> Optional[Event]:
        return self.detection.event if self.detection is not None else None

    def render(self, template: str) -> str:
        """Tiny placeholder substitution for ``{event.host}`` style args."""
        if not template or "{" not in template:
            return template
        scope: Dict[str, Any] = dict(self.args)
        if self.event is not None:
            scope["event"] = _EventView(self.event)
        if self.detection is not None:
            scope["detection"] = _DetectionView(self.detection)
        if self.incident is not None:
            scope["incident"] = self.incident
        try:
            return template.format(**scope)
        except (KeyError, IndexError, AttributeError):
            return template


@dataclass
class ActionResult:
    action: str
    status: ActionStatus
    started_at: float
    finished_at: float
    detail: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        return max(0.0, (self.finished_at - self.started_at) * 1000.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": round(self.duration_ms, 2),
            "detail": self.detail,
            "metadata": dict(self.metadata),
        }


Action = ActionResult  # alias commonly used in callers


class BaseAction(abc.ABC):
    name: str = "base"
    description: str = ""
    destructive: bool = False

    _backends: Dict[str, Callable[..., Any]] = {}

    @classmethod
    def bind_backend(cls, name: str, fn: Callable[..., Any]) -> None:
        cls._backends[name] = fn

    @classmethod
    def get_backend(cls, name: str) -> Optional[Callable[..., Any]]:
        return cls._backends.get(name)

    @abc.abstractmethod
    def execute(self, ctx: ActionContext) -> ActionResult:
        ...

    def __call__(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        try:
            result = self.execute(ctx)
            return result
        except Exception as exc:                            # pragma: no cover
            _log.exception("action %s crashed", self.name)
            return ActionResult(
                action=self.name,
                status=ActionStatus.FAILURE,
                started_at=started,
                finished_at=now_epoch(),
                detail=f"crashed: {exc}",
            )


# --- light-weight value views for templating ----------------------

class _EventView:
    """Read-only attribute proxy for safe template formatting."""

    def __init__(self, event: Event) -> None:
        self._event = event

    def __getattr__(self, item: str) -> Any:
        return getattr(self._event, item, "")

    def __format__(self, _: str) -> str:
        return str(self._event.to_dict())


class _DetectionView:
    def __init__(self, detection: Detection) -> None:
        self._d = detection

    @property
    def score(self) -> float:
        return self._d.score

    @property
    def severity(self) -> str:
        return self._d.severity.value

    @property
    def detector(self) -> str:
        return self._d.detector

    @property
    def reasons(self) -> str:
        return "; ".join(self._d.reasons[:3])


# --- built-in actions ---------------------------------------------

def _finish(action: str, ctx: ActionContext, status: ActionStatus, detail: str, **metadata: Any) -> ActionResult:
    return ActionResult(
        action=action,
        status=status,
        started_at=metadata.pop("_started", now_epoch()),
        finished_at=now_epoch(),
        detail=detail,
        metadata={k: v for k, v in metadata.items() if not k.startswith("_")},
    )


class BlockIPAction(BaseAction):
    name = "block_ip"
    description = "Block an IP address at the configured firewall backend"
    destructive = True

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        ip = ctx.args.get("ip") or (ctx.event.dst_ip if ctx.event else None)
        if not ip:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "no ip in args or event", _started=started)
        backend = self.get_backend("firewall")
        if ctx.dry_run or backend is None:
            _log.info("DRY-RUN block_ip %s", ip)
            return _finish(self.name, ctx, ActionStatus.DRY_RUN, f"would block ip {ip}",
                           ip=ip, _started=started)
        try:
            backend(ip)
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, f"backend error: {exc}",
                           ip=ip, _started=started)
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"blocked ip {ip}",
                       ip=ip, _started=started)


class IsolateHostAction(BaseAction):
    name = "isolate_host"
    description = "Isolate a host at the EDR / network backend"
    destructive = True

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        host = ctx.args.get("host") or (ctx.event.host if ctx.event else None)
        if not host:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "no host", _started=started)
        backend = self.get_backend("edr")
        if ctx.dry_run or backend is None:
            return _finish(self.name, ctx, ActionStatus.DRY_RUN, f"would isolate host {host}",
                           host=host, _started=started)
        try:
            backend(host)
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, f"backend error: {exc}",
                           host=host, _started=started)
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"isolated host {host}",
                       host=host, _started=started)


class KillProcessAction(BaseAction):
    name = "kill_process"
    description = "Terminate a process on a host via the EDR backend"
    destructive = True

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        host = ctx.args.get("host") or (ctx.event.host if ctx.event else None)
        pid = ctx.args.get("pid") or (ctx.event.pid if ctx.event else None)
        if not host or pid is None:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "missing host or pid", _started=started)
        backend = self.get_backend("edr")
        if ctx.dry_run or backend is None:
            return _finish(self.name, ctx, ActionStatus.DRY_RUN, f"would kill pid {pid} on {host}",
                           host=host, pid=pid, _started=started)
        try:
            backend(host, int(pid))
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, str(exc), _started=started)
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"killed pid {pid} on {host}",
                       host=host, pid=pid, _started=started)


class QuarantineFileAction(BaseAction):
    name = "quarantine_file"
    description = "Move a file to the quarantine path"
    destructive = True

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        path = ctx.args.get("path") or (ctx.event.file_path if ctx.event else None)
        host = ctx.args.get("host") or (ctx.event.host if ctx.event else None)
        if not path:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "no file path", _started=started)
        backend = self.get_backend("edr")
        if ctx.dry_run or backend is None:
            return _finish(self.name, ctx, ActionStatus.DRY_RUN, f"would quarantine {path} on {host}",
                           path=path, host=host, _started=started)
        try:
            backend(host, path)
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, str(exc), _started=started)
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"quarantined {path} on {host}",
                       path=path, host=host, _started=started)


class DisableUserAction(BaseAction):
    name = "disable_user"
    description = "Disable a user account at the identity provider"
    destructive = True

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        user = ctx.args.get("user") or (ctx.event.user if ctx.event else None)
        if not user:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "no user", _started=started)
        backend = self.get_backend("idp")
        if ctx.dry_run or backend is None:
            return _finish(self.name, ctx, ActionStatus.DRY_RUN, f"would disable user {user}",
                           user=user, _started=started)
        try:
            backend(user)
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, str(exc), _started=started)
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"disabled user {user}",
                       user=user, _started=started)


class SnapshotGraphAction(BaseAction):
    name = "snapshot_graph"
    description = "Persist the current provenance graph to a pickle file"

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        path = ctx.args.get("path", "graph-snapshot.pkl")
        graph = ctx.metadata.get("graph")
        if graph is None:
            return _finish(self.name, ctx, ActionStatus.SKIPPED,
                           "no graph wired into context", _started=started)
        if ctx.dry_run:
            return _finish(self.name, ctx, ActionStatus.DRY_RUN,
                           f"would snapshot graph to {path}", path=path, _started=started)
        try:
            graph.save(path)
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, str(exc), _started=started)
        return _finish(self.name, ctx, ActionStatus.SUCCESS,
                       f"snapshot written to {path}", path=path, _started=started)


class NotifyAction(BaseAction):
    name = "notify"
    description = "Forward a templated message to a notification backend"

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        message = ctx.render(ctx.args.get("message", "threatpipe alert"))
        channel = ctx.args.get("channel", "ops")
        backend = self.get_backend("notify")
        if ctx.dry_run or backend is None:
            return _finish(self.name, ctx, ActionStatus.DRY_RUN, f"would notify {channel}: {message}",
                           channel=channel, message=message, _started=started)
        try:
            backend(channel, message)
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, str(exc), _started=started)
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"notified {channel}",
                       channel=channel, _started=started)


class ShellAction(BaseAction):
    name = "shell"
    description = "Run an explicitly allow-listed shell command"
    destructive = True

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        cmd = ctx.render(ctx.args.get("cmd", ""))
        if not cmd:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "no command", _started=started)
        allow_list = self.get_backend("shell_allow")
        if allow_list is None or not allow_list(cmd):
            return _finish(self.name, ctx, ActionStatus.SKIPPED,
                           "command not in allow list", _started=started)
        if ctx.dry_run:
            return _finish(self.name, ctx, ActionStatus.DRY_RUN, f"would run: {cmd}", _started=started)
        try:
            result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=10)
        except Exception as exc:                            # pragma: no cover
            return _finish(self.name, ctx, ActionStatus.FAILURE, str(exc), _started=started)
        status = ActionStatus.SUCCESS if result.returncode == 0 else ActionStatus.FAILURE
        return _finish(self.name, ctx, status,
                       f"rc={result.returncode} stdout={result.stdout[:200]!r}",
                       _started=started)


class TagIncidentAction(BaseAction):
    name = "tag_incident"
    description = "Attach a tag to the triggering incident"

    def execute(self, ctx: ActionContext) -> ActionResult:
        started = now_epoch()
        tag = ctx.args.get("tag")
        if not tag or ctx.incident is None:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "no tag or incident", _started=started)
        if hasattr(ctx.incident, "tags"):
            ctx.incident.tags.add(str(tag))
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"tagged with {tag}",
                       tag=tag, _started=started)


class UpdateIncidentStatusAction(BaseAction):
    name = "update_incident_status"
    description = "Move the incident to a new status"

    def execute(self, ctx: ActionContext) -> ActionResult:
        from ..incidents.model import IncidentStatus
        started = now_epoch()
        status_raw = ctx.args.get("status")
        if not status_raw or ctx.incident is None:
            return _finish(self.name, ctx, ActionStatus.SKIPPED, "missing status or incident",
                           _started=started)
        try:
            new_status = IncidentStatus(status_raw)
        except ValueError:
            return _finish(self.name, ctx, ActionStatus.FAILURE, f"unknown status: {status_raw}",
                           _started=started)
        ctx.incident.status = new_status
        return _finish(self.name, ctx, ActionStatus.SUCCESS, f"status -> {new_status.value}",
                       _started=started)


DEFAULT_ACTIONS: Dict[str, BaseAction] = {
    cls.name: cls() for cls in (
        BlockIPAction,
        IsolateHostAction,
        KillProcessAction,
        QuarantineFileAction,
        DisableUserAction,
        SnapshotGraphAction,
        NotifyAction,
        ShellAction,
        TagIncidentAction,
        UpdateIncidentStatusAction,
    )
}
