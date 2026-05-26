"""Slack alert sink using ``chat.postMessage`` over plain urllib.

The implementation deliberately mirrors the Slack web API contract so
the same sink works with any drop-in bot token. We format the message
as a top-line summary plus a detection-detail attachment with the
contributing detectors and their scores.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, List, Optional

from ..detection.base import Detection, Severity
from ..utils.logging_setup import get_logger
from ..utils.timeutil import format_iso
from .base import AlertSink

_log = get_logger(__name__)

_SLACK_API = "https://slack.com/api/chat.postMessage"
_COLOR = {
    Severity.LOW: "#999999",
    Severity.MEDIUM: "#f2c744",
    Severity.HIGH: "#e8631a",
    Severity.CRITICAL: "#c8262c",
}


class SlackSink(AlertSink):
    name = "slack"

    def __init__(
        self,
        token: str,
        channel: str,
        timeout: float = 5.0,
    ) -> None:
        self.token = token
        self.channel = channel
        self.timeout = timeout

    def emit(self, detection: Detection) -> None:
        body = self._format(detection)
        req = urllib.request.Request(
            _SLACK_API,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8") or "{}")
            if not payload.get("ok"):
                _log.warning("slack post failed: %s", payload.get("error"))
        except (urllib.error.URLError, TimeoutError) as exc:
            _log.warning("slack post errored: %s", exc)

    def _format(self, detection: Detection) -> Dict[str, object]:
        event = detection.event
        components = detection.metadata.get("components", [])
        fields: List[Dict[str, object]] = [
            {"title": "Host", "value": event.host or "-", "short": True},
            {"title": "User", "value": event.user or "-", "short": True},
            {"title": "Process", "value": event.process or "-", "short": True},
            {"title": "Action", "value": event.action or "-", "short": True},
        ]
        if event.dst_ip:
            fields.append({"title": "Dest", "value": f"{event.dst_ip}:{event.dst_port or '-'}", "short": True})
        if event.file_path:
            fields.append({"title": "File", "value": event.file_path, "short": True})

        return {
            "channel": self.channel,
            "text": f"*{detection.severity.value.upper()}* score {detection.score:.2f} on {event.host or '?'}",
            "attachments": [
                {
                    "color": _COLOR.get(detection.severity, "#888"),
                    "title": f"threatpipe :: {detection.severity.value} detection",
                    "ts": int(event.timestamp),
                    "fields": fields,
                    "text": "\n".join(detection.reasons[:5]) or "(no reasons)",
                    "footer": (
                        f"detectors: "
                        + ", ".join(f"{c.get('detector')}={float(c.get('score', 0)):.2f}" for c in components)
                        + f"  ·  {format_iso(event.timestamp)}"
                    ),
                }
            ],
        }
