"""Stdout / stderr alert sink.

Pretty-prints detections in either human-readable or JSON-lines mode.
This is the default sink so the CLI is useful out of the box.
"""

from __future__ import annotations

import json
import sys
from typing import IO

from ..detection.base import Detection, Severity
from ..utils.timeutil import format_iso
from .base import AlertSink


_SEVERITY_COLOR = {
    Severity.LOW: "\033[37m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[31m",
    Severity.CRITICAL: "\033[1;41m",
}
_RESET = "\033[0m"


class StdoutSink(AlertSink):
    name = "stdout"

    def __init__(
        self,
        stream: IO[str] = sys.stdout,
        json_mode: bool = False,
        color: bool = True,
    ) -> None:
        self.stream = stream
        self.json_mode = json_mode
        self.color = color and stream.isatty()

    def emit(self, detection: Detection) -> None:
        if self.json_mode:
            self.stream.write(json.dumps(detection.to_dict(), default=str))
            self.stream.write("\n")
            self.stream.flush()
            return
        ts = format_iso(detection.event.timestamp)
        prefix = ""
        suffix = ""
        if self.color:
            prefix = _SEVERITY_COLOR.get(detection.severity, "")
            suffix = _RESET
        self.stream.write(
            f"{prefix}[{ts}] {detection.severity.value.upper():>8} "
            f"score={detection.score:.2f} host={detection.event.host or '-'} "
            f"src={detection.event.source or '-'} "
            f"reason={'; '.join(detection.reasons[:3])}{suffix}\n"
        )
        self.stream.flush()
