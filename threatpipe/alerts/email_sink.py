"""SMTP email alert sink."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable, List, Optional

from ..detection.base import Detection
from ..utils.logging_setup import get_logger
from ..utils.timeutil import format_iso
from .base import AlertSink

_log = get_logger(__name__)


class EmailSink(AlertSink):
    name = "email"

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        sender: str,
        recipients: Iterable[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients: List[str] = list(recipients)
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

    def emit(self, detection: Detection) -> None:
        if not self.recipients:
            return
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg["Subject"] = (
            f"[threatpipe/{detection.severity.value}] "
            f"{detection.event.host or 'unknown'} score={detection.score:.2f}"
        )
        msg.set_content(self._body(detection))

        try:
            ctx = ssl.create_default_context() if self.use_tls else None
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                if self.use_tls:
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                if self.username and self.password:
                    smtp.login(self.username, self.password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, TimeoutError, OSError) as exc:
            _log.warning("email alert failed: %s", exc)

    def _body(self, detection: Detection) -> str:
        event = detection.event
        lines = [
            f"Severity   : {detection.severity.value}",
            f"Score      : {detection.score:.3f}",
            f"Timestamp  : {format_iso(event.timestamp)}",
            f"Host       : {event.host}",
            f"User       : {event.user}",
            f"Process    : {event.process}",
            f"Command    : {event.command_line}",
            f"Source     : {event.source}",
            "",
            "Reasons:",
        ]
        lines.extend(f"  - {r}" for r in detection.reasons)
        return "\n".join(lines) + "\n"
