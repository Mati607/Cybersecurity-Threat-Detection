"""Assemble the alert chain described by an :class:`AlertConfig`."""

from __future__ import annotations

from typing import List

from ..detection.base import Severity
from ..utils.config import AlertConfig
from ..utils.logging_setup import get_logger
from .base import AlertSink, MultiSink, NullSink, RateLimitedSink, SeverityFilterSink
from .stdout_sink import StdoutSink
from .file_sink import FileSink
from .webhook_sink import WebhookSink
from .slack_sink import SlackSink
from .email_sink import EmailSink

_log = get_logger(__name__)


def build_alert_sink(config: AlertConfig) -> AlertSink:
    sinks: List[AlertSink] = []
    for channel in config.channels:
        channel = channel.lower().strip()
        if channel in ("stdout", "console"):
            sinks.append(StdoutSink())
        elif channel.startswith("file:"):
            sinks.append(FileSink(path=channel.split(":", 1)[1]))
        elif channel == "webhook":
            if not config.webhook_url:
                _log.warning("webhook channel requested but no webhook_url configured")
                continue
            sinks.append(WebhookSink(url=config.webhook_url))
        elif channel == "slack":
            if not (config.slack_token and config.slack_channel):
                _log.warning("slack channel requested but missing token or channel")
                continue
            sinks.append(SlackSink(token=config.slack_token, channel=config.slack_channel))
        elif channel == "email":
            if not (config.email_smtp_host and config.email_from and config.email_to):
                _log.warning("email channel requested but SMTP settings incomplete")
                continue
            sinks.append(EmailSink(
                smtp_host=config.email_smtp_host,
                smtp_port=config.email_smtp_port,
                sender=config.email_from,
                recipients=config.email_to,
            ))
        elif channel in ("null", "discard"):
            sinks.append(NullSink())
        else:
            _log.warning("unknown alert channel: %s", channel)

    if not sinks:
        sinks.append(NullSink())

    combined: AlertSink = sinks[0] if len(sinks) == 1 else MultiSink(sinks)
    try:
        min_severity = Severity(config.min_severity.lower())
    except (AttributeError, ValueError):
        min_severity = Severity.MEDIUM
    combined = SeverityFilterSink(combined, min_severity=min_severity)
    if config.rate_limit_per_min > 0:
        combined = RateLimitedSink(combined, per_minute=config.rate_limit_per_min)
    return combined
