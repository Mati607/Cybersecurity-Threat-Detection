"""Generic HTTP webhook alert sink.

We deliberately stick to ``urllib`` so the package has zero hard
dependencies for delivery; if requests is available, callers can plug
their own sink in instead.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Dict, Optional

from ..detection.base import Detection
from ..utils.logging_setup import get_logger
from .base import AlertSink

_log = get_logger(__name__)


class WebhookSink(AlertSink):
    name = "webhook"

    def __init__(
        self,
        url: str,
        timeout: float = 5.0,
        headers: Optional[Dict[str, str]] = None,
        verify_tls: bool = True,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self._ctx: Optional[ssl.SSLContext] = None
        if not verify_tls:
            self._ctx = ssl._create_unverified_context()

    def emit(self, detection: Detection) -> None:
        payload = json.dumps(detection.to_dict(), default=str).encode("utf-8")
        req = urllib.request.Request(self.url, data=payload, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                if resp.status >= 400:
                    _log.warning("webhook %s -> HTTP %s", self.url, resp.status)
        except (urllib.error.URLError, TimeoutError) as exc:
            _log.warning("webhook %s failed: %s", self.url, exc)
