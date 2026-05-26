"""UDP syslog ingestion.

Listens on RFC-3164 (BSD) and RFC-5424 syslog messages on a UDP port
and forwards them through the standard parser pipeline. We do not
implement TCP/TLS here — those should run behind a sidecar (e.g.
``rsyslog`` or ``vector``) in production deployments.
"""

from __future__ import annotations

import socket
from typing import Iterator, Optional

from ..utils.logging_setup import get_logger
from .base import BaseSource
from .event import Event
from .normalizer import Normalizer
from .parsers import parse_line

_log = get_logger(__name__)


class SyslogSource(BaseSource):
    name = "syslog"

    def __init__(
        self,
        queue,
        host: str = "0.0.0.0",
        port: int = 5514,
        recv_buffer: int = 65535,
        normalizer: Optional[Normalizer] = None,
    ) -> None:
        super().__init__(queue)
        self.host = host
        self.port = port
        self.recv_buffer = recv_buffer
        self._normalizer = normalizer or Normalizer()
        self._sock: Optional[socket.socket] = None

    def _iter_events(self) -> Iterator[Event]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        _log.info("syslog listening on %s:%d/udp", self.host, self.port)

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(self.recv_buffer)
                except socket.timeout:
                    continue
                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                event = parse_line(line)
                if event is None:
                    continue
                if event.host is None:
                    event.host = addr[0]
                yield self._normalizer(event)
        finally:
            sock.close()
            self._sock = None

    def stop(self, timeout: float = 5.0) -> None:
        super().stop(timeout=timeout)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
