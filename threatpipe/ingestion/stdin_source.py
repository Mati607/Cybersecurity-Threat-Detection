"""Stdin ingestion source.

Useful as a Unix-pipeline sink (``journalctl -f | threatpipe run --source stdin``)
and as a trivial test harness.
"""

from __future__ import annotations

import sys
from typing import Iterator, Optional

from .base import BaseSource
from .event import Event
from .normalizer import Normalizer
from .parsers import parse_line


class StdinSource(BaseSource):
    name = "stdin"

    def __init__(self, queue, normalizer: Optional[Normalizer] = None) -> None:
        super().__init__(queue)
        self._normalizer = normalizer or Normalizer()

    def _iter_events(self) -> Iterator[Event]:
        for line in sys.stdin:
            if self._stop.is_set():
                break
            ev = parse_line(line)
            if ev is None:
                continue
            yield self._normalizer(ev)
