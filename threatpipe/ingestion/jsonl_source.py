"""Batch JSONL source.

Reads a single file of newline-delimited JSON once, end to end. Used
by the CLI ``replay`` sub-command and most of the tests. Unlike
:class:`FileTailSource` it does not follow the file after EOF.
"""

from __future__ import annotations

import gzip
import os
from pathlib import Path
from typing import Iterator, Optional

from ..utils.logging_setup import get_logger
from .base import BaseSource
from .event import Event
from .normalizer import Normalizer
from .parsers import parse_line

_log = get_logger(__name__)


class JSONLSource(BaseSource):
    name = "jsonl"

    def __init__(
        self,
        queue,
        path: str | os.PathLike[str],
        normalizer: Optional[Normalizer] = None,
    ) -> None:
        super().__init__(queue)
        self.path = Path(path)
        self._normalizer = normalizer or Normalizer()

    def _iter_events(self) -> Iterator[Event]:
        opener = gzip.open if self.path.suffix == ".gz" else open
        try:
            with opener(self.path, "rt", encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh):
                    if self._stop.is_set():
                        break
                    event = parse_line(line, fmt="json")
                    if event is None:
                        continue
                    yield self._normalizer(event)
        except FileNotFoundError:
            _log.error("jsonl file not found: %s", self.path)
