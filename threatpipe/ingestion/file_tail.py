"""Follow-the-file ingestion source.

Equivalent to ``tail -F`` — handles rotation by checking the file's
inode on every poll, and re-opens on truncation. This is enough for the
common case of pointing at ``/var/log/auth.log`` or a daemon's JSONL
file without pulling in inotify on Linux or kqueue on macOS.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterator, Optional

from ..utils.logging_setup import get_logger
from .base import BaseSource
from .event import Event
from .normalizer import Normalizer
from .parsers import parse_line

_log = get_logger(__name__)


class FileTailSource(BaseSource):
    name = "file"

    def __init__(
        self,
        queue,
        path: str | os.PathLike[str],
        follow: bool = True,
        poll_interval: float = 0.25,
        from_start: bool = False,
        normalizer: Optional[Normalizer] = None,
    ) -> None:
        super().__init__(queue)
        self.path = Path(path)
        self.follow = follow
        self.poll_interval = poll_interval
        self.from_start = from_start
        self._normalizer = normalizer or Normalizer()

    def _iter_events(self) -> Iterator[Event]:
        if not self.path.exists():
            _log.error("file does not exist: %s", self.path)
            return

        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            if not self.from_start:
                fh.seek(0, os.SEEK_END)
            last_inode = self._inode()

            while not self._stop.is_set():
                line = fh.readline()
                if line:
                    event = parse_line(line)
                    if event is not None:
                        yield self._normalizer(event)
                    continue

                if not self.follow:
                    break

                # No data — sleep, check for rotation.
                time.sleep(self.poll_interval)
                inode = self._inode()
                if inode is not None and inode != last_inode:
                    _log.info("detected rotation on %s; reopening", self.path)
                    fh.close()
                    fh = self.path.open("r", encoding="utf-8", errors="replace")
                    last_inode = inode

    def _inode(self) -> Optional[int]:
        try:
            return self.path.stat().st_ino
        except FileNotFoundError:
            return None
