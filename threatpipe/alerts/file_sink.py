"""JSON-lines file alert sink with rotation."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Optional

from ..detection.base import Detection
from .base import AlertSink


class FileSink(AlertSink):
    name = "file"

    def __init__(
        self,
        path: str | os.PathLike[str],
        max_bytes: int = 50 * 1024 * 1024,
        backups: int = 3,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        self._fh: Optional[object] = None
        self._open()

    def _open(self) -> None:
        self._fh = self.path.open("a", encoding="utf-8")

    def _rotate(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        for i in range(self.backups - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{i}")
            dst = self.path.with_suffix(self.path.suffix + f".{i + 1}")
            if src.exists():
                src.replace(dst)
        if self.path.exists():
            self.path.replace(self.path.with_suffix(self.path.suffix + ".1"))
        self._open()

    def emit(self, detection: Detection) -> None:
        line = json.dumps(detection.to_dict(), default=str)
        with self._lock:
            if self._fh is None:
                self._open()
            assert self._fh is not None
            self._fh.write(line)
            self._fh.write("\n")
            self._fh.flush()
            if self.path.stat().st_size > self.max_bytes:
                self._rotate()

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
