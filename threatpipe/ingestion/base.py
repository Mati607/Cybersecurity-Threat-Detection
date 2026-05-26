"""Abstract source contract and a small thread-safe event queue.

Sources push :class:`Event` objects into an :class:`EventQueue`; the
pipeline driver pops them in batches and hands them to the detectors.
The queue exposes only the operations we actually need so test stubs
can mimic it cheaply.
"""

from __future__ import annotations

import abc
import queue
import threading
from typing import Iterable, Iterator, List, Optional

from ..utils.logging_setup import get_logger
from .event import Event

_log = get_logger(__name__)


class EventQueue:
    def __init__(self, maxsize: int = 10_000):
        self._q: "queue.Queue[Event]" = queue.Queue(maxsize=maxsize)
        self._dropped = 0
        self._lock = threading.Lock()

    def put(self, event: Event, timeout: Optional[float] = None) -> bool:
        try:
            self._q.put(event, timeout=timeout)
            return True
        except queue.Full:
            with self._lock:
                self._dropped += 1
            if self._dropped % 1000 == 1:
                _log.warning("event queue full; dropped=%d", self._dropped)
            return False

    def get_batch(self, max_items: int, timeout: float = 0.25) -> List[Event]:
        out: List[Event] = []
        try:
            first = self._q.get(timeout=timeout)
            out.append(first)
        except queue.Empty:
            return out
        while len(out) < max_items:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        return out

    @property
    def dropped(self) -> int:
        return self._dropped

    def __len__(self) -> int:
        return self._q.qsize()


class BaseSource(abc.ABC):
    """Base class for ingestion sources.

    Concrete sources implement :meth:`_iter_events`, which yields events
    until the source is exhausted or :attr:`_stop` is set. ``run`` wires
    them into an :class:`EventQueue` from a background thread.
    """

    name = "base"

    def __init__(self, queue: EventQueue) -> None:
        self._queue = queue
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @abc.abstractmethod
    def _iter_events(self) -> Iterator[Event]:
        ...

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name=f"src-{self.name}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        _log.info("starting source: %s", self.name)
        try:
            for ev in self._iter_events():
                if self._stop.is_set():
                    break
                self._queue.put(ev, timeout=1.0)
        except Exception:  # pragma: no cover - background thread guard
            _log.exception("source %s crashed", self.name)
        finally:
            _log.info("source %s stopped", self.name)

    def drain(self) -> Iterable[Event]:
        """Synchronously yield events without spawning a thread.

        Useful for batch processing files in tests and the CLI ``replay``
        sub-command.
        """
        yield from self._iter_events()
