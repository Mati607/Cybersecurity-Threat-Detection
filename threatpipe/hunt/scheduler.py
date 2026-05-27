"""Background scheduler for saved hunts.

Runs each enabled hunt every ``schedule_seconds`` against the live
detection/incident stream, records stats back on the store, and
forwards any matches to a sink callable. Sinks are typically wired to
the alert pipeline or the response engine so a hunt can act as a
deferred detector.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional

from ..utils.logging_setup import get_logger
from .evaluator import HuntEvaluator
from .query import HuntQuery, HuntResult
from .store import HuntStore, SavedHunt

_log = get_logger(__name__)


RecordProvider = Callable[[SavedHunt], Iterable[Any]]
HuntSink = Callable[[SavedHunt, HuntResult], None]


class HuntScheduler:
    def __init__(
        self,
        store: HuntStore,
        provider: RecordProvider,
        *,
        sink: Optional[HuntSink] = None,
        evaluator: Optional[HuntEvaluator] = None,
        min_interval: float = 1.0,
    ) -> None:
        self.store = store
        self.provider = provider
        self.sink = sink
        self.evaluator = evaluator or HuntEvaluator()
        self.min_interval = min_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_run: Dict[str, float] = {}

    # --- lifecycle ----------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="hunt-scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # --- main loop ----------------------------------------------

    def _loop(self) -> None:
        _log.info("hunt scheduler started")
        try:
            while not self._stop.is_set():
                self._tick(time.time())
                time.sleep(self.min_interval)
        except Exception:                                  # pragma: no cover
            _log.exception("hunt scheduler crashed")
        finally:
            _log.info("hunt scheduler stopped")

    def _tick(self, now: float) -> None:
        for hunt in self.store.list(enabled_only=True):
            if hunt.schedule_seconds is None or hunt.schedule_seconds <= 0:
                continue
            last = self._last_run.get(hunt.hunt_id, 0.0)
            if now - last < hunt.schedule_seconds:
                continue
            self._last_run[hunt.hunt_id] = now
            self.run_now(hunt)

    def run_now(self, hunt: SavedHunt) -> HuntResult:
        records = self.provider(hunt)
        try:
            query = HuntQuery(hunt.query, evaluator=self.evaluator)
            result = query.run_over(records)
        except SyntaxError as exc:
            result = HuntResult(query=hunt.query, error=str(exc))
        self.store.update_stats(
            hunt.hunt_id,
            match_count=result.match_count,
            duration_ms=result.duration_ms,
            error=result.error,
        )
        if self.sink is not None and result.match_count:
            try:
                self.sink(hunt, result)
            except Exception:                              # pragma: no cover
                _log.exception("hunt sink raised")
        return result

    def run_all(self) -> List[HuntResult]:
        out: List[HuntResult] = []
        for hunt in self.store.list(enabled_only=True):
            out.append(self.run_now(hunt))
        return out
