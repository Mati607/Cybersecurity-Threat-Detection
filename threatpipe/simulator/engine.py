"""Run scenarios through the live pipeline or in fast-forward.

The engine has two modes:

* **replay** (default) — synchronously push every generated event
  through ``pipeline.run_once`` so detections, graph, incidents, and
  responses all fire exactly as they would in production. Returns a
  :class:`SimulationResult` tying each step back to the detections it
  produced.
* **live** — enqueue events onto the pipeline's queue with real
  inter-step delays, for demos against the streaming worker.

Either way the simulated clock is deterministic so coverage results
are reproducible.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set

from ..utils.logging_setup import get_logger
from ..utils.timeutil import now_epoch
from .model import Scenario, SimulationResult, StepResult

_log = get_logger(__name__)


class SimulationEngine:
    def __init__(self, pipeline: Optional[Any] = None) -> None:
        self.pipeline = pipeline

    def run(
        self,
        scenario: Scenario,
        *,
        host: str = "victim01",
        user: str = "jdoe",
        base_ts: Optional[float] = None,
        speedup: float = 0.0,
    ) -> SimulationResult:
        if self.pipeline is None:
            raise RuntimeError("SimulationEngine needs a pipeline to run a scenario")

        base_ts = base_ts if base_ts is not None else now_epoch()
        ctx: Dict[str, Any] = {
            "host": host,
            "user": user,
            "base_ts": base_ts,
            "_clock": base_ts,
            "_pid": 4000,
        }
        started = now_epoch()
        step_results: List[StepResult] = []
        emitted = 0

        for step in scenario.steps:
            ctx["_clock"] = ctx.get("_clock", base_ts) + step.delay_s
            events = step.build(ctx)
            emitted += len(events)
            event_ids = [e.event_id for e in events]

            detections = self.pipeline.run_once(events)
            by_event: Dict[str, list] = {}
            for det in detections:
                by_event.setdefault(det.event.event_id, []).append(det)

            step_detections = [d for eid in event_ids for d in by_event.get(eid, [])]
            max_score = max((d.score for d in step_detections), default=0.0)
            step_results.append(StepResult(
                step_id=step.step_id,
                name=step.name,
                technique=step.technique,
                expect_detection=step.expect_detection,
                event_ids=event_ids,
                detected=bool(step_detections),
                detection_ids=[d.event.event_id for d in step_detections],
                max_score=max_score,
            ))

            if speedup > 0:
                time.sleep(min(step.delay_s / speedup, 2.0))

        return SimulationResult(
            scenario_id=scenario.scenario_id,
            started_at=started,
            finished_at=now_epoch(),
            events_emitted=emitted,
            step_results=step_results,
        )

    def generate_events(
        self,
        scenario: Scenario,
        *,
        host: str = "victim01",
        user: str = "jdoe",
        base_ts: float = 1_700_000_000.0,
    ) -> List:
        """Produce a scenario's events without a pipeline (for tests / replay files)."""
        ctx: Dict[str, Any] = {
            "host": host, "user": user, "base_ts": base_ts,
            "_clock": base_ts, "_pid": 4000,
        }
        events = []
        for step in scenario.steps:
            ctx["_clock"] += step.delay_s
            events.extend(step.build(ctx))
        return events
