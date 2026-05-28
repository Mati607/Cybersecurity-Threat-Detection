"""Scenario model for adversary emulation.

A :class:`Scenario` is an ordered list of :class:`ScenarioStep`s, each
of which produces one or more events when the engine runs it. Steps
carry the ATT&CK technique they emulate and an ``expect_detection``
flag so the coverage evaluator can score how much of the scenario the
detection stack actually caught.

This is the on-line analog of replaying a labelled DARPA trace: instead
of needing a multi-gigabyte capture, an analyst can run a named
scenario, watch it flow through the live pipeline, and get a coverage
report back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..ingestion.event import Event


# A step builder takes a mutable context dict (host, user, pids, base
# timestamp, ...) and returns the events it generated.
StepBuilder = Callable[[Dict[str, Any]], List[Event]]


@dataclass
class ScenarioStep:
    step_id: str
    name: str
    technique: str                     # ATT&CK technique id, e.g. T1059
    builder: StepBuilder
    description: str = ""
    expect_detection: bool = True
    delay_s: float = 1.0               # simulated gap before this step

    def build(self, ctx: Dict[str, Any]) -> List[Event]:
        return self.builder(ctx)


@dataclass
class Scenario:
    scenario_id: str
    name: str
    description: str
    steps: List[ScenarioStep]
    tactic_chain: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    @property
    def techniques(self) -> List[str]:
        seen: List[str] = []
        for step in self.steps:
            if step.technique and step.technique not in seen:
                seen.append(step.technique)
        return seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "step_count": len(self.steps),
            "techniques": self.techniques,
            "tactic_chain": list(self.tactic_chain),
            "references": list(self.references),
            "steps": [
                {
                    "step_id": s.step_id,
                    "name": s.name,
                    "technique": s.technique,
                    "description": s.description,
                    "expect_detection": s.expect_detection,
                }
                for s in self.steps
            ],
        }


@dataclass
class StepResult:
    step_id: str
    name: str
    technique: str
    expect_detection: bool
    event_ids: List[str]
    detected: bool = False
    detection_ids: List[str] = field(default_factory=list)
    max_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "technique": self.technique,
            "expect_detection": self.expect_detection,
            "event_count": len(self.event_ids),
            "detected": self.detected,
            "detection_ids": list(self.detection_ids),
            "max_score": round(self.max_score, 4),
        }


@dataclass
class SimulationResult:
    scenario_id: str
    started_at: float
    finished_at: float
    events_emitted: int
    step_results: List[StepResult] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 4),
            "events_emitted": self.events_emitted,
            "steps": [s.to_dict() for s in self.step_results],
        }
