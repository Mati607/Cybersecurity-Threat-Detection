"""Score how much of a scenario the detection stack caught.

The coverage report answers the question every detection engineer
asks after a purple-team exercise: "of the steps that were *supposed*
to be caught, how many were?" - plus the inverse, where we flag steps
that fired unexpectedly (potential false positives in the emulation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .model import Scenario, SimulationResult, StepResult


@dataclass
class CoverageReport:
    scenario_id: str
    total_steps: int
    expected_steps: int
    detected_expected: int
    missed_steps: List[str] = field(default_factory=list)
    unexpected_detections: List[str] = field(default_factory=list)
    technique_coverage: Dict[str, bool] = field(default_factory=dict)

    @property
    def coverage_fraction(self) -> float:
        if self.expected_steps == 0:
            return 1.0
        return round(self.detected_expected / self.expected_steps, 4)

    @property
    def grade(self) -> str:
        frac = self.coverage_fraction
        if frac >= 0.9:
            return "A"
        if frac >= 0.75:
            return "B"
        if frac >= 0.5:
            return "C"
        if frac > 0:
            return "D"
        return "F"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "total_steps": self.total_steps,
            "expected_steps": self.expected_steps,
            "detected_expected": self.detected_expected,
            "coverage_fraction": self.coverage_fraction,
            "grade": self.grade,
            "missed_steps": list(self.missed_steps),
            "unexpected_detections": list(self.unexpected_detections),
            "technique_coverage": dict(self.technique_coverage),
        }


def evaluate_detection_coverage(scenario: Scenario, result: SimulationResult) -> CoverageReport:
    expected = [s for s in result.step_results if s.expect_detection]
    detected_expected = [s for s in expected if s.detected]
    missed = [s.step_id for s in expected if not s.detected]
    unexpected = [s.step_id for s in result.step_results if s.detected and not s.expect_detection]

    technique_coverage: Dict[str, bool] = {}
    for step in result.step_results:
        # a technique counts as covered if *any* step emulating it was detected
        technique_coverage[step.technique] = technique_coverage.get(step.technique, False) or step.detected

    return CoverageReport(
        scenario_id=scenario.scenario_id,
        total_steps=len(result.step_results),
        expected_steps=len(expected),
        detected_expected=len(detected_expected),
        missed_steps=missed,
        unexpected_detections=unexpected,
        technique_coverage=technique_coverage,
    )
