from typing import Optional

from threatpipe.detection import (
    BaseDetector,
    Detection,
    EnsembleDetector,
    RuleEngine,
    Severity,
)
from threatpipe.ingestion import Event, EventType


class _AlwaysFires(BaseDetector):
    def __init__(self, name: str, score: float) -> None:
        self.name = name
        self.score = score

    def detect(self, event: Event) -> Optional[Detection]:
        return Detection(
            event=event,
            detector=self.name,
            score=self.score,
            severity=Severity.from_score(self.score),
            reasons=[f"{self.name} fired"],
        )


def test_ensemble_returns_none_when_no_detectors_hit():
    ens = EnsembleDetector(detectors=[RuleEngine(rules=[])], score_threshold=0.5)
    assert ens.detect(Event()) is None


def test_weighted_mean_strategy():
    ens = EnsembleDetector(
        detectors=[_AlwaysFires("a", 0.6), _AlwaysFires("b", 1.0)],
        weights={"a": 1.0, "b": 3.0},
        strategy="weighted_mean",
        score_threshold=0.0,
    )
    det = ens.detect(Event())
    assert det is not None
    assert abs(det.score - (0.6 + 3 * 1.0) / 4.0) < 1e-9


def test_max_strategy_picks_highest():
    ens = EnsembleDetector(
        detectors=[_AlwaysFires("a", 0.3), _AlwaysFires("b", 0.9)],
        strategy="max",
        score_threshold=0.0,
    )
    assert ens.detect(Event()).score == 0.9


def test_majority_strategy_requires_quorum():
    ens = EnsembleDetector(
        detectors=[
            _AlwaysFires("a", 0.9),
            RuleEngine(rules=[]),  # never fires
            RuleEngine(rules=[]),  # never fires
        ],
        strategy="majority",
        score_threshold=0.0,
    )
    # only one of three fires; below majority
    assert ens.detect(Event()) is None


def test_score_threshold_filters():
    ens = EnsembleDetector(
        detectors=[_AlwaysFires("a", 0.4)],
        strategy="weighted_mean",
        score_threshold=0.5,
    )
    assert ens.detect(Event()) is None


def test_ensemble_propagates_reasons_and_components():
    ens = EnsembleDetector(
        detectors=[_AlwaysFires("a", 0.6), _AlwaysFires("b", 0.8)],
        strategy="max",
        score_threshold=0.0,
    )
    det = ens.detect(Event(event_type=EventType.PROCESS))
    assert det is not None
    assert any("[a]" in r for r in det.reasons)
    assert any("[b]" in r for r in det.reasons)
    names = {c["detector"] for c in det.metadata["components"]}
    assert names == {"a", "b"}
