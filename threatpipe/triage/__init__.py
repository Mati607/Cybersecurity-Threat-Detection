"""Alert triage: deduplication, suppression, and priority scoring.

The detection pipeline emits one detection per interesting event, which
in a busy environment means a firehose an analyst can't drink from. The
triage layer turns that firehose into a ranked, deduplicated work queue:

* recurring detections collapse into a single :class:`TriagedAlert` with a
  growing ``count`` (see :mod:`~threatpipe.triage.fingerprint`);
* :class:`SuppressionRule`s silence known-benign noise, with a severity
  ceiling and optional expiry so they can't over-reach;
* a :class:`PriorityScorer` ranks alerts by severity *and* volume, host
  spread, intel context, and confidence — so the P1 queue reflects what
  actually matters first.

Wire :class:`TriageEngine` in as the pipeline's ``alert_sink`` (it is a
``Detection -> None`` callable) and give it a ``downstream`` sink to
forward only newly-actionable or freshly-escalated alerts onward.
"""

from .model import (
    SuppressionRule,
    TriageDisposition,
    TriagePriority,
    TriageStatus,
    TriagedAlert,
)
from .fingerprint import describe, fingerprint, key_fields_for
from .priority import PriorityScorer
from .suppression import SuppressionList
from .store import TriageStore
from .engine import TriageEngine, TriageResult

__all__ = [
    "SuppressionRule",
    "TriageDisposition",
    "TriagePriority",
    "TriageStatus",
    "TriagedAlert",
    "describe",
    "fingerprint",
    "key_fields_for",
    "PriorityScorer",
    "SuppressionList",
    "TriageStore",
    "TriageEngine",
    "TriageResult",
]
