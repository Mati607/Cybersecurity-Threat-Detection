"""User-facing query object that turns a DSL string into a callable.

A :class:`HuntQuery` is the small, ergonomic shell most callers want:

    HuntQuery("severity == 'high' AND event.dst_port IN (4444, 1337)") \
        .run_over(pipeline.recent(limit=500))

It caches the parsed AST so re-running the same query (e.g. on a
schedule) doesn't re-parse, and emits a :class:`HuntResult` with the
matched records plus a small set of summary counters.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from .ast import Expr
from .evaluator import HuntEvaluator
from .parser import parse_query


@dataclass
class HuntResult:
    query: str
    matches: List[Any] = field(default_factory=list)
    scanned: int = 0
    duration_ms: float = 0.0
    error: Optional[str] = None

    @property
    def match_count(self) -> int:
        return len(self.matches)

    def to_dict(self) -> Dict[str, Any]:
        def _record(item: Any) -> Any:
            if hasattr(item, "to_dict") and callable(item.to_dict):
                return item.to_dict()
            return item

        return {
            "query": self.query,
            "scanned": self.scanned,
            "match_count": self.match_count,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
            "matches": [_record(m) for m in self.matches],
        }


class HuntQuery:
    def __init__(
        self,
        text: str,
        *,
        evaluator: Optional[HuntEvaluator] = None,
        max_matches: int = 1000,
    ) -> None:
        self.text = text
        self.evaluator = evaluator or HuntEvaluator()
        self.max_matches = max_matches
        self._expr: Optional[Expr] = None
        self._error: Optional[str] = None

    @property
    def expr(self) -> Expr:
        if self._expr is None and self._error is None:
            try:
                self._expr = parse_query(self.text)
            except Exception as exc:                       # SyntaxError is the common case
                self._error = str(exc)
                raise
        if self._expr is None:                              # pragma: no cover
            raise SyntaxError(self._error or "unparsed")
        return self._expr

    def __call__(self, record: Any) -> bool:
        return self.evaluator.matches(self.expr, record)

    def run_over(self, records: Iterable[Any]) -> HuntResult:
        started = time.time()
        result = HuntResult(query=self.text)
        try:
            expr = self.expr
        except Exception as exc:
            result.error = str(exc)
            return result
        for record in records:
            result.scanned += 1
            try:
                if self.evaluator.matches(expr, record):
                    result.matches.append(record)
                    if len(result.matches) >= self.max_matches:
                        break
            except Exception:                              # pragma: no cover
                continue
        result.duration_ms = (time.time() - started) * 1000.0
        return result
