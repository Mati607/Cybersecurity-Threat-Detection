"""AST -> boolean evaluator.

Given a parsed :mod:`ast` tree and a record (dict or dataclass-like
object), the evaluator returns whether the record matches. We support
dotted field access, type-tolerant comparison (string vs number),
SQL ``LIKE`` translation, regex caching, and a small set of built-in
functions (``lower``, ``upper``, ``length``, ``now``).
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, Mapping

from .ast import (
    BetweenOp,
    BinaryOp,
    ExistsOp,
    Expr,
    Field,
    FunctionCall,
    InOp,
    LikeOp,
    Literal,
    RegexOp,
    UnaryOp,
)


_REGEX_CACHE: Dict[str, re.Pattern] = {}


def _regex(pattern: str) -> re.Pattern:
    cached = _REGEX_CACHE.get(pattern)
    if cached is None:
        cached = re.compile(pattern)
        _REGEX_CACHE[pattern] = cached
    return cached


def _like_to_regex(pattern: str) -> re.Pattern:
    escaped: list[str] = []
    for ch in pattern:
        if ch == "%":
            escaped.append(".*")
        elif ch == "_":
            escaped.append(".")
        else:
            escaped.append(re.escape(ch))
    return _regex("^" + "".join(escaped) + "$")


def _resolve_field(record: Any, path: str) -> Any:
    parts = path.split(".")
    cur = record
    for part in parts:
        if cur is None:
            return None
        if isinstance(cur, Mapping):
            cur = cur.get(part)
            continue
        cur = getattr(cur, part, None)
    return cur


def _coerce(a: Any, b: Any) -> tuple[Any, Any]:
    """Best-effort numeric coercion before comparison."""
    if isinstance(a, (int, float)) and isinstance(b, str):
        try:
            return a, float(b)
        except ValueError:
            return a, b
    if isinstance(b, (int, float)) and isinstance(a, str):
        try:
            return float(a), b
        except ValueError:
            return a, b
    return a, b


_BINARY_OPS: Dict[str, Callable[[Any, Any], Any]] = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
}


_FUNCTIONS: Dict[str, Callable[..., Any]] = {
    "lower": lambda x: str(x).lower() if x is not None else None,
    "upper": lambda x: str(x).upper() if x is not None else None,
    "length": lambda x: len(x) if x is not None else 0,
    "now": lambda: time.time(),
    "abs": lambda x: abs(x) if isinstance(x, (int, float)) else 0,
}


class HuntEvaluator:
    def __init__(self, functions: Mapping[str, Callable[..., Any]] = ()) -> None:
        self.functions: Dict[str, Callable[..., Any]] = dict(_FUNCTIONS)
        for name, fn in dict(functions).items():
            self.functions[name] = fn

    def evaluate(self, expr: Expr, record: Any) -> Any:
        if isinstance(expr, Literal):
            return expr.value
        if isinstance(expr, Field):
            return _resolve_field(record, expr.path)
        if isinstance(expr, FunctionCall):
            args = [self.evaluate(a, record) for a in expr.args]
            fn = self.functions.get(expr.name.lower())
            if fn is None:
                return None
            try:
                return fn(*args)
            except Exception:                              # pragma: no cover
                return None
        if isinstance(expr, UnaryOp) and expr.op == "NOT":
            return not bool(self.evaluate(expr.operand, record))
        if isinstance(expr, BinaryOp):
            return self._eval_binary(expr, record)
        if isinstance(expr, InOp):
            value = self.evaluate(expr.field, record)
            values = [self.evaluate(v, record) for v in expr.values]
            result = value in values
            return (not result) if expr.negate else result
        if isinstance(expr, LikeOp):
            value = self.evaluate(expr.field, record)
            if value is None:
                return expr.negate
            result = bool(_like_to_regex(expr.pattern).match(str(value)))
            return (not result) if expr.negate else result
        if isinstance(expr, RegexOp):
            value = self.evaluate(expr.field, record)
            if value is None:
                return expr.negate
            try:
                result = bool(_regex(expr.pattern).search(str(value)))
            except re.error:
                return False
            return (not result) if expr.negate else result
        if isinstance(expr, BetweenOp):
            value = self.evaluate(expr.field, record)
            low = self.evaluate(expr.low, record)
            high = self.evaluate(expr.high, record)
            if value is None or low is None or high is None:
                return False
            try:
                result = low <= value <= high
            except TypeError:
                return False
            return (not result) if expr.negate else result
        if isinstance(expr, ExistsOp):
            value = self.evaluate(expr.field, record)
            is_null = value is None
            return (not is_null) if expr.negate else is_null
        return False

    def matches(self, expr: Expr, record: Any) -> bool:
        return bool(self.evaluate(expr, record))

    def _eval_binary(self, expr: BinaryOp, record: Any) -> Any:
        if expr.op in ("AND", "OR"):
            left = self.evaluate(expr.left, record)
            if expr.op == "AND" and not left:
                return False
            if expr.op == "OR" and left:
                return True
            return bool(self.evaluate(expr.right, record))
        op = _BINARY_OPS.get(expr.op)
        if op is None:
            return False
        a, b = self.evaluate(expr.left, record), self.evaluate(expr.right, record)
        if a is None or b is None:
            return expr.op == "!=" and (a is not b)
        a, b = _coerce(a, b)
        try:
            return op(a, b)
        except TypeError:
            try:
                return op(str(a), str(b))
            except Exception:                              # pragma: no cover
                return False


def evaluate(query: str | Expr, record: Any) -> bool:
    from .parser import parse_query
    expr = query if isinstance(query, Expr) else parse_query(query)
    return HuntEvaluator().matches(expr, record)
