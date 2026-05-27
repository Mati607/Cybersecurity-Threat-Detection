"""AST node definitions for the threatpipe hunt DSL.

The grammar is small but expressive enough to cover the hunts SOC
analysts actually write against streamed events:

    severity == "high" AND event.dst_port IN (4444, 1337, 31337)
    process LIKE "%powershell%" AND command_line REGEX "[A-Za-z0-9+/=]{50,}"
    score >= 0.8 AND timestamp BETWEEN 1700000000 AND 1700001000

Nodes are deliberately data-only - the evaluator walks them, the
parser builds them, and serialization helpers turn them back into a
canonical text form for storage.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, List, Sequence


class Expr(abc.ABC):
    @abc.abstractmethod
    def to_str(self) -> str:
        ...

    def __repr__(self) -> str:                              # pragma: no cover
        return f"<{type(self).__name__} {self.to_str()}>"


@dataclass
class Literal(Expr):
    value: Any

    def to_str(self) -> str:
        if isinstance(self.value, str):
            escaped = self.value.replace('"', '\\"')
            return f'"{escaped}"'
        if self.value is None:
            return "null"
        return str(self.value)


@dataclass
class Field(Expr):
    path: str            # dotted, e.g. event.dst_ip

    def to_str(self) -> str:
        return self.path


@dataclass
class BinaryOp(Expr):
    op: str              # ==, !=, >, >=, <, <=, AND, OR
    left: Expr
    right: Expr

    def to_str(self) -> str:
        return f"({self.left.to_str()} {self.op} {self.right.to_str()})"


@dataclass
class UnaryOp(Expr):
    op: str              # NOT
    operand: Expr

    def to_str(self) -> str:
        return f"({self.op} {self.operand.to_str()})"


@dataclass
class InOp(Expr):
    field: Expr
    values: List[Expr] = field(default_factory=list)
    negate: bool = False

    def to_str(self) -> str:
        items = ", ".join(v.to_str() for v in self.values)
        return f"({self.field.to_str()} {'NOT IN' if self.negate else 'IN'} ({items}))"


@dataclass
class LikeOp(Expr):
    field: Expr
    pattern: str             # SQL-like with % and _
    negate: bool = False

    def to_str(self) -> str:
        kw = "NOT LIKE" if self.negate else "LIKE"
        return f"({self.field.to_str()} {kw} \"{self.pattern}\")"


@dataclass
class RegexOp(Expr):
    field: Expr
    pattern: str
    negate: bool = False

    def to_str(self) -> str:
        kw = "NOT REGEX" if self.negate else "REGEX"
        return f"({self.field.to_str()} {kw} \"{self.pattern}\")"


@dataclass
class BetweenOp(Expr):
    field: Expr
    low: Expr
    high: Expr
    negate: bool = False

    def to_str(self) -> str:
        kw = "NOT BETWEEN" if self.negate else "BETWEEN"
        return f"({self.field.to_str()} {kw} {self.low.to_str()} AND {self.high.to_str()})"


@dataclass
class ExistsOp(Expr):
    field: Expr
    negate: bool = False

    def to_str(self) -> str:
        return f"({self.field.to_str()} IS {'NOT NULL' if self.negate else 'NULL'})"


@dataclass
class FunctionCall(Expr):
    name: str
    args: List[Expr] = field(default_factory=list)

    def to_str(self) -> str:
        args = ", ".join(a.to_str() for a in self.args)
        return f"{self.name}({args})"
