"""Lexer for the hunt DSL.

Hand-rolled because the surface is small and the runtime should stay
dependency-free. Supports identifiers (with dotted paths), integer and
float literals, double-quoted strings with backslash escapes, the
standard comparison operators, boolean keywords (case-insensitive),
and the list/range/text-match keywords (IN, LIKE, REGEX, BETWEEN,
NULL, NOT).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Iterator, List, Optional


class HuntSyntaxError(SyntaxError):
    pass


class TokenKind(str, enum.Enum):
    IDENT = "ident"
    INT = "int"
    FLOAT = "float"
    STRING = "string"
    OP = "op"
    LPAREN = "lparen"
    RPAREN = "rparen"
    COMMA = "comma"
    KEYWORD = "keyword"
    EOF = "eof"


@dataclass
class Token:
    kind: TokenKind
    value: str
    pos: int


_KEYWORDS = {
    "AND", "OR", "NOT", "IN", "LIKE", "REGEX", "BETWEEN", "IS", "NULL", "TRUE", "FALSE",
}
_OPS = {"==", "!=", ">=", "<=", ">", "<", "=", "<>"}
_OP_STARTS = set("=!<>")


def tokenize(text: str) -> List[Token]:
    out: List[Token] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            out.append(Token(TokenKind.LPAREN, ch, i))
            i += 1
            continue
        if ch == ")":
            out.append(Token(TokenKind.RPAREN, ch, i))
            i += 1
            continue
        if ch == ",":
            out.append(Token(TokenKind.COMMA, ch, i))
            i += 1
            continue
        if ch == '"' or ch == "'":
            quote = ch
            start = i
            i += 1
            buf: List[str] = []
            while i < n and text[i] != quote:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    nxt = text[i + 1]
                    if nxt in (quote, "\\"):
                        buf.append(nxt)
                        i += 2
                        continue
                    if nxt == "n":
                        buf.append("\n")
                        i += 2
                        continue
                    if nxt == "t":
                        buf.append("\t")
                        i += 2
                        continue
                buf.append(c)
                i += 1
            if i >= n:
                raise HuntSyntaxError(f"unterminated string starting at {start}")
            i += 1
            out.append(Token(TokenKind.STRING, "".join(buf), start))
            continue
        if ch.isdigit() or (ch == "-" and i + 1 < n and text[i + 1].isdigit()):
            start = i
            if ch == "-":
                i += 1
            saw_dot = False
            while i < n and (text[i].isdigit() or text[i] == "."):
                if text[i] == ".":
                    if saw_dot:
                        break
                    saw_dot = True
                i += 1
            raw = text[start:i]
            kind = TokenKind.FLOAT if saw_dot else TokenKind.INT
            out.append(Token(kind, raw, start))
            continue
        if ch in _OP_STARTS:
            start = i
            i += 1
            if i < n and text[start:i + 1] in _OPS:
                i += 1
            op = text[start:i]
            if op not in _OPS:
                raise HuntSyntaxError(f"unknown operator '{op}' at {start}")
            out.append(Token(TokenKind.OP, op, start))
            continue
        if ch.isalpha() or ch == "_":
            start = i
            while i < n and (text[i].isalnum() or text[i] in "._"):
                i += 1
            raw = text[start:i]
            upper = raw.upper()
            if upper in _KEYWORDS:
                out.append(Token(TokenKind.KEYWORD, upper, start))
            else:
                out.append(Token(TokenKind.IDENT, raw, start))
            continue
        raise HuntSyntaxError(f"unexpected character '{ch}' at {i}")
    out.append(Token(TokenKind.EOF, "", n))
    return out
