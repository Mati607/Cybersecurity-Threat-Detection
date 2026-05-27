"""Recursive-descent parser for the hunt DSL.

Grammar (lowercase = non-terminal, UPPERCASE = keyword):

    query    -> or
    or       -> and (OR and)*
    and      -> not (AND not)*
    not      -> NOT not | primary
    primary  -> "(" query ")" | comparison | predicate
    comparison -> term op term
    predicate -> term IN "(" args ")"
              | term [NOT] LIKE STRING
              | term [NOT] REGEX STRING
              | term [NOT] BETWEEN term AND term
              | term IS [NOT] NULL
    term     -> literal | field | function
    function -> IDENT "(" args ")"
    args     -> term ("," term)*

This is intentionally a fragment of SQL/Lucene: enough to express the
queries the API needs without taking on a full expression language.
"""

from __future__ import annotations

from typing import List, Optional

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
from .lexer import HuntSyntaxError, Token, TokenKind, tokenize


_COMPARATORS = {"==", "!=", ">", ">=", "<", "<=", "=", "<>"}


class HuntParser:
    def __init__(self, tokens: List[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    # --- helpers -------------------------------------------------

    def _peek(self, offset: int = 0) -> Token:
        return self.tokens[self.pos + offset]

    def _take(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _expect(self, kind: TokenKind, value: Optional[str] = None) -> Token:
        tok = self._peek()
        if tok.kind != kind or (value is not None and tok.value != value):
            raise HuntSyntaxError(
                f"expected {kind.value}{(' ' + value) if value else ''}, got {tok.kind.value} '{tok.value}' at {tok.pos}"
            )
        return self._take()

    def _accept(self, kind: TokenKind, value: Optional[str] = None) -> Optional[Token]:
        tok = self._peek()
        if tok.kind == kind and (value is None or tok.value == value):
            return self._take()
        return None

    # --- entry ---------------------------------------------------

    def parse(self) -> Expr:
        expr = self._parse_or()
        if self._peek().kind != TokenKind.EOF:
            tok = self._peek()
            raise HuntSyntaxError(f"unexpected token '{tok.value}' at {tok.pos}")
        return expr

    # --- recursive descent ---------------------------------------

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._accept(TokenKind.KEYWORD, "OR"):
            right = self._parse_and()
            left = BinaryOp("OR", left, right)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_not()
        while self._accept(TokenKind.KEYWORD, "AND"):
            right = self._parse_not()
            left = BinaryOp("AND", left, right)
        return left

    def _parse_not(self) -> Expr:
        if self._accept(TokenKind.KEYWORD, "NOT"):
            return UnaryOp("NOT", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Expr:
        if self._accept(TokenKind.LPAREN):
            expr = self._parse_or()
            self._expect(TokenKind.RPAREN)
            return expr
        return self._parse_predicate()

    def _parse_predicate(self) -> Expr:
        left = self._parse_term()
        tok = self._peek()

        # comparison
        if tok.kind == TokenKind.OP and tok.value in _COMPARATORS:
            op = self._take().value
            right = self._parse_term()
            normalized = op if op not in ("=", "<>") else ("==" if op == "=" else "!=")
            return BinaryOp(normalized, left, right)

        # IN, NOT IN, LIKE, REGEX, BETWEEN, IS [NOT] NULL
        negate = False
        if tok.kind == TokenKind.KEYWORD and tok.value == "NOT":
            self._take()
            negate = True
            tok = self._peek()

        if tok.kind == TokenKind.KEYWORD and tok.value == "IN":
            self._take()
            self._expect(TokenKind.LPAREN)
            args: List[Expr] = []
            if not self._accept(TokenKind.RPAREN):
                args.append(self._parse_term())
                while self._accept(TokenKind.COMMA):
                    args.append(self._parse_term())
                self._expect(TokenKind.RPAREN)
            return InOp(field=left, values=args, negate=negate)

        if tok.kind == TokenKind.KEYWORD and tok.value == "LIKE":
            self._take()
            pat = self._expect(TokenKind.STRING).value
            return LikeOp(field=left, pattern=pat, negate=negate)

        if tok.kind == TokenKind.KEYWORD and tok.value == "REGEX":
            self._take()
            pat = self._expect(TokenKind.STRING).value
            return RegexOp(field=left, pattern=pat, negate=negate)

        if tok.kind == TokenKind.KEYWORD and tok.value == "BETWEEN":
            self._take()
            low = self._parse_term()
            self._expect(TokenKind.KEYWORD, "AND")
            high = self._parse_term()
            return BetweenOp(field=left, low=low, high=high, negate=negate)

        if tok.kind == TokenKind.KEYWORD and tok.value == "IS":
            self._take()
            inner_negate = False
            if self._accept(TokenKind.KEYWORD, "NOT"):
                inner_negate = True
            self._expect(TokenKind.KEYWORD, "NULL")
            return ExistsOp(field=left, negate=(negate ^ inner_negate))

        if negate:
            raise HuntSyntaxError(f"NOT must be followed by IN/LIKE/REGEX/BETWEEN at {tok.pos}")
        # A bare term (e.g. truthy field) — keep as boolean predicate
        return left

    def _parse_term(self) -> Expr:
        tok = self._peek()
        if tok.kind == TokenKind.INT:
            self._take()
            return Literal(int(tok.value))
        if tok.kind == TokenKind.FLOAT:
            self._take()
            return Literal(float(tok.value))
        if tok.kind == TokenKind.STRING:
            self._take()
            return Literal(tok.value)
        if tok.kind == TokenKind.KEYWORD and tok.value in ("TRUE", "FALSE"):
            self._take()
            return Literal(tok.value == "TRUE")
        if tok.kind == TokenKind.KEYWORD and tok.value == "NULL":
            self._take()
            return Literal(None)
        if tok.kind == TokenKind.IDENT:
            ident = self._take().value
            if self._accept(TokenKind.LPAREN):
                args: List[Expr] = []
                if not self._accept(TokenKind.RPAREN):
                    args.append(self._parse_term())
                    while self._accept(TokenKind.COMMA):
                        args.append(self._parse_term())
                    self._expect(TokenKind.RPAREN)
                return FunctionCall(ident, args)
            return Field(ident)
        raise HuntSyntaxError(f"unexpected token '{tok.value}' at {tok.pos}")


def parse_query(text: str) -> Expr:
    return HuntParser(tokenize(text)).parse()
