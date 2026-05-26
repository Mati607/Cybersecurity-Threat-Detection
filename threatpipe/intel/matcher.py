"""Detector that matches events against an :class:`IOCStore`.

The matcher inspects multiple event fields per call (network addresses,
file paths, hashes, command lines, etc.) and emits a single
:class:`~threatpipe.detection.Detection` summarizing every hit. Scoring
respects the per-IOC ``threat_score`` weighted by ``confidence``, with
a small boost when multiple distinct IOCs match the same event.
"""

from __future__ import annotations

import re
from typing import List, Optional

from ..detection.base import BaseDetector, Detection, Severity
from ..ingestion.event import Event
from .ioc import IOC, IOCType
from .store import IOCMatch, IOCStore


_URL_RE = re.compile(r"https?://([^/\s]+)", re.IGNORECASE)
_HASH_RE = re.compile(r"\b([a-fA-F0-9]{32,64})\b")


class IOCMatcher(BaseDetector):
    name = "ioc"
    stateful = False

    def __init__(self, store: IOCStore, *, min_score: float = 0.5) -> None:
        self.store = store
        self.min_score = min_score

    def detect(self, event: Event) -> Optional[Detection]:
        matches: List[IOCMatch] = []
        self._match_field(event.dst_ip, "dst_ip", IOCType.IP, matches)
        self._match_field(event.src_ip, "src_ip", IOCType.IP, matches)
        self._match_field(event.file_path, "file_path", IOCType.FILE_PATH, matches)
        self._match_field(event.process, "process", IOCType.PROCESS, matches)
        self._match_field(event.user, "user", IOCType.USER, matches)

        # extract domains and hashes from free-text fields
        for field_name in ("command_line", "message"):
            value = getattr(event, field_name, None)
            if not value:
                continue
            for url_match in _URL_RE.finditer(value):
                host = url_match.group(1).strip("/")
                # could be IP or domain
                self._match_field(host, field_name, IOCType.DOMAIN, matches)
                self._match_field(host, field_name, IOCType.IP, matches)
            for hash_match in _HASH_RE.finditer(value):
                h = hash_match.group(1)
                if len(h) == 32:
                    self._match_field(h, field_name, IOCType.HASH_MD5, matches)
                elif len(h) == 40:
                    self._match_field(h, field_name, IOCType.HASH_SHA1, matches)
                elif len(h) == 64:
                    self._match_field(h, field_name, IOCType.HASH_SHA256, matches)

        # match hash event field directly
        raw_hash = event.raw.get("hash") if event.raw else None
        if isinstance(raw_hash, str):
            for hash_type, expected_len in (
                (IOCType.HASH_MD5, 32),
                (IOCType.HASH_SHA1, 40),
                (IOCType.HASH_SHA256, 64),
            ):
                if len(raw_hash) == expected_len:
                    self._match_field(raw_hash, "raw.hash", hash_type, matches)

        if not matches:
            return None

        score = self._score(matches)
        if score < self.min_score:
            return None
        reasons = [
            f"IOC match {m.ioc.type.value}={m.value} (source={m.ioc.meta.source}, conf={m.confidence:.2f})"
            for m in matches[:5]
        ]
        tags = sorted({tag for m in matches for tag in m.ioc.meta.tags} | {"ioc"})
        return Detection(
            event=event,
            detector=self.name,
            score=score,
            severity=Severity.from_score(score),
            reasons=reasons,
            tags=tags,
            metadata={
                "matches": [m.to_dict() for m in matches],
                "match_count": len(matches),
                "sources": sorted({m.ioc.meta.source for m in matches}),
            },
        )

    def _match_field(self, value, field_name: str, ioc_type: IOCType, sink: List[IOCMatch]) -> None:
        if not value:
            return
        v = str(value)
        # for IPs, strip any "ip:port"
        if ioc_type == IOCType.IP and ":" in v:
            v = v.split(":", 1)[0]
        ioc = self.store.lookup(ioc_type, v)
        if ioc is not None:
            sink.append(IOCMatch(
                ioc=ioc, field=field_name, value=v,
                confidence=ioc.meta.confidence, threat_score=ioc.meta.threat_score,
            ))

    def _score(self, matches: List[IOCMatch]) -> float:
        # weighted by confidence, top score plus diminishing-returns boost
        weighted = [m.threat_score * m.confidence for m in matches]
        weighted.sort(reverse=True)
        top = weighted[0]
        boost = sum(w * (0.6 ** i) for i, w in enumerate(weighted[1:], start=1)) * 0.25
        return min(1.0, top + boost)
