"""Threat-intel feed loaders.

Each loader takes a file path and yields :class:`IOC` objects. The
loaders are tolerant — they skip malformed rows rather than aborting,
because real-world threat feeds often contain garbage lines.

Supported formats:

* CSV with a header row mapping columns to IOC fields
* JSON files containing either a list of records or a top-level ``"iocs"`` list
* JSON-lines with one IOC per line
* STIX-lite (a flat JSON file with ``"indicators": [...]`` records)
* Plain text host files: one indicator per line, ``#`` for comments
"""

from __future__ import annotations

import abc
import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional

from ..utils.logging_setup import get_logger
from .ioc import IOC, IOCMeta, IOCType, parse_ioc_type

_log = get_logger(__name__)


class BaseFeedLoader(abc.ABC):
    name: str = "base"

    def __init__(self, source_name: Optional[str] = None) -> None:
        self.source_name = source_name or self.name

    @abc.abstractmethod
    def load(self, path: str | Path) -> Iterator[IOC]:
        ...

    def _make_ioc(
        self,
        value: str,
        *,
        ioc_type: Optional[IOCType] = None,
        confidence: float = 0.8,
        threat_score: float = 0.7,
        tags: Iterable[str] = (),
        description: str = "",
    ) -> Optional[IOC]:
        if not value:
            return None
        inferred = ioc_type or parse_ioc_type(value)
        if inferred is None:
            return None
        meta = IOCMeta(
            source=self.source_name,
            confidence=float(confidence),
            threat_score=float(threat_score),
            tags=tuple(sorted(set(tags))),
            description=description,
        )
        try:
            return IOC(type=inferred, value=value.strip(), meta=meta)
        except ValueError:
            return None


class CSVFeedLoader(BaseFeedLoader):
    name = "csv"

    _ALIASES = {
        "value": ("value", "indicator", "ioc", "address", "hash"),
        "type": ("type", "ioc_type", "indicator_type"),
        "confidence": ("confidence",),
        "threat_score": ("threat_score", "score"),
        "tags": ("tags", "labels"),
        "description": ("description", "comment", "notes"),
    }

    def load(self, path: str | Path) -> Iterator[IOC]:
        with Path(path).open("r", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                value = self._first(row, self._ALIASES["value"])
                if value is None:
                    continue
                type_raw = self._first(row, self._ALIASES["type"])
                ioc_type: Optional[IOCType] = None
                if type_raw:
                    try:
                        ioc_type = IOCType(type_raw.lower())
                    except ValueError:
                        ioc_type = parse_ioc_type(type_raw)
                tags_raw = self._first(row, self._ALIASES["tags"]) or ""
                ioc = self._make_ioc(
                    value=value,
                    ioc_type=ioc_type,
                    confidence=float(self._first(row, self._ALIASES["confidence"]) or 0.8),
                    threat_score=float(self._first(row, self._ALIASES["threat_score"]) or 0.7),
                    tags=[t.strip() for t in tags_raw.split(";") if t.strip()],
                    description=self._first(row, self._ALIASES["description"]) or "",
                )
                if ioc is not None:
                    yield ioc

    @staticmethod
    def _first(row: Dict[str, str], keys: Iterable[str]) -> Optional[str]:
        for k in keys:
            if k in row and row[k]:
                return row[k]
        return None


class JSONFeedLoader(BaseFeedLoader):
    name = "json"

    def load(self, path: str | Path) -> Iterator[IOC]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        records = data["iocs"] if isinstance(data, dict) and "iocs" in data else data
        if not isinstance(records, list):
            return iter(())
        for raw in records:
            try:
                yield IOC.from_dict(raw)
            except (ValueError, KeyError):
                continue


class JSONLFeedLoader(BaseFeedLoader):
    name = "jsonl"

    def load(self, path: str | Path) -> Iterator[IOC]:
        with Path(path).open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    yield IOC.from_dict(json.loads(line))
                except (ValueError, KeyError, json.JSONDecodeError):
                    continue


class STIXLiteFeedLoader(BaseFeedLoader):
    """Loader for a flat STIX-like structure.

    Real STIX 2.x is a graph; we accept the common "flattened" form that
    open-source feeds publish — a JSON file with ``"indicators": [...]``
    where each record has at least ``pattern`` (e.g. ``[ipv4-addr:value = '1.2.3.4']``).
    """

    name = "stix-lite"
    _PATTERN_RE = __import__("re").compile(
        r"\[(?P<otype>[a-z0-9-]+):(?P<attr>[a-z_]+)\s*=\s*'(?P<val>[^']+)'\]"
    )
    _STIX_TO_IOC = {
        "ipv4-addr": IOCType.IP,
        "ipv6-addr": IOCType.IP,
        "domain-name": IOCType.DOMAIN,
        "url": IOCType.URL,
        "file": IOCType.HASH_SHA256,    # default for hash patterns
        "email-addr": IOCType.EMAIL,
        "windows-registry-key": IOCType.REGISTRY,
    }

    def load(self, path: str | Path) -> Iterator[IOC]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for record in data.get("indicators", []):
            pattern = record.get("pattern", "")
            tags = record.get("labels") or record.get("tags") or []
            description = record.get("name") or record.get("description") or ""
            for m in self._PATTERN_RE.finditer(pattern):
                otype = m.group("otype")
                attr = m.group("attr").lower()
                value = m.group("val")
                ioc_type = self._STIX_TO_IOC.get(otype)
                if ioc_type == IOCType.HASH_SHA256 and "md5" in attr:
                    ioc_type = IOCType.HASH_MD5
                elif ioc_type == IOCType.HASH_SHA256 and "sha-1" in attr:
                    ioc_type = IOCType.HASH_SHA1
                ioc = self._make_ioc(
                    value=value,
                    ioc_type=ioc_type,
                    confidence=float(record.get("confidence", 70)) / 100.0,
                    threat_score=float(record.get("threat_score", 0.7)),
                    tags=tags,
                    description=description,
                )
                if ioc is not None:
                    yield ioc


class HostsFileLoader(BaseFeedLoader):
    name = "hosts"

    def load(self, path: str | Path) -> Iterator[IOC]:
        with Path(path).open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                value = line.split()[-1]
                ioc = self._make_ioc(value)
                if ioc is not None:
                    yield ioc


_BY_SUFFIX = {
    ".csv": CSVFeedLoader,
    ".json": JSONFeedLoader,
    ".jsonl": JSONLFeedLoader,
    ".ndjson": JSONLFeedLoader,
    ".stix": STIXLiteFeedLoader,
    ".txt": HostsFileLoader,
    ".list": HostsFileLoader,
}


def load_feed(path: str | Path, *, format: Optional[str] = None,
              source_name: Optional[str] = None) -> Iterable[IOC]:
    """Dispatch to the right loader by extension or explicit ``format``."""
    p = Path(path)
    loader_cls = None
    if format:
        for cls in (CSVFeedLoader, JSONFeedLoader, JSONLFeedLoader, STIXLiteFeedLoader, HostsFileLoader):
            if cls.name == format:
                loader_cls = cls
                break
    if loader_cls is None:
        loader_cls = _BY_SUFFIX.get(p.suffix.lower())
    if loader_cls is None:
        _log.warning("no loader for feed %s; assuming hosts-style", p)
        loader_cls = HostsFileLoader
    loader = loader_cls(source_name=source_name or p.name)
    return loader.load(p)
