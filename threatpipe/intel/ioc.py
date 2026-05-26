"""Indicator-of-compromise value object and type detection.

We model IOCs as small dataclasses rather than a polymorphic class
hierarchy — every IOC is keyed by ``(type, value_normalized)`` and the
type tells the matcher which event field to look at.

The type inferencer is regex-based and tolerant: callers may pass IPs
with ports, hashes in mixed case, or domains with ``www.`` prefixes
and still get a normalized value back.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    FILE_PATH = "file_path"
    PROCESS = "process"
    USER = "user"
    EMAIL = "email"
    REGISTRY = "registry"


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_REGISTRY_RE = re.compile(r"^HK(?:LM|CU|CR|U|CC)\\", re.IGNORECASE)


def _normalize(ioc_type: IOCType, value: str) -> str:
    v = value.strip()
    if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
        return v.lower()
    if ioc_type == IOCType.DOMAIN:
        return v.lower().lstrip(".").removeprefix("www.")
    if ioc_type == IOCType.URL:
        return v
    if ioc_type == IOCType.EMAIL:
        return v.lower()
    if ioc_type == IOCType.IP:
        # strip a trailing port if present
        if ":" in v and v.count(":") == 1:
            v = v.split(":", 1)[0]
        return v
    return v


def parse_ioc_type(value: str) -> Optional[IOCType]:
    """Infer the IOC type from the raw indicator string.

    Returns ``None`` when the input doesn't look like any supported
    indicator. The matcher uses this when loading freeform feeds.
    """
    v = value.strip()
    if not v:
        return None
    if _URL_RE.match(v):
        return IOCType.URL
    if _EMAIL_RE.match(v):
        return IOCType.EMAIL
    if _IP_RE.match(v.split(":", 1)[0]):
        return IOCType.IP
    if _IPV6_RE.match(v):
        return IOCType.IP
    if _MD5_RE.match(v):
        return IOCType.HASH_MD5
    if _SHA1_RE.match(v):
        return IOCType.HASH_SHA1
    if _SHA256_RE.match(v):
        return IOCType.HASH_SHA256
    if _REGISTRY_RE.match(v):
        return IOCType.REGISTRY
    if _DOMAIN_RE.match(v):
        return IOCType.DOMAIN
    if "/" in v or "\\" in v:
        return IOCType.FILE_PATH
    return None


@dataclass(frozen=True)
class IOCMeta:
    source: str = "unknown"
    confidence: float = 0.8
    threat_score: float = 0.7
    tags: Tuple[str, ...] = ()
    description: str = ""


@dataclass
class IOC:
    type: IOCType
    value: str
    meta: IOCMeta = field(default_factory=IOCMeta)

    def __post_init__(self) -> None:
        # normalize once at construction time; matcher relies on it
        object.__setattr__(self, "value", _normalize(self.type, self.value))

    @property
    def key(self) -> Tuple[str, str]:
        return (self.type.value, self.value)

    def fingerprint(self) -> str:
        return hashlib.sha1(f"{self.type.value}|{self.value}".encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "fingerprint": self.fingerprint(),
            "source": self.meta.source,
            "confidence": self.meta.confidence,
            "threat_score": self.meta.threat_score,
            "tags": list(self.meta.tags),
            "description": self.meta.description,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "IOC":
        ioc_type = IOCType(raw["type"]) if "type" in raw and raw["type"] else parse_ioc_type(raw.get("value", ""))
        if ioc_type is None:
            raise ValueError(f"unrecognized IOC: {raw!r}")
        meta = IOCMeta(
            source=str(raw.get("source", "unknown")),
            confidence=float(raw.get("confidence", 0.8)),
            threat_score=float(raw.get("threat_score", 0.7)),
            tags=tuple(raw.get("tags", []) or []),
            description=str(raw.get("description", "")),
        )
        return cls(type=ioc_type, value=str(raw["value"]), meta=meta)
