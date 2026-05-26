"""Best-effort enrichment helpers for events and detections.

The functions here are non-destructive: callers pass in an event or a
detection and get back an annotated dict ready for downstream alerting
or API responses. Nothing here calls out to the network — enrichment
purely combines locally available data (IOC store, reputation cache).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..detection.base import Detection
from ..ingestion.event import Event
from .ioc import IOCType
from .reputation import ReputationCache
from .store import IOCStore


def enrich_event(
    event: Event,
    *,
    store: Optional[IOCStore] = None,
    reputation: Optional[ReputationCache] = None,
) -> Dict[str, Any]:
    enrichment: Dict[str, Any] = {"ioc_hits": [], "reputation": {}}
    if store is not None:
        for field_name, ioc_type in (
            ("dst_ip", IOCType.IP),
            ("src_ip", IOCType.IP),
            ("file_path", IOCType.FILE_PATH),
            ("process", IOCType.PROCESS),
            ("user", IOCType.USER),
        ):
            value = getattr(event, field_name, None)
            if not value:
                continue
            v = str(value).split(":", 1)[0] if ioc_type == IOCType.IP else str(value)
            ioc = store.lookup(ioc_type, v)
            if ioc is not None:
                enrichment["ioc_hits"].append({
                    "field": field_name, "value": v, "ioc": ioc.to_dict(),
                })
    if reputation is not None:
        for field_name, kind in (("dst_ip", "ip"), ("src_ip", "ip")):
            value = getattr(event, field_name, None)
            if not value:
                continue
            v = str(value).split(":", 1)[0]
            rep = reputation.resolve(kind, v)
            if rep is not None:
                enrichment["reputation"][f"{field_name}={v}"] = rep.to_dict()
    return enrichment


def enrich_detection(
    detection: Detection,
    *,
    store: Optional[IOCStore] = None,
    reputation: Optional[ReputationCache] = None,
) -> Dict[str, Any]:
    base = detection.to_dict()
    base["enrichment"] = enrich_event(detection.event, store=store, reputation=reputation)
    return base
