"""Persistent store of saved hunts.

Saved hunts are named queries that survive across restarts. The
scheduler reads from this store, and the API exposes CRUD operations
over it. Persistence is intentionally a small JSON file so operators
can also edit the catalog by hand or check it into git.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional


@dataclass
class SavedHunt:
    hunt_id: str
    name: str
    query: str
    description: str = ""
    schedule_seconds: Optional[int] = None
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    severity_floor: Optional[str] = None
    last_run_at: float = 0.0
    last_match_count: int = 0
    last_duration_ms: float = 0.0
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "name": self.name,
            "query": self.query,
            "description": self.description,
            "schedule_seconds": self.schedule_seconds,
            "enabled": self.enabled,
            "tags": list(self.tags),
            "severity_floor": self.severity_floor,
            "last_run_at": self.last_run_at,
            "last_match_count": self.last_match_count,
            "last_duration_ms": self.last_duration_ms,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SavedHunt":
        return cls(
            hunt_id=str(raw["hunt_id"]),
            name=str(raw.get("name", raw["hunt_id"])),
            query=str(raw["query"]),
            description=str(raw.get("description", "")),
            schedule_seconds=raw.get("schedule_seconds"),
            enabled=bool(raw.get("enabled", True)),
            tags=list(raw.get("tags", [])),
            severity_floor=raw.get("severity_floor"),
            last_run_at=float(raw.get("last_run_at", 0.0)),
            last_match_count=int(raw.get("last_match_count", 0)),
            last_duration_ms=float(raw.get("last_duration_ms", 0.0)),
            last_error=raw.get("last_error"),
        )


class HuntStore:
    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else None
        self._hunts: Dict[str, SavedHunt] = {}
        self._lock = threading.RLock()
        if self.path and self.path.exists():
            self.load()

    def upsert(self, hunt: SavedHunt) -> SavedHunt:
        with self._lock:
            self._hunts[hunt.hunt_id] = hunt
        self.save()
        return hunt

    def get(self, hunt_id: str) -> Optional[SavedHunt]:
        with self._lock:
            return self._hunts.get(hunt_id)

    def remove(self, hunt_id: str) -> bool:
        with self._lock:
            removed = self._hunts.pop(hunt_id, None) is not None
        if removed:
            self.save()
        return removed

    def list(self, *, enabled_only: bool = False) -> List[SavedHunt]:
        with self._lock:
            items = list(self._hunts.values())
        if enabled_only:
            items = [h for h in items if h.enabled]
        items.sort(key=lambda h: h.hunt_id)
        return items

    def update_stats(self, hunt_id: str, *, match_count: int, duration_ms: float,
                     error: Optional[str] = None) -> None:
        with self._lock:
            hunt = self._hunts.get(hunt_id)
            if hunt is None:
                return
            hunt.last_run_at = time.time()
            hunt.last_match_count = match_count
            hunt.last_duration_ms = duration_ms
            hunt.last_error = error
        self.save()

    def __len__(self) -> int:
        return len(self._hunts)

    # --- persistence ---------------------------------------------

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        items = data.get("hunts", data) if isinstance(data, dict) else data
        with self._lock:
            self._hunts.clear()
            for raw in items or []:
                try:
                    hunt = SavedHunt.from_dict(raw)
                except (KeyError, ValueError):
                    continue
                self._hunts[hunt.hunt_id] = hunt

    def save(self) -> None:
        if not self.path:
            return
        with self._lock:
            payload = {"hunts": [h.to_dict() for h in self._hunts.values()]}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError:                                      # pragma: no cover
            pass

    def import_many(self, items: Iterable[Mapping[str, Any]]) -> int:
        n = 0
        for raw in items:
            try:
                self.upsert(SavedHunt.from_dict(raw))
                n += 1
            except (KeyError, ValueError):
                continue
        return n
