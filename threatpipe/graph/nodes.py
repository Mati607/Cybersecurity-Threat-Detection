"""Node and edge primitives for the provenance graph.

We keep the data model intentionally small: a node is keyed by a
``(type, identity)`` tuple so that the same process across two events
collapses into a single graph node, and an edge is keyed by
``(src_key, dst_key, type)`` so repeated observations bump a weight
rather than creating duplicate edges.

The original research notebooks in ``system/`` work on full DARPA
provenance traces — this is the on-line equivalent: streamed
:class:`~threatpipe.ingestion.Event` objects fold into the same kind of
graph so detectors can ask graph-shaped questions ("did this process
later contact an external IP?") without having to wait for an offline
batch run.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


class NodeType(str, enum.Enum):
    HOST = "host"
    PROCESS = "process"
    USER = "user"
    FILE = "file"
    SOCKET = "socket"
    DOMAIN = "domain"
    HASH = "hash"
    UNKNOWN = "unknown"


class EdgeType(str, enum.Enum):
    SPAWNED = "spawned"
    EXECUTED = "executed"
    READ = "read"
    WROTE = "wrote"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    OWNS = "owns"
    HOSTED_BY = "hosted_by"
    RESOLVED_TO = "resolved_to"
    HASH_OF = "hash_of"


NodeKey = Tuple[str, str]  # (type, identity)
EdgeKey = Tuple[NodeKey, NodeKey, str]


@dataclass
class Node:
    type: NodeType
    identity: str
    label: Optional[str] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    event_count: int = 0
    attrs: Dict[str, Any] = field(default_factory=dict)
    detection_score: float = 0.0
    detection_count: int = 0

    @property
    def key(self) -> NodeKey:
        return (self.type.value, self.identity)

    def touch(self, timestamp: float) -> None:
        if self.first_seen == 0.0 or timestamp < self.first_seen:
            self.first_seen = timestamp
        if timestamp > self.last_seen:
            self.last_seen = timestamp
        self.event_count += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "identity": self.identity,
            "label": self.label or self.identity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "detection_score": round(self.detection_score, 4),
            "detection_count": self.detection_count,
            "attrs": dict(self.attrs),
        }


@dataclass
class Edge:
    src: NodeKey
    dst: NodeKey
    type: EdgeType
    weight: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    attrs: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> EdgeKey:
        return (self.src, self.dst, self.type.value)

    def touch(self, timestamp: float) -> None:
        self.weight += 1
        if self.first_seen == 0.0 or timestamp < self.first_seen:
            self.first_seen = timestamp
        if timestamp > self.last_seen:
            self.last_seen = timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": list(self.src),
            "dst": list(self.dst),
            "type": self.type.value,
            "weight": self.weight,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attrs": dict(self.attrs),
        }


def node_key(node_type: NodeType, identity: str) -> NodeKey:
    return (node_type.value, identity)
