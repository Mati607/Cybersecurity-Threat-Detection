"""In-memory provenance graph with bounded size + TTL.

The graph fills with every event going through the pipeline, so we
cap it: nodes evict by ``last_seen`` once we exceed ``max_nodes``, and
the helper :meth:`expire_older_than` lets the API server drop ancient
state on a schedule. Concurrent access from the pipeline worker and
the API thread is guarded by a single ``RLock``.
"""

from __future__ import annotations

import heapq
import json
import pickle
import threading
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set

from ..utils.logging_setup import get_logger
from .nodes import Edge, EdgeKey, EdgeType, Node, NodeKey, NodeType

_log = get_logger(__name__)


class ProvenanceGraph:
    def __init__(self, max_nodes: int = 50_000, max_edges_per_node: int = 256) -> None:
        self.max_nodes = max_nodes
        self.max_edges_per_node = max_edges_per_node
        self._nodes: Dict[NodeKey, Node] = {}
        self._edges: Dict[EdgeKey, Edge] = {}
        self._out: Dict[NodeKey, Set[EdgeKey]] = {}
        self._in: Dict[NodeKey, Set[EdgeKey]] = {}
        self._lock = threading.RLock()

    # --- basic mutation ----------------------------------------------

    def upsert_node(
        self,
        node_type: NodeType,
        identity: str,
        *,
        timestamp: float = 0.0,
        label: Optional[str] = None,
        attrs: Optional[Dict[str, object]] = None,
    ) -> Node:
        key = (node_type.value, identity)
        with self._lock:
            node = self._nodes.get(key)
            if node is None:
                node = Node(type=node_type, identity=identity, label=label)
                self._nodes[key] = node
                self._out[key] = set()
                self._in[key] = set()
            if attrs:
                node.attrs.update(attrs)
            if label and not node.label:
                node.label = label
            if timestamp:
                node.touch(timestamp)
            if len(self._nodes) > self.max_nodes:
                self._evict_oldest(int(self.max_nodes * 0.05))
            return node

    def upsert_edge(
        self,
        src: NodeKey,
        dst: NodeKey,
        edge_type: EdgeType,
        *,
        timestamp: float = 0.0,
        attrs: Optional[Dict[str, object]] = None,
    ) -> Edge:
        key: EdgeKey = (src, dst, edge_type.value)
        with self._lock:
            edge = self._edges.get(key)
            if edge is None:
                edge = Edge(src=src, dst=dst, type=edge_type)
                self._edges[key] = edge
                self._out.setdefault(src, set()).add(key)
                self._in.setdefault(dst, set()).add(key)
            if attrs:
                edge.attrs.update(attrs)
            if timestamp:
                edge.touch(timestamp)
            # bound per-source fanout to avoid runaway memory on noisy hubs
            out_edges = self._out.get(src, set())
            if len(out_edges) > self.max_edges_per_node:
                weakest = min(out_edges, key=lambda k: self._edges[k].last_seen)
                self._remove_edge(weakest)
            return edge

    # --- attribution from detection results -------------------------

    def attribute_detection(self, keys: Iterable[NodeKey], score: float) -> None:
        with self._lock:
            for key in keys:
                node = self._nodes.get(key)
                if node is None:
                    continue
                node.detection_count += 1
                node.detection_score = min(1.0, node.detection_score + score * 0.5)

    # --- queries ----------------------------------------------------

    def node(self, key: NodeKey) -> Optional[Node]:
        with self._lock:
            return self._nodes.get(key)

    def edges_from(self, key: NodeKey) -> List[Edge]:
        with self._lock:
            return [self._edges[k] for k in self._out.get(key, ()) if k in self._edges]

    def edges_to(self, key: NodeKey) -> List[Edge]:
        with self._lock:
            return [self._edges[k] for k in self._in.get(key, ()) if k in self._edges]

    def neighbors(self, key: NodeKey, direction: str = "both") -> List[Node]:
        with self._lock:
            keys: Set[NodeKey] = set()
            if direction in ("out", "both"):
                keys.update(e.dst for e in self.edges_from(key))
            if direction in ("in", "both"):
                keys.update(e.src for e in self.edges_to(key))
            return [self._nodes[k] for k in keys if k in self._nodes]

    def subgraph(self, seeds: Iterable[NodeKey], depth: int = 2) -> "ProvenanceGraph":
        """Return a fresh graph containing the BFS-expansion around seeds."""
        with self._lock:
            frontier = set(k for k in seeds if k in self._nodes)
            visited: Set[NodeKey] = set()
            for _ in range(max(0, depth)):
                next_frontier: Set[NodeKey] = set()
                for k in frontier:
                    visited.add(k)
                    for e in self.edges_from(k):
                        next_frontier.add(e.dst)
                    for e in self.edges_to(k):
                        next_frontier.add(e.src)
                frontier = next_frontier - visited
            visited.update(frontier)

            sub = ProvenanceGraph(max_nodes=self.max_nodes, max_edges_per_node=self.max_edges_per_node)
            for key in visited:
                src_node = self._nodes[key]
                sub.upsert_node(
                    NodeType(src_node.type.value),
                    src_node.identity,
                    label=src_node.label,
                    attrs=dict(src_node.attrs),
                )
                sub._nodes[key].first_seen = src_node.first_seen
                sub._nodes[key].last_seen = src_node.last_seen
                sub._nodes[key].event_count = src_node.event_count
                sub._nodes[key].detection_count = src_node.detection_count
                sub._nodes[key].detection_score = src_node.detection_score
            for key, edge in self._edges.items():
                if edge.src in visited and edge.dst in visited:
                    new_edge = sub.upsert_edge(
                        edge.src, edge.dst,
                        EdgeType(edge.type.value),
                        attrs=dict(edge.attrs),
                    )
                    new_edge.weight = edge.weight
                    new_edge.first_seen = edge.first_seen
                    new_edge.last_seen = edge.last_seen
            return sub

    # --- maintenance ------------------------------------------------

    def expire_older_than(self, cutoff_ts: float) -> int:
        removed = 0
        with self._lock:
            stale = [k for k, n in self._nodes.items() if n.last_seen and n.last_seen < cutoff_ts]
            for key in stale:
                self._remove_node(key)
                removed += 1
        if removed:
            _log.info("graph expired %d nodes older than %.0f", removed, cutoff_ts)
        return removed

    def _evict_oldest(self, count: int) -> None:
        if count <= 0:
            return
        oldest = heapq.nsmallest(count, self._nodes.values(), key=lambda n: n.last_seen)
        for node in oldest:
            self._remove_node(node.key)

    def _remove_node(self, key: NodeKey) -> None:
        self._nodes.pop(key, None)
        for ekey in list(self._out.pop(key, set())):
            self._remove_edge(ekey)
        for ekey in list(self._in.pop(key, set())):
            self._remove_edge(ekey)

    def _remove_edge(self, ekey: EdgeKey) -> None:
        edge = self._edges.pop(ekey, None)
        if edge is None:
            return
        self._out.get(edge.src, set()).discard(ekey)
        self._in.get(edge.dst, set()).discard(ekey)

    # --- iteration --------------------------------------------------

    def nodes(self) -> Iterator[Node]:
        with self._lock:
            for node in list(self._nodes.values()):
                yield node

    def edges(self) -> Iterator[Edge]:
        with self._lock:
            for edge in list(self._edges.values()):
                yield edge

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "nodes": len(self._nodes),
                "edges": len(self._edges),
                "max_nodes": self.max_nodes,
                "max_edges_per_node": self.max_edges_per_node,
            }

    def __len__(self) -> int:
        return len(self._nodes)

    # --- persistence ------------------------------------------------

    def save(self, path: str | Path) -> None:
        with self._lock:
            Path(path).write_bytes(pickle.dumps({
                "nodes": self._nodes,
                "edges": self._edges,
                "out": self._out,
                "in": self._in,
                "max_nodes": self.max_nodes,
                "max_edges_per_node": self.max_edges_per_node,
            }))

    def load(self, path: str | Path) -> "ProvenanceGraph":
        blob = pickle.loads(Path(path).read_bytes())
        with self._lock:
            self._nodes = blob["nodes"]
            self._edges = blob["edges"]
            self._out = blob["out"]
            self._in = blob["in"]
            self.max_nodes = blob.get("max_nodes", self.max_nodes)
            self.max_edges_per_node = blob.get("max_edges_per_node", self.max_edges_per_node)
        return self
