"""Read-only query facade over :class:`ProvenanceGraph`.

The API server exposes these primitives via ``GET /graph/...`` so we
funnel the request shapes through a single class rather than letting
the handler poke at internal collections directly.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from .nodes import NodeKey, NodeType
from .provenance import ProvenanceGraph
from .scoring import centrality, score_subgraph, suspicious_paths


class GraphQuery:
    def __init__(self, graph: ProvenanceGraph) -> None:
        self.graph = graph

    def stats(self) -> Dict[str, int]:
        return self.graph.stats()

    def top_nodes(self, limit: int = 10, by: str = "detection_score") -> List[Dict[str, object]]:
        nodes = list(self.graph.nodes())
        if by == "detection_score":
            nodes.sort(key=lambda n: (n.detection_score, n.detection_count), reverse=True)
        elif by == "centrality":
            cmap = centrality(self.graph)
            nodes.sort(key=lambda n: cmap.get(n.key, 0.0), reverse=True)
        elif by == "event_count":
            nodes.sort(key=lambda n: n.event_count, reverse=True)
        elif by == "last_seen":
            nodes.sort(key=lambda n: n.last_seen, reverse=True)
        else:
            nodes.sort(key=lambda n: n.detection_score, reverse=True)
        return [n.to_dict() for n in nodes[:limit]]

    def find_nodes(self, *, type: Optional[str] = None, identity_contains: Optional[str] = None,
                   limit: int = 100) -> List[Dict[str, object]]:
        out: List[Dict[str, object]] = []
        for node in self.graph.nodes():
            if type and node.type.value != type:
                continue
            if identity_contains and identity_contains not in node.identity:
                continue
            out.append(node.to_dict())
            if len(out) >= limit:
                break
        return out

    def neighbors(self, key: NodeKey, direction: str = "both",
                  limit: int = 100) -> List[Dict[str, object]]:
        nodes = self.graph.neighbors(key, direction=direction)
        return [n.to_dict() for n in nodes[:limit]]

    def subgraph(self, seeds: Iterable[NodeKey], depth: int = 2) -> Dict[str, object]:
        sub = self.graph.subgraph(seeds, depth=depth)
        return {
            "nodes": [n.to_dict() for n in sub.nodes()],
            "edges": [e.to_dict() for e in sub.edges()],
            "score": score_subgraph(sub),
        }

    def suspicious_paths(self, seeds: Iterable[NodeKey], *, depth: int = 4) -> List[List[List[str]]]:
        paths = suspicious_paths(self.graph, seeds, max_depth=depth)
        return [[list(k) for k in path] for path in paths]
