"""Lightweight graph-analytic helpers.

We deliberately do not pull in NetworkX for the runtime path — every
function here operates on a :class:`ProvenanceGraph` directly so the
on-line service stays dependency-free. The implementations are
straightforward translations of the textbook formulas, optimized for
the read-mostly access pattern the API server has.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Tuple

from .nodes import EdgeType, NodeKey
from .provenance import ProvenanceGraph


def score_subgraph(graph: ProvenanceGraph) -> float:
    """Return a 0..1 score reflecting how "hot" a subgraph looks.

    Combines per-node detection scores with edge-weight density. The
    formula is deliberately monotonic so two attacker-controlled
    subgraphs sort intuitively.
    """
    nodes = list(graph.nodes())
    if not nodes:
        return 0.0
    avg_det = sum(n.detection_score for n in nodes) / len(nodes)
    edge_density = sum(e.weight for e in graph.edges()) / max(1, len(nodes))
    saturated_edges = min(1.0, edge_density / 32.0)
    return min(1.0, 0.7 * avg_det + 0.3 * saturated_edges)


def centrality(graph: ProvenanceGraph) -> Dict[NodeKey, float]:
    """Degree-centrality variant biased by detection score.

    For each node, score = (in_degree + out_degree) / (2*n - 2)
    scaled by ``(1 + detection_score)``. This produces the same
    relative order as plain degree centrality on benign graphs but
    promotes attacker-touched nodes once detections start flowing in.
    """
    nodes = list(graph.nodes())
    n = len(nodes)
    if n < 2:
        return {node.key: 0.0 for node in nodes}
    norm = 2.0 * (n - 1)
    out: Dict[NodeKey, float] = {}
    for node in nodes:
        deg = len(graph.edges_from(node.key)) + len(graph.edges_to(node.key))
        base = deg / norm
        out[node.key] = base * (1.0 + node.detection_score)
    return out


def suspicious_paths(
    graph: ProvenanceGraph,
    seeds: Iterable[NodeKey],
    *,
    max_depth: int = 4,
    min_path_score: float = 0.3,
) -> List[List[NodeKey]]:
    """BFS outward from each seed and return paths whose terminal node
    looks suspicious.

    A path is kept if any node on it (besides the seed) has a
    ``detection_score >= 0.5`` or if a forbidden edge type appears
    (e.g. CONNECTED to an external SOCKET right after EXECUTED).
    """
    paths: List[List[NodeKey]] = []
    seeds = list(seeds)
    for seed in seeds:
        if graph.node(seed) is None:
            continue
        queue: deque[Tuple[NodeKey, List[NodeKey]]] = deque([(seed, [seed])])
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            cur_node = graph.node(current)
            if cur_node is None:
                continue
            terminal_score = _path_score(graph, path)
            if len(path) > 1 and terminal_score >= min_path_score:
                paths.append(list(path))
            if len(path) == max_depth:
                continue
            for edge in graph.edges_from(current):
                if edge.dst in path:
                    continue
                queue.append((edge.dst, path + [edge.dst]))
    # de-dup paths preserving order
    seen = set()
    unique: List[List[NodeKey]] = []
    for path in paths:
        marker = tuple(path)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(path)
    return unique


def _path_score(graph: ProvenanceGraph, path: List[NodeKey]) -> float:
    score = 0.0
    for key in path[1:]:
        node = graph.node(key)
        if node is None:
            continue
        score = max(score, node.detection_score)
    # bonus when the path crosses an EXECUTED→CONNECTED→remote-socket pattern
    if len(path) >= 3:
        for a, b in zip(path[:-1], path[1:]):
            edges = [e for e in graph.edges_from(a) if e.dst == b]
            for e in edges:
                if e.type == EdgeType.CONNECTED:
                    score += 0.15
                elif e.type == EdgeType.WROTE:
                    score += 0.05
    return min(1.0, score)
