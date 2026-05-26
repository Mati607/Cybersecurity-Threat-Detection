"""Graph serialization helpers (Graphviz DOT + Cytoscape JSON).

These are intentionally the only places where graph state is rendered
for non-Python consumers — keeping the responsibility centralized means
the rest of the codebase never has to think about visualization
format compatibility.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .provenance import ProvenanceGraph


_NODE_COLORS = {
    "host": "#5a8fbb",
    "process": "#e0a458",
    "user": "#9b59b6",
    "file": "#48bb78",
    "socket": "#e74c3c",
    "domain": "#f1c40f",
    "hash": "#8e44ad",
    "unknown": "#bdc3c7",
}


def to_dot(graph: ProvenanceGraph, *, title: str = "threatpipe-graph") -> str:
    lines: List[str] = [f'digraph "{title}" {{', "  rankdir=LR;", "  node [style=filled, fontname=Helvetica];"]
    node_ids: Dict[tuple, str] = {}
    for i, node in enumerate(graph.nodes()):
        nid = f"n{i}"
        node_ids[node.key] = nid
        color = _NODE_COLORS.get(node.type.value, "#dddddd")
        label = (node.label or node.identity).replace('"', "'")
        score = f"\\nscore={node.detection_score:.2f}" if node.detection_score else ""
        lines.append(
            f'  {nid} [label="{node.type.value}\\n{label}{score}", fillcolor="{color}"];'
        )
    for edge in graph.edges():
        src = node_ids.get(edge.src)
        dst = node_ids.get(edge.dst)
        if not src or not dst:
            continue
        lines.append(
            f'  {src} -> {dst} [label="{edge.type.value} (x{edge.weight})"];'
        )
    lines.append("}")
    return "\n".join(lines)


def to_cyto_json(graph: ProvenanceGraph) -> str:
    """Cytoscape.js compatible JSON, easy to drop into a HTML dashboard."""
    elements: List[Dict] = []
    for node in graph.nodes():
        data = node.to_dict()
        data["id"] = f"{node.type.value}|{node.identity}"
        elements.append({"data": data, "group": "nodes"})
    for edge in graph.edges():
        src_id = f"{edge.src[0]}|{edge.src[1]}"
        dst_id = f"{edge.dst[0]}|{edge.dst[1]}"
        edata = edge.to_dict()
        edata.update({"id": f"{src_id}->{dst_id}::{edge.type.value}", "source": src_id, "target": dst_id})
        elements.append({"data": edata, "group": "edges"})
    return json.dumps({"elements": elements})
