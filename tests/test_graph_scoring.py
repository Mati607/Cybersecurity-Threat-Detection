from threatpipe.graph import (
    EdgeType,
    GraphBuilder,
    NodeType,
    ProvenanceGraph,
    centrality,
    score_subgraph,
    suspicious_paths,
    to_cyto_json,
    to_dot,
)
from threatpipe.ingestion import Event, EventType


def _seed_chain(n: int = 4) -> ProvenanceGraph:
    g = ProvenanceGraph()
    b = GraphBuilder(g)
    b.absorb(Event(host="h", process="bash", pid=10, event_type=EventType.PROCESS, timestamp=1))
    b.absorb(Event(host="h", process="curl", pid=11, parent_pid=10, event_type=EventType.PROCESS, timestamp=2))
    b.absorb(Event(host="h", process="curl", pid=11, dst_ip="1.2.3.4", dst_port=4444,
                   event_type=EventType.NETWORK, timestamp=3))
    return g


def test_score_subgraph_low_without_detections():
    # without any attributed detections, the score is dominated by edge
    # density and stays well below the "suspicious" threshold.
    g = _seed_chain()
    assert score_subgraph(g) < 0.1


def test_score_subgraph_climbs_with_detections():
    g = _seed_chain()
    g.attribute_detection([n.key for n in g.nodes()], score=0.9)
    assert score_subgraph(g) > 0.0


def test_centrality_returns_one_per_node():
    g = _seed_chain()
    c = centrality(g)
    assert set(c) == {n.key for n in g.nodes()}


def test_suspicious_paths_finds_executed_to_connected():
    g = _seed_chain()
    g.attribute_detection([("socket", "1.2.3.4:4444")], score=0.9)
    # walk from the host node so we cross EXECUTED -> CONNECTED chain
    paths = suspicious_paths(g, [("host", "h")], max_depth=4)
    assert any(keys[-1][0] == "socket" for keys in paths)


def test_to_dot_emits_valid_digraph():
    g = _seed_chain()
    dot = to_dot(g)
    assert dot.startswith("digraph")
    assert "->" in dot


def test_to_cyto_json_has_elements_list():
    g = _seed_chain()
    import json
    payload = json.loads(to_cyto_json(g))
    assert "elements" in payload
    groups = {e["group"] for e in payload["elements"]}
    assert {"nodes", "edges"} <= groups
