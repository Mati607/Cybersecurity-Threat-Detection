from threatpipe.graph import EdgeType, GraphBuilder, NodeType, ProvenanceGraph
from threatpipe.ingestion import Event, EventType


def test_upsert_node_is_idempotent():
    g = ProvenanceGraph()
    a = g.upsert_node(NodeType.HOST, "h1", timestamp=10)
    b = g.upsert_node(NodeType.HOST, "h1", timestamp=20)
    assert a is b
    assert a.first_seen == 10 and a.last_seen == 20
    assert a.event_count == 2


def test_upsert_edge_bumps_weight():
    g = ProvenanceGraph()
    g.upsert_node(NodeType.HOST, "h1", timestamp=1)
    g.upsert_node(NodeType.PROCESS, "p1", timestamp=1)
    edge = g.upsert_edge(("host", "h1"), ("process", "p1"), EdgeType.EXECUTED, timestamp=1)
    g.upsert_edge(("host", "h1"), ("process", "p1"), EdgeType.EXECUTED, timestamp=2)
    assert edge.weight == 2


def test_builder_creates_process_tree():
    g = ProvenanceGraph()
    builder = GraphBuilder(g)
    builder.absorb(Event(
        host="h", process="bash", pid=12, parent_pid=10, event_type=EventType.PROCESS, timestamp=1,
    ))
    keys = {n.key for n in g.nodes()}
    assert ("host", "h") in keys
    assert any(k[0] == "process" for k in keys)
    # parent edge exists
    edges = [e.type.value for e in g.edges()]
    assert "spawned" in edges


def test_builder_returns_touched_keys_for_attribution():
    g = ProvenanceGraph()
    builder = GraphBuilder(g)
    touched = builder.absorb(Event(
        host="h", process="curl", pid=13, dst_ip="1.2.3.4", dst_port=80,
        event_type=EventType.NETWORK, timestamp=1,
    ))
    assert ("host", "h") in touched
    assert any(k[0] == "process" for k in touched)
    assert any(k[0] == "socket" for k in touched)


def test_attribute_detection_updates_node_score():
    g = ProvenanceGraph()
    builder = GraphBuilder(g)
    touched = builder.absorb(Event(host="h", process="bash", pid=1, event_type=EventType.PROCESS, timestamp=1))
    g.attribute_detection(touched, score=0.8)
    node = g.node(touched[0])
    assert node.detection_count == 1
    assert node.detection_score > 0.0


def test_subgraph_extraction():
    g = ProvenanceGraph()
    builder = GraphBuilder(g)
    for i in range(3):
        builder.absorb(Event(
            host="h", process=f"p{i}", pid=10 + i, parent_pid=10 if i > 0 else None,
            event_type=EventType.PROCESS, timestamp=i,
        ))
    sub = g.subgraph([("host", "h")], depth=1)
    assert ("host", "h") in {n.key for n in sub.nodes()}


def test_eviction_when_over_capacity():
    g = ProvenanceGraph(max_nodes=10)
    builder = GraphBuilder(g)
    for i in range(40):
        builder.absorb(Event(host="h", process=f"p{i}", pid=i, event_type=EventType.PROCESS, timestamp=i))
    assert len(g) <= 10


def test_expire_older_than():
    g = ProvenanceGraph()
    builder = GraphBuilder(g)
    builder.absorb(Event(host="h", process="old", pid=1, event_type=EventType.PROCESS, timestamp=10))
    builder.absorb(Event(host="h", process="new", pid=2, event_type=EventType.PROCESS, timestamp=100))
    removed = g.expire_older_than(50)
    assert removed >= 1


def test_save_load_round_trip(tmp_path):
    g = ProvenanceGraph()
    builder = GraphBuilder(g)
    builder.absorb(Event(host="h", process="x", pid=1, event_type=EventType.PROCESS, timestamp=1))
    path = tmp_path / "g.pkl"
    g.save(path)
    fresh = ProvenanceGraph().load(path)
    assert fresh.stats()["nodes"] == g.stats()["nodes"]
