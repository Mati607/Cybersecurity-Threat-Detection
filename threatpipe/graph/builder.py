"""Translate :class:`~threatpipe.ingestion.Event` objects into graph mutations.

Each event maps to a small bundle of upserts:

* host node for ``event.host``
* user node for ``event.user`` (edge: ``OWNS`` from host -> user, only
  emitted on auth/login events to avoid spamming the graph)
* process node keyed by ``host::process[pid]``
* file/socket/domain nodes where applicable

Edges record verbs (``SPAWNED``, ``EXECUTED``, ``READ``, ``WROTE``,
``CONNECTED``). The builder is stateless so multiple workers can share
the same :class:`ProvenanceGraph` without coordination beyond the
graph's own lock.
"""

from __future__ import annotations

from typing import List, Optional

from ..ingestion.event import Event, EventType
from .nodes import EdgeType, NodeKey, NodeType, node_key
from .provenance import ProvenanceGraph


def _proc_id(event: Event) -> str:
    """Stable identity for a process node within a host."""
    host = event.host or "unknown"
    pid = event.pid if event.pid is not None else "?"
    name = event.process or "?"
    return f"{host}::{name}[{pid}]"


def _parent_proc_id(event: Event) -> Optional[str]:
    if event.parent_pid is None:
        return None
    host = event.host or "unknown"
    return f"{host}::?[{event.parent_pid}]"


class GraphBuilder:
    def __init__(self, graph: ProvenanceGraph) -> None:
        self.graph = graph

    def absorb(self, event: Event) -> List[NodeKey]:
        """Insert the event into the graph and return the touched node keys.

        The pipeline uses the return value to attribute detections back
        to the contributing graph nodes.
        """
        touched: List[NodeKey] = []
        ts = event.timestamp

        if event.host:
            host = self.graph.upsert_node(NodeType.HOST, event.host, timestamp=ts)
            touched.append(host.key)

        proc_key: Optional[NodeKey] = None
        if event.process or event.pid is not None:
            identity = _proc_id(event)
            proc = self.graph.upsert_node(
                NodeType.PROCESS, identity,
                timestamp=ts,
                label=event.process,
                attrs={"pid": event.pid, "command_line": event.command_line},
            )
            proc_key = proc.key
            touched.append(proc_key)
            if event.host:
                self.graph.upsert_edge(
                    node_key(NodeType.HOST, event.host), proc_key,
                    EdgeType.EXECUTED, timestamp=ts,
                )

            parent_id = _parent_proc_id(event)
            if parent_id:
                parent = self.graph.upsert_node(
                    NodeType.PROCESS, parent_id, timestamp=ts,
                    attrs={"pid": event.parent_pid},
                )
                self.graph.upsert_edge(parent.key, proc_key, EdgeType.SPAWNED, timestamp=ts)
                touched.append(parent.key)

        if event.user and event.event_type in (EventType.AUTH, EventType.AUDIT):
            user = self.graph.upsert_node(NodeType.USER, event.user, timestamp=ts)
            touched.append(user.key)
            if event.host:
                self.graph.upsert_edge(
                    node_key(NodeType.HOST, event.host), user.key,
                    EdgeType.AUTHENTICATED, timestamp=ts,
                    attrs={"status": event.status},
                )

        if event.file_path and proc_key:
            file_node = self.graph.upsert_node(
                NodeType.FILE, event.file_path, timestamp=ts,
                attrs={"last_action": event.action},
            )
            touched.append(file_node.key)
            edge_type = EdgeType.WROTE if event.action in ("write", "create") else EdgeType.READ
            self.graph.upsert_edge(proc_key, file_node.key, edge_type, timestamp=ts)

        if event.dst_ip and proc_key:
            sock_id = f"{event.dst_ip}:{event.dst_port or 0}"
            sock = self.graph.upsert_node(
                NodeType.SOCKET, sock_id, timestamp=ts,
                attrs={
                    "ip": event.dst_ip,
                    "port": event.dst_port,
                    "protocol": event.protocol,
                    "bytes_sent": event.bytes_sent,
                    "bytes_recv": event.bytes_recv,
                },
            )
            touched.append(sock.key)
            self.graph.upsert_edge(proc_key, sock.key, EdgeType.CONNECTED, timestamp=ts)

        return touched
