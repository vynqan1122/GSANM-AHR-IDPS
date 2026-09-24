from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .edge_builder import EDGE_TYPES, EdgeBuilder, GraphEdge
from .feature_builder import graph_feature_vector
from .node_registry import NODE_TYPES, GraphNode, NodeRegistry


ALLOWED_WINDOWS = {10, 30, 60, 120}
DEFAULT_WINDOW_SECONDS = 30


@dataclass(slots=True)
class SecurityGraph:
    graph_id: str
    session_key: str
    window_start: datetime
    window_seconds: int
    events: list[dict[str, Any]] = field(default_factory=list)
    registry: NodeRegistry = field(default_factory=NodeRegistry)
    edges: list[GraphEdge] = field(default_factory=list)

    @property
    def nodes(self) -> list[GraphNode]:
        return self.registry.values()

    def add_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        self.edges.extend(EdgeBuilder(self.registry).from_event(event))

    def feature_vector(self):
        return graph_feature_vector(self.nodes, self.edges)

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "session_key": self.session_key,
            "window_start": self.window_start.isoformat(),
            "window_seconds": self.window_seconds,
            "node_types": NODE_TYPES,
            "edge_types": EDGE_TYPES,
            "event_ids": [event["event_id"] for event in self.events if event.get("event_id")],
            "nodes": [
                {
                    "id": node.node_id,
                    "type": node.node_type,
                    "value": node.value,
                    "attrs": node.attrs,
                    "event_ids": sorted(node.event_ids),
                }
                for node in self.nodes
            ],
            "edges": [edge.to_dict() for edge in self.edges],
        }


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    text = str(value or "").replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_window_seconds(window_seconds: int) -> int:
    if window_seconds not in ALLOWED_WINDOWS:
        raise ValueError(f"window_seconds must be one of {sorted(ALLOWED_WINDOWS)}")
    return window_seconds


def window_start(timestamp: datetime, window_seconds: int) -> datetime:
    epoch = int(timestamp.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % window_seconds), timezone.utc)


def session_key(event: dict[str, Any], window_seconds: int = DEFAULT_WINDOW_SECONDS) -> str:
    timestamp = parse_time(event.get("timestamp"))
    bucket = int(window_start(timestamp, window_seconds).timestamp())
    container = event.get("container") if isinstance(event.get("container"), dict) else {}
    http = event.get("http") if isinstance(event.get("http"), dict) else {}
    network = event.get("network") if isinstance(event.get("network"), dict) else {}
    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    components = [
        event.get("src_ip") or "src:none",
        container.get("name") or container.get("image") or "container:none",
        http.get("session_id") or http.get("cookie_hash") or "http:none",
        network.get("flow_id") or f"{event.get('src_port')}->{event.get('dst_port')}",
        process.get("parent") or process.get("ppid") or "process:none",
        str(bucket),
    ]
    digest = hashlib.sha1("|".join(map(str, components)).encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"session:{digest}"


def build_graphs(events: list[dict[str, Any]], window_seconds: int = DEFAULT_WINDOW_SECONDS) -> list[SecurityGraph]:
    validate_window_seconds(window_seconds)
    graphs: dict[str, SecurityGraph] = {}
    for event in sorted(events, key=lambda item: parse_time(item.get("timestamp"))):
        key = session_key(event, window_seconds)
        ts = parse_time(event.get("timestamp"))
        start = window_start(ts, window_seconds)
        graph_id = hashlib.sha1(f"{key}:{start.isoformat()}".encode("utf-8")).hexdigest()[:24]
        graph = graphs.get(key)
        if graph is None:
            graph = SecurityGraph(graph_id, key, start, window_seconds)
            graphs[key] = graph
        graph.add_event(event)
    return list(graphs.values())


def graph_json(graph: SecurityGraph) -> str:
    return json.dumps(graph.to_dict(), separators=(",", ":"), sort_keys=True, default=str)

