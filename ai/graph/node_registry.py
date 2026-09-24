from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


NODE_TYPES = (
    "IP",
    "Flow",
    "HTTPRequest",
    "User",
    "Container",
    "Process",
    "File",
    "Database",
    "Domain",
    "Alert",
)


@dataclass(slots=True)
class GraphNode:
    node_id: str
    node_type: str
    value: str
    attrs: dict[str, Any] = field(default_factory=dict)
    event_ids: set[str] = field(default_factory=set)


class NodeRegistry:
    """Stable semantic node registry; IDs are type/value based, not runtime IDs."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], GraphNode] = {}

    @staticmethod
    def make_id(node_type: str, value: str) -> str:
        digest = hashlib.sha1(f"{node_type}:{value}".encode("utf-8", errors="replace")).hexdigest()[:16]
        return f"{node_type.lower()}:{digest}"

    def get(self, node_type: str, value: Any, *, event_id: str | None = None, **attrs: Any) -> GraphNode:
        if node_type not in NODE_TYPES:
            raise ValueError(f"unsupported node type: {node_type}")
        clean_value = str(value or "unknown").strip() or "unknown"
        key = (node_type, clean_value)
        node = self._nodes.get(key)
        if node is None:
            node = GraphNode(self.make_id(node_type, clean_value), node_type, clean_value)
            self._nodes[key] = node
        for name, attr_value in attrs.items():
            if attr_value not in (None, ""):
                node.attrs[name] = attr_value
        if event_id:
            node.event_ids.add(event_id)
        return node

    def values(self) -> list[GraphNode]:
        return list(self._nodes.values())

