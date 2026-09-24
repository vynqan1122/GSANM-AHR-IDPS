from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Any

import numpy as np

from .edge_builder import EDGE_TYPES, GraphEdge
from .node_registry import NODE_TYPES, GraphNode


FEATURE_VERSION = "graph-features-v1"
NODE_FEATURE_DIM = len(NODE_TYPES) + 12


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _hash01(value: Any, salt: str = "") -> float:
    digest = hashlib.sha1(f"{salt}:{value}".encode("utf-8", errors="replace")).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def node_feature(node: GraphNode, degree: int = 0) -> np.ndarray:
    vector = np.zeros(NODE_FEATURE_DIM, dtype=np.float32)
    vector[NODE_TYPES.index(node.node_type)] = 1.0
    base = len(NODE_TYPES)
    vector[base + 0] = min(degree, 32) / 32.0
    vector[base + 1] = min(len(node.event_ids), 16) / 16.0
    vector[base + 2] = _hash01(node.value, node.node_type)
    vector[base + 3] = _num(node.attrs.get("severity")) / 10.0
    if node.node_type == "IP":
        vector[base + 4] = 1.0 if str(node.attrs.get("role")) == "source" else 0.0
        vector[base + 5] = 1.0 if str(node.value).startswith(("127.", "172.", "10.", "192.168.")) else 0.0
    elif node.node_type == "Process":
        value = str(node.value).lower()
        vector[base + 4] = 1.0 if any(shell in value for shell in ("sh", "bash", "dash", "ash", "cmd", "powershell")) else 0.0
        vector[base + 5] = min(_num(node.attrs.get("depth")), 8) / 8.0
        vector[base + 6] = 1.0 if node.attrs.get("unexpected_child") else 0.0
    elif node.node_type == "HTTPRequest":
        method = str(node.attrs.get("method") or "GET").upper()
        vector[base + 4] = {"GET": 0.1, "POST": 0.45, "PUT": 0.7, "DELETE": 0.9}.get(method, 0.3)
        vector[base + 5] = _num(node.attrs.get("status")) / 599.0
        vector[base + 6] = _hash01(node.value, "uri")
        vector[base + 7] = min(_num(node.attrs.get("request_size")), 10000) / 10000.0
        vector[base + 8] = min(_num(node.attrs.get("response_size")), 100000) / 100000.0
    elif node.node_type == "Container":
        value = f"{node.value} {node.attrs.get('image', '')}".lower()
        vector[base + 4] = 1.0 if "dvwa" in value else 0.0
        vector[base + 5] = 1.0 if "nginx" in value else 0.0
        vector[base + 6] = 1.0 if any(db in value for db in ("database", "postgres", "mariadb", "redis")) else 0.0
    return vector


def adjacency(edges: list[GraphEdge]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        graph[edge.src].add(edge.dst)
        graph[edge.dst].add(edge.src)
    return graph


def edge_type_counts(edges: list[GraphEdge]) -> np.ndarray:
    counts = Counter(edge.edge_type for edge in edges)
    return np.array([counts.get(edge_type, 0) for edge_type in EDGE_TYPES], dtype=np.float32) / max(1, len(edges))


def graph_feature_vector(nodes: list[GraphNode], edges: list[GraphEdge]) -> np.ndarray:
    adj = adjacency(edges)
    if nodes:
        node_vectors = np.vstack([node_feature(node, len(adj.get(node.node_id, set()))) for node in nodes])
    else:
        node_vectors = np.zeros((1, NODE_FEATURE_DIM), dtype=np.float32)
    stats = np.array(
        [
            min(len(nodes), 128) / 128.0,
            min(len(edges), 256) / 256.0,
            float(len(edges)) / max(1.0, float(len(nodes))),
            max((len(adj.get(node.node_id, ())) for node in nodes), default=0) / 32.0,
        ],
        dtype=np.float32,
    )
    return np.concatenate([node_vectors.mean(axis=0), node_vectors.max(axis=0), edge_type_counts(edges), stats])

