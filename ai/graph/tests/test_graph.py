from __future__ import annotations

import numpy as np

from ai.graph.graph_builder import build_graphs, session_key, validate_window_seconds
from ai.graph.graphsage import GraphSAGEWindowClassifier
from ai.graph.node_registry import NodeRegistry


def sample(event_id: str, src: str, marker: str, label: bool = False):
    return {
        "event_id": event_id,
        "timestamp": "2026-01-01T00:00:01Z",
        "source": "nginx",
        "event_type": "http_request",
        "src_ip": src,
        "dst_ip": "172.20.0.10",
        "dst_port": 80,
        "protocol": "tcp",
        "http": {"method": "GET", "uri": f"/?q={marker}", "status": 200},
        "container": {"name": "dvwa", "image": "ghcr.io/digininja/dvwa"},
        "severity": 2 if not label else 8,
        "attack_label": label,
        "raw_event": {"message": marker},
    }


def test_node_registry_stable_ids():
    registry = NodeRegistry()
    one = registry.get("IP", "127.0.0.1")
    two = registry.get("IP", "127.0.0.1")
    assert one.node_id == two.node_id
    assert len(registry.values()) == 1


def test_allowed_windows_only():
    assert validate_window_seconds(30) == 30
    try:
        validate_window_seconds(45)
    except ValueError:
        pass
    else:
        raise AssertionError("45-second graph windows must be rejected")


def test_sessionization_not_single_giant_window():
    events = [sample("a", "127.0.0.1", "one"), sample("b", "127.0.0.2", "two")]
    assert session_key(events[0]) != session_key(events[1])
    graphs = build_graphs(events, 30)
    assert len(graphs) == 2


def test_graph_contains_required_entities_and_edges():
    graph = build_graphs([sample("a", "127.0.0.1", "marker", True)], 30)[0]
    assert {"IP", "Flow", "HTTPRequest", "Container", "Alert"} <= {node.node_type for node in graph.nodes}
    assert {"CONNECTED_TO", "REQUESTED", "TARGETED", "TRIGGERED"} <= {edge.edge_type for edge in graph.edges}
    assert graph.feature_vector().shape[0] > 20


def test_graphsage_trains_and_predicts():
    graphs = build_graphs(
        [
            sample("a", "127.0.0.1", "benign", False),
            sample("b", "127.0.0.2", "attack", True),
        ],
        30,
    )
    model = GraphSAGEWindowClassifier()
    model.fit(graphs, np.array([0, 1], dtype=np.int32))
    score, baseline, embedding = model.predict_proba(graphs[0])
    assert 0.0 <= score <= 1.0
    assert 0.0 <= baseline <= 1.0
    assert embedding.shape[0] > graphs[0].feature_vector().shape[0]
