from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .feature_builder import NODE_FEATURE_DIM, adjacency, graph_feature_vector, node_feature
from .graph_builder import SecurityGraph


MODEL_ID = "graphsage-security-event"
MODEL_VERSION = "graphsage-v1"


@dataclass(slots=True)
class GraphExplanation:
    important_nodes: list[dict[str, Any]]
    important_edges: list[dict[str, Any]]
    high_risk_subgraph: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "important_nodes": self.important_nodes,
            "important_edges": self.important_edges,
            "high_risk_subgraph": self.high_risk_subgraph,
        }


class GraphSAGEWindowClassifier:
    """CPU GraphSAGE-style classifier with mean neighbor aggregation."""

    def __init__(self) -> None:
        self.graph_model = make_pipeline(
            StandardScaler(),
            MLPClassifier(hidden_layer_sizes=(32,), random_state=42, max_iter=600),
        )
        self.baseline_model = make_pipeline(
            StandardScaler(),
            MLPClassifier(hidden_layer_sizes=(24,), random_state=43, max_iter=600),
        )
        self.is_fitted = False

    @staticmethod
    def _node_embeddings(graph: SecurityGraph) -> np.ndarray:
        nodes = graph.nodes
        if not nodes:
            return np.zeros((1, NODE_FEATURE_DIM * 2), dtype=np.float32)
        by_id = {node.node_id: node for node in nodes}
        adj = adjacency(graph.edges)
        rows: list[np.ndarray] = []
        for node in nodes:
            self_vec = node_feature(node, len(adj.get(node.node_id, set())))
            neigh = [
                node_feature(by_id[nid], len(adj.get(nid, set())))
                for nid in adj.get(node.node_id, set())
                if nid in by_id
            ]
            neigh_vec = np.mean(neigh, axis=0) if neigh else np.zeros(NODE_FEATURE_DIM, dtype=np.float32)
            rows.append(np.concatenate([self_vec, neigh_vec]))
        return np.vstack(rows)

    @classmethod
    def embed_graph(cls, graph: SecurityGraph) -> np.ndarray:
        node_embeddings = cls._node_embeddings(graph)
        return np.concatenate(
            [
                node_embeddings.mean(axis=0),
                node_embeddings.max(axis=0),
                graph_feature_vector(graph.nodes, graph.edges),
            ]
        )

    @staticmethod
    def baseline_features(graph: SecurityGraph) -> np.ndarray:
        return graph_feature_vector(graph.nodes, graph.edges)

    def fit(self, graphs: list[SecurityGraph], labels: np.ndarray) -> None:
        if len(graphs) < 2 or len(set(labels.tolist())) < 2:
            raise ValueError("GraphSAGE training requires at least two graphs and both classes")
        graph_x = np.vstack([self.embed_graph(graph) for graph in graphs])
        base_x = np.vstack([self.baseline_features(graph) for graph in graphs])
        self.graph_model.fit(graph_x, labels)
        self.baseline_model.fit(base_x, labels)
        self.is_fitted = True

    def predict_proba(self, graph: SecurityGraph) -> tuple[float, float, np.ndarray]:
        if not self.is_fitted:
            raise RuntimeError("model is not fitted")
        embedding = self.embed_graph(graph).reshape(1, -1)
        baseline = self.baseline_features(graph).reshape(1, -1)
        graph_prob = float(self.graph_model.predict_proba(embedding)[0][1])
        baseline_prob = float(self.baseline_model.predict_proba(baseline)[0][1])
        return graph_prob, baseline_prob, embedding.ravel()

    def explain(self, graph: SecurityGraph, graph_score: float) -> GraphExplanation:
        degrees: dict[str, int] = {}
        for edge in graph.edges:
            degrees[edge.src] = degrees.get(edge.src, 0) + 1
            degrees[edge.dst] = degrees.get(edge.dst, 0) + 1
        ranked_nodes = sorted(
            graph.nodes,
            key=lambda node: (degrees.get(node.node_id, 0), len(node.event_ids), float(node.attrs.get("severity") or 0)),
            reverse=True,
        )[:5]
        important_edges = sorted(
            graph.edges,
            key=lambda edge: (edge.weight, edge.edge_type in {"TRIGGERED", "TARGETED", "QUERIED"}),
            reverse=True,
        )[:8]
        return GraphExplanation(
            important_nodes=[
                {"id": node.node_id, "type": node.node_type, "value": node.value, "degree": degrees.get(node.node_id, 0)}
                for node in ranked_nodes
            ],
            important_edges=[edge.to_dict() for edge in important_edges],
            high_risk_subgraph={
                "graph_score": graph_score,
                "event_ids": [event.get("event_id") for event in graph.events],
                "node_count": len(graph.nodes),
                "edge_count": len(graph.edges),
            },
        )

    def evaluate(self, graphs: list[SecurityGraph], labels: np.ndarray) -> dict[str, float]:
        probabilities = np.array([self.predict_proba(graph)[0] for graph in graphs], dtype=np.float32)
        baseline = np.array([self.predict_proba(graph)[1] for graph in graphs], dtype=np.float32)
        predictions = (probabilities >= 0.5).astype(np.int32)
        metrics = {
            "accuracy": accuracy_score(labels, predictions),
            "precision": precision_score(labels, predictions, zero_division=0),
            "recall": recall_score(labels, predictions, zero_division=0),
            "f1": f1_score(labels, predictions, zero_division=0),
            "baseline_mean_probability": float(baseline.mean()),
            "graphsage_mean_probability": float(probabilities.mean()),
        }
        try:
            metrics["roc_auc"] = roc_auc_score(labels, probabilities)
            metrics["baseline_roc_auc"] = roc_auc_score(labels, baseline)
        except ValueError:
            metrics["roc_auc"] = 0.5
            metrics["baseline_roc_auc"] = 0.5
        return {key: float(value) for key, value in metrics.items()}

    def save(self, path: str) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "GraphSAGEWindowClassifier":
        return joblib.load(path)

