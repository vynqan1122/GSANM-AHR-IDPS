from __future__ import annotations

from typing import Any

import numpy as np

from feature_engine.network_features import build_network_features, feature_names
from feature_engine.window_features import attach_window_features


async def load_labeled_rows(connection: Any) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in await connection.fetch(
            """
            SELECT e.event_id, e.source, e.event_type, e.category, e.src_ip,
                   e.src_port, e.dst_ip, e.dst_port, e.protocol, e.http,
                   e.container, e.network, e.rule, e.severity, e.raw_event,
                   l.label
            FROM ahr.events e
            JOIN ahr.event_labels l ON l.event_id = e.event_id
            ORDER BY e.timestamp ASC
            """
        )
    ]


async def load_recent_unlabeled(connection: Any, limit: int = 200) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in await connection.fetch(
            """
            SELECT event_id, source, event_type, category, src_ip, src_port,
                   dst_ip, dst_port, protocol, http, container, network, rule,
                   severity, raw_event
            FROM ahr.events
            ORDER BY timestamp DESC
            LIMIT $1
            """,
            limit,
        )
    ]


def to_matrix(rows: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray | None]:
    enriched = attach_window_features(rows)
    x = np.array([build_network_features(row) for row in enriched], dtype=np.float32)
    labels = [row.get("label") for row in enriched]
    y = None
    if all(label is not None for label in labels):
        y = np.array([1 if label == "attack" else 0 for label in labels], dtype=np.int32)
    return x, y


def schema() -> dict[str, object]:
    return {"features": feature_names(), "target": "attack_probability"}
