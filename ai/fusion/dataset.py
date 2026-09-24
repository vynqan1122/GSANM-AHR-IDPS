from __future__ import annotations

from typing import Any

import numpy as np

from ai.graph.dataset import row_to_event

from .scoring import parse_timestamp, score_components, weighted_baseline


FEATURE_NAMES = (
    "rule_score",
    "network_score",
    "log_score",
    "graph_score",
    "context_score",
    "severity",
    "event_density",
    "missing_count",
)


async def event_density(connection: Any, event: dict[str, Any], seconds: int = 60) -> float:
    timestamp = parse_timestamp(event["timestamp"])
    row = await connection.fetchrow(
        """
        SELECT count(*)::float AS density
        FROM ahr.events
        WHERE timestamp BETWEEN $1::timestamptz - ($2::int * interval '1 second')
                            AND $1::timestamptz + ($2::int * interval '1 second')
          AND ($3::text IS NULL OR src_ip = $3::text)
        """,
        timestamp,
        seconds,
        event.get("src_ip"),
    )
    return float(row["density"] if row else 0.0)


async def load_training_rows(connection: Any) -> list[dict[str, Any]]:
    rows = await connection.fetch(
        """
        SELECT e.*, lbl.attack_label
        FROM ahr.events e
        JOIN (
            SELECT event_id, bool_or(label <> 'benign') AS attack_label
            FROM ahr.event_labels
            GROUP BY event_id
        ) lbl ON lbl.event_id = e.event_id
        ORDER BY e.timestamp ASC
        """
    )
    events: list[dict[str, Any]] = []
    for row in rows:
        event = row_to_event(row)
        event["attack_label"] = bool(row["attack_label"])
        events.append(event)
    return events


def feature_vector(event: dict[str, Any], density: float = 0.0) -> list[float]:
    components = score_components(event, density)
    baseline = weighted_baseline(components)
    return [
        float(components.get("rule_score") or 0.0),
        float(components.get("network_score") or 0.0),
        float(components.get("log_score") or 0.0),
        float(components.get("graph_score") or 0.0),
        float(components.get("context_score") or 0.0),
        float(event.get("severity") or 0.0) / 10.0,
        min(float(density), 25.0) / 25.0,
        float(len(baseline.missing_scores)) / 5.0,
    ]


async def matrix(connection: Any, events: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    rows = []
    for event in events:
        rows.append(feature_vector(event, await event_density(connection, event)))
    labels = np.array([1 if event.get("attack_label") else 0 for event in events], dtype=np.int32)
    return np.array(rows, dtype=np.float32), labels
