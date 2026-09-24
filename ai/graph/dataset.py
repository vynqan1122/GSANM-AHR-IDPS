from __future__ import annotations

import json
from typing import Any

import numpy as np

from .graph_builder import DEFAULT_WINDOW_SECONDS, SecurityGraph, build_graphs


EVENT_COLUMNS = (
    "event_id, source_event_id, timestamp, ingestion_timestamp, source, event_type, "
    "category, src_ip, src_port, dst_ip, dst_port, protocol, http, container, "
    "process, user_details, file_details, network, rule, severity, labels, ai, "
    "raw_event, metadata"
)


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def row_to_event(row: Any) -> dict[str, Any]:
    data = dict(row)
    for key in (
        "http",
        "container",
        "process",
        "user_details",
        "file_details",
        "network",
        "rule",
        "labels",
        "ai",
        "raw_event",
        "metadata",
    ):
        data[key] = _json(data.get(key))
    if data.get("timestamp") is not None:
        data["timestamp"] = data["timestamp"].isoformat()
    return data


async def load_labeled_events(connection: Any, limit: int = 5000) -> list[dict[str, Any]]:
    rows = await connection.fetch(
        """
        SELECT e.*,
               lbl.attack_label AS attack_label
        FROM ahr.events e
        JOIN (
            SELECT event_id, bool_or(label <> 'benign') AS attack_label
            FROM ahr.event_labels
            GROUP BY event_id
        ) lbl ON lbl.event_id = e.event_id
        ORDER BY e.timestamp ASC
        LIMIT $1
        """,
        limit,
    )
    events = []
    for row in rows:
        event = row_to_event(row)
        event["attack_label"] = bool(row["attack_label"])
        events.append(event)
    return events


def graphs_and_labels(events: list[dict[str, Any]], window_seconds: int = DEFAULT_WINDOW_SECONDS) -> tuple[list[SecurityGraph], np.ndarray]:
    graphs = build_graphs(events, window_seconds)
    labels = np.array([1 if any(event.get("attack_label") for event in graph.events) else 0 for graph in graphs], dtype=np.int32)
    return graphs, labels
