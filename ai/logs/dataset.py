from __future__ import annotations

from typing import Any

import numpy as np

from .minilm import MiniLMEmbedder
from .representation import normalized_log_text

LOG_SOURCES = {"falco", "wazuh", "nginx", "suricata"}


async def load_labeled_logs(connection: Any) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in await connection.fetch(
            """
            SELECT e.event_id, e.source, e.event_type, e.category, e.http,
                   e.container, e.process, e.rule, e.severity, e.raw_event,
                   l.label
            FROM ahr.events e
            JOIN ahr.event_labels l ON l.event_id = e.event_id
            WHERE e.source = ANY($1::text[])
            ORDER BY e.timestamp ASC
            """,
            sorted(LOG_SOURCES),
        )
    ]


def to_embeddings(rows: list[dict[str, Any]], embedder: MiniLMEmbedder | None = None) -> tuple[np.ndarray, np.ndarray, list[str]]:
    embedder = embedder or MiniLMEmbedder()
    texts = [normalized_log_text(row) for row in rows]
    x = embedder.encode(texts)
    y = np.array([1 if row.get("label") == "attack" else 0 for row in rows], dtype=np.int32)
    return x, y, texts
