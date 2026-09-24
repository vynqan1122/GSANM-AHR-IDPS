from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class PatternCluster:
    key: str
    events: list[dict[str, Any]]
    confidence: float

    @property
    def support(self) -> int:
        return len(self.events)


def cluster_events(events: list[dict[str, Any]], *, min_support: int = 5) -> list[PatternCluster]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        key = str(event.get("behavior_key") or event.get("event_type") or "unknown")
        buckets[key].append(event)
    clusters = []
    for key, rows in buckets.items():
        if len(rows) < min_support:
            continue
        confidence = sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows)
        clusters.append(PatternCluster(key=key, events=rows, confidence=confidence))
    return sorted(clusters, key=lambda item: (item.confidence, item.support), reverse=True)

