from __future__ import annotations

from typing import Any

from .abstraction import abstract_pattern
from .clustering import PatternCluster, cluster_events


def behavior_key(event: dict[str, Any]) -> str:
    http = event.get("http") if isinstance(event.get("http"), dict) else {}
    uri = str(http.get("uri") or http.get("url") or "")
    normalized_uri = uri.split("?", 1)[0]
    container = event.get("container") if isinstance(event.get("container"), dict) else {}
    return "|".join(
        [
            str(event.get("source") or ""),
            str(event.get("event_type") or ""),
            str(http.get("method") or ""),
            normalized_uri,
            str(container.get("name") or ""),
        ]
    )


def high_confidence_events(events: list[dict[str, Any]], *, min_confidence: float) -> list[dict[str, Any]]:
    result = []
    for event in events:
        ai = event.get("ai") if isinstance(event.get("ai"), dict) else {}
        confidence = ai.get("fusion_score")
        if confidence is None:
            confidence = event.get("confidence")
        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError):
            continue
        if confidence_value >= min_confidence:
            row = dict(event)
            row["confidence"] = confidence_value
            row["behavior_key"] = behavior_key(event)
            result.append(row)
    return result


def mine_patterns(events: list[dict[str, Any]], *, min_support: int = 5, min_confidence: float = 0.85) -> list[dict[str, Any]]:
    candidates = high_confidence_events(events, min_confidence=min_confidence)
    patterns = []
    for cluster in cluster_events(candidates, min_support=min_support):
        pattern = abstract_pattern(cluster.events)
        pattern["cluster_key"] = cluster.key
        pattern["support"] = cluster.support
        pattern["confidence"] = cluster.confidence
        pattern["example_event_ids"] = [event["event_id"] for event in cluster.events[:10]]
        patterns.append(pattern)
    return patterns

