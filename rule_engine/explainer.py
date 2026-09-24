from __future__ import annotations

from typing import Any


def explain(pattern: dict[str, Any], *, support: int, confidence: float) -> dict[str, Any]:
    return {
        "summary": f"Repeated {pattern.get('type')} behavior observed {support} times",
        "support": support,
        "confidence": confidence,
        "behavior": {
            "http_method": pattern.get("http_method"),
            "uri_pattern": pattern.get("uri_pattern"),
            "event_type": pattern.get("event_type"),
            "container_role": pattern.get("container_role"),
            "process_family": pattern.get("process_family"),
        },
        "safety": "candidate_only_no_auto_activation",
    }

