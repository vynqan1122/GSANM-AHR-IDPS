from __future__ import annotations

from typing import Any

from .sanitizer import sanitize_text
from feature_engine.event_contract import learning_event


def _get(document: dict[str, Any], *path: str) -> Any:
    current: Any = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def normalized_log_text(event: dict[str, Any]) -> str:
    event = learning_event(event)
    source = str(event.get("source") or "")
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    container = event.get("container") if isinstance(event.get("container"), dict) else {}
    http = event.get("http") if isinstance(event.get("http"), dict) else {}
    raw = event.get("raw_event") if isinstance(event.get("raw_event"), dict) else {}
    parts = [
        f"source={source}",
        f"type={event.get('event_type') or ''}",
        f"category={event.get('category') or ''}",
        f"rule={rule.get('name') or rule.get('rule_id') or _get(raw, 'rule', 'description') or ''}",
        f"process={process.get('name') or _get(raw, 'output_fields', 'proc.name') or ''}",
        f"parent={process.get('parent_name') or _get(raw, 'output_fields', 'proc.pname') or ''}",
        f"command={process.get('cmdline') or _get(raw, 'output_fields', 'proc.cmdline') or raw.get('full_log') or ''}",
        f"container={container.get('name') or _get(raw, 'container', 'name') or ''}",
        f"http={http.get('method') or ''} {http.get('uri') or ''} {http.get('status') or ''}",
        f"severity={event.get('severity') if event.get('severity') is not None else ''}",
    ]
    return sanitize_text(" ".join(parts))
