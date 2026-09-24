"""Falco JSON output adapter."""

from __future__ import annotations

from typing import Any, Mapping

from ..base import RawEvent, make_raw_event
from ._common import nested, stable_source_id


def parse_falco(document: Mapping[str, Any], metadata: Mapping[str, Any]) -> RawEvent:
    timestamp = document.get("time") or document.get("timestamp")
    source_id = stable_source_id(
        document,
        (
            timestamp,
            document.get("uuid"),
            document.get("rule"),
            nested(document, "output_fields", "evt.time"),
            nested(document, "output_fields", "evt.num"),
            nested(document, "output_fields", "proc.pid"),
            nested(document, "output_fields", "container.id"),
        ),
    )
    return make_raw_event(
        source="falco",
        source_event_id=source_id,
        observed_at=timestamp,
        payload=document,
        metadata=metadata,
    )

