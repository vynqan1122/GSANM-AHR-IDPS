"""Wazuh manager alerts.json adapter."""

from __future__ import annotations

from typing import Any, Mapping

from ..base import RawEvent, make_raw_event
from ._common import nested, stable_source_id


def parse_wazuh(document: Mapping[str, Any], metadata: Mapping[str, Any]) -> RawEvent:
    timestamp = document.get("timestamp")
    source_id = str(document.get("id") or "").strip() or stable_source_id(
        document,
        (
            timestamp,
            nested(document, "agent", "id"),
            nested(document, "rule", "id"),
            nested(document, "manager", "name"),
            nested(document, "data", "integration"),
            document.get("full_log"),
        ),
    )
    return make_raw_event(
        source="wazuh",
        source_event_id=source_id,
        observed_at=timestamp,
        payload=document,
        metadata=metadata,
    )

