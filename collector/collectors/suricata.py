"""Suricata EVE JSON adapter."""

from __future__ import annotations

from typing import Any, Mapping

from ..base import RawEvent, make_raw_event
from ._common import nested, stable_source_id


def parse_suricata(document: Mapping[str, Any], metadata: Mapping[str, Any]) -> RawEvent:
    timestamp = document.get("timestamp")
    source_id = stable_source_id(
        document,
        (
            timestamp,
            document.get("event_type"),
            document.get("flow_id"),
            document.get("tx_id"),
            document.get("pcap_cnt"),
            nested(document, "alert", "signature_id"),
            nested(document, "alert", "action"),
        ),
    )
    return make_raw_event(
        source="suricata",
        source_event_id=source_id,
        observed_at=timestamp,
        payload=document,
        metadata=metadata,
    )

