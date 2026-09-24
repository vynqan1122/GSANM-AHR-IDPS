"""Structured Nginx access log adapter."""

from __future__ import annotations

from typing import Any, Mapping

from ..base import RawEvent, make_raw_event
from ._common import stable_source_id


def parse_nginx(document: Mapping[str, Any], metadata: Mapping[str, Any]) -> RawEvent:
    timestamp = (
        document.get("timestamp")
        or document.get("time_iso8601")
        or document.get("time")
        or document.get("@timestamp")
    )
    request_id = document.get("request_id") or document.get("trace_id")
    source_id = str(request_id or "").strip() or stable_source_id(
        document,
        (
            timestamp,
            document.get("remote_addr") or document.get("src_ip"),
            document.get("request") or document.get("uri"),
            document.get("status"),
            document.get("request_time"),
            document.get("bytes_sent"),
        ),
    )
    return make_raw_event(
        source="nginx",
        source_event_id=source_id,
        observed_at=timestamp,
        payload=document,
        metadata=metadata,
    )

