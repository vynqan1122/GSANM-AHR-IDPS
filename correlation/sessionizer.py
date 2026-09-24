from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


WINDOW_SECONDS = 300


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _container_name(event: dict[str, Any]) -> str:
    container = event.get("container") if isinstance(event.get("container"), dict) else {}
    return str(container.get("name") or "")


def _flow_id(event: dict[str, Any]) -> str:
    network = event.get("network") if isinstance(event.get("network"), dict) else {}
    raw = event.get("raw_event") if isinstance(event.get("raw_event"), dict) else {}
    return str(network.get("flow_id") or raw.get("flow_id") or "")


def _http_session(event: dict[str, Any]) -> str:
    http = event.get("http") if isinstance(event.get("http"), dict) else {}
    cookie = str(http.get("cookie") or http.get("session") or "")
    if cookie:
        return cookie[:96]
    return str(http.get("method") or "") + ":" + str(http.get("uri") or http.get("url") or "")


def _scenario(event: dict[str, Any]) -> str:
    labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
    return str(labels.get("scenario_id") or labels.get("attack_type") or "")


@dataclass(frozen=True, slots=True)
class SessionKey:
    value: str
    bucket: int
    parts: dict[str, str]

    @property
    def incident_id(self) -> str:
        digest = hashlib.sha256(f"{self.value}:{self.bucket}".encode("utf-8")).hexdigest()
        return f"inc-{digest[:32]}"


def correlation_key(event: dict[str, Any], *, window_seconds: int = WINDOW_SECONDS) -> SessionKey:
    timestamp = parse_time(event["timestamp"])
    bucket = int(timestamp.timestamp()) // window_seconds
    parts = {
        "scenario": _scenario(event),
        "src_ip": str(event.get("src_ip") or ""),
        "dst_ip": str(event.get("dst_ip") or ""),
        "container": _container_name(event),
        "flow": _flow_id(event),
        "http_session": _http_session(event),
        "source": str(event.get("source") or ""),
    }
    if parts["scenario"]:
        stable = f"scenario:{parts['scenario']}"
    elif parts["flow"]:
        stable = f"flow:{parts['flow']}:{parts['src_ip']}:{parts['dst_ip']}"
    else:
        stable = ":".join(
            [
                parts["src_ip"],
                parts["dst_ip"],
                parts["container"],
                parts["http_session"],
                parts["source"],
            ]
        )
    return SessionKey(stable, bucket, parts)

