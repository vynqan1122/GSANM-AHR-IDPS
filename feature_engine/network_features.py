from __future__ import annotations

from typing import Any

from .encoders import port_class, protocol_flags
from .versioning import NETWORK_FEATURES, assert_no_feature_leakage
from .event_contract import decode_event


def _num(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _json_get(document: Any, *path: str) -> Any:
    current = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def build_network_features(row: dict[str, Any]) -> list[float]:
    row = decode_event(row)
    assert_no_feature_leakage()
    protocol_tcp, protocol_udp, protocol_http = protocol_flags(row.get("protocol"))
    http_status = _json_get(row.get("http"), "status") or _json_get(row.get("raw_event"), "http", "status")
    network = row.get("network") if isinstance(row.get("network"), dict) else {}
    packets_total = _num(network.get("packets_to_server")) + _num(network.get("packets_to_client"))
    bytes_total = _num(network.get("bytes_to_server")) + _num(network.get("bytes_to_client"))
    dst_port = int(_num(row.get("dst_port"))) if row.get("dst_port") is not None else None
    event_type = str(row.get("event_type") or "").lower()
    return [
        _num(row.get("src_port")),
        _num(row.get("dst_port")),
        port_class(dst_port),
        protocol_tcp,
        protocol_udp,
        protocol_http,
        1.0 if row.get("src_ip") else 0.0,
        1.0 if row.get("dst_ip") else 0.0,
        1.0 if row.get("container") else 0.0,
        1.0 if row.get("rule") else 0.0,
        _num(row.get("severity")),
        1.0 if event_type == "alert" else 0.0,
        1.0 if event_type == "http" else 0.0,
        1.0 if event_type == "flow" else 0.0,
        bytes_total,
        packets_total,
        1.0 if _num(http_status) >= 400 else 0.0,
        _num(row.get("connections_per_window")),
        _num(row.get("unique_dst_per_window")),
        _num(row.get("request_rate")),
        _num(row.get("error_rate")),
    ]


def feature_names() -> list[str]:
    return list(NETWORK_FEATURES)
