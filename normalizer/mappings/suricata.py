"""Suricata EVE JSON mapping."""

from __future__ import annotations

from normalizer.schemas import (
    HTTPDetails,
    NetworkDetails,
    RawEnvelope,
    RuleDetails,
    SecurityEvent,
)

from .common import actual_labels, as_int, as_str, base, first, nonempty


SURICATA_SEVERITY = {1: 9, 2: 7, 3: 5, 4: 3}


def map_suricata(envelope: RawEnvelope) -> SecurityEvent:
    data = envelope.payload
    event_type = as_str(first(data, "event_type")) or "event"
    alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    flow = data.get("flow") if isinstance(data.get("flow"), dict) else {}
    http_data = data.get("http") if isinstance(data.get("http"), dict) else {}
    priority = as_int(alert.get("severity"), minimum=1)
    severity = SURICATA_SEVERITY.get(priority) if priority is not None else None
    category = as_str(alert.get("category")) or (
        f"network.{event_type}" if event_type != "alert" else "network.alert"
    )

    http = nonempty(
        HTTPDetails,
        method=as_str(first(http_data, "http_method", "method")),
        host=as_str(first(http_data, "hostname", "host")),
        uri=as_str(first(http_data, "url", "uri")),
        status=as_int(first(http_data, "status"), minimum=100, maximum=999),
        user_agent=as_str(first(http_data, "http_user_agent", "user_agent")),
        referer=as_str(first(http_data, "http_refer", "referer")),
        response_length=as_int(
            first(http_data, "http_content_len", "response_length"), minimum=0
        ),
    )
    network = nonempty(
        NetworkDetails,
        interface=as_str(first(data, "in_iface")),
        direction=as_str(first(flow, "flow_state", "direction")),
        flow_id=as_str(first(data, "flow_id")),
        community_id=as_str(first(data, "community_id")),
        packets_to_server=as_int(first(flow, "pkts_toserver"), minimum=0),
        packets_to_client=as_int(first(flow, "pkts_toclient"), minimum=0),
        bytes_to_server=as_int(first(flow, "bytes_toserver"), minimum=0),
        bytes_to_client=as_int(first(flow, "bytes_toclient"), minimum=0),
        state=as_str(first(flow, "state", "reason")),
    )
    rule = nonempty(
        RuleDetails,
        engine="suricata" if alert else None,
        rule_id=as_str(first(alert, "signature_id")),
        name=as_str(first(alert, "signature")),
        category=as_str(first(alert, "category")),
        severity=severity,
        tags=[],
    )
    values = base(envelope, event_type, category)
    values.update(
        src_ip=as_str(first(data, "src_ip")),
        src_port=as_int(first(data, "src_port"), maximum=65535),
        dst_ip=as_str(first(data, "dest_ip", "dst_ip")),
        dst_port=as_int(first(data, "dest_port", "dst_port"), maximum=65535),
        protocol=(as_str(first(data, "proto")) or "").lower() or None,
        http=http,
        network=network,
        rule=rule,
        severity=severity,
        labels=actual_labels(envelope),
    )
    return SecurityEvent(**values)

