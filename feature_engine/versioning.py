FEATURES_VERSION = "network-v1"

NETWORK_FEATURES = [
    "src_port",
    "dst_port",
    "dst_port_class",
    "protocol_tcp",
    "protocol_udp",
    "protocol_http",
    "has_src_ip",
    "has_dst_ip",
    "has_container",
    "has_rule",
    "severity",
    "event_type_alert",
    "event_type_http",
    "event_type_flow",
    "bytes_total",
    "packets_total",
    "status_error",
    "connections_per_window",
    "unique_dst_per_window",
    "request_rate",
    "error_rate",
]

BANNED_LEAKAGE_FIELDS = {
    "scenario_id",
    "label",
    "attack_type",
    "timestamp",
    "container_id",
    "attacker_ip",
}


def assert_no_feature_leakage(features: list[str] = NETWORK_FEATURES) -> None:
    leaked = sorted(BANNED_LEAKAGE_FIELDS.intersection(features))
    if leaked:
        raise ValueError(f"feature leakage detected: {leaked}")
