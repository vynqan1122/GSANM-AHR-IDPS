from __future__ import annotations

from correlation.attack_chain import build_attack_chain
from correlation.sessionizer import correlation_key


def event(event_id: str, timestamp: str, **overrides):
    base = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": "nginx",
        "event_type": "http",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "container": {"name": "dvwa"},
        "http": {"method": "GET", "uri": "/vulnerabilities/sqli/?id=1"},
        "severity": 5,
        "ai": {"fusion_score": 0.7, "risk_level": "high"},
    }
    base.update(overrides)
    return base


def test_close_events_share_incident_key():
    first = correlation_key(event("e1", "2026-08-27T10:00:00Z"))
    second = correlation_key(event("e2", "2026-08-27T10:04:30Z"))
    assert first.value == second.value
    assert first.incident_id == second.incident_id


def test_separate_time_buckets_do_not_merge():
    first = correlation_key(event("e1", "2026-08-27T10:00:00Z"))
    second = correlation_key(event("e2", "2026-08-27T10:07:00Z"))
    assert first.value == second.value
    assert first.incident_id != second.incident_id


def test_attack_chain_edges_include_timestamps():
    graph = build_attack_chain([event("e1", "2026-08-27T10:00:00Z")])
    assert graph["nodes"]
    assert graph["edges"]
    assert all(edge.get("timestamp") for edge in graph["edges"])
