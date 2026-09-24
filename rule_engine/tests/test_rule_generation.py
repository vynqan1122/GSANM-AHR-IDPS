from __future__ import annotations

from rule_engine.abstraction import contains_sample_specific_artifact
from rule_engine.engine_selector import select_engine
from rule_engine.generator import render_candidate
from rule_engine.pattern_miner import mine_patterns


def event(idx: int, *, source: str = "nginx", score: float = 0.9):
    return {
        "event_id": f"e{idx}",
        "timestamp": "2026-08-27T10:00:00Z",
        "source": source,
        "event_type": "http" if source == "nginx" else "alert",
        "src_ip": f"10.0.0.{idx}",
        "dst_ip": "10.0.0.10",
        "dst_port": 80,
        "protocol": "tcp",
        "http": {"method": "GET", "uri": f"/vulnerabilities/sqli/?id={idx}"},
        "container": {"name": "dvwa"},
        "ai": {"fusion_score": score},
    }


def test_repeated_high_confidence_anomaly_clusters_and_extracts_pattern():
    patterns = mine_patterns([event(i) for i in range(6)], min_support=5, min_confidence=0.85)
    assert patterns
    assert patterns[0]["support"] == 6
    assert patterns[0]["uri_pattern"] == "/vulnerabilities/sqli/"


def test_engine_selector_maps_network_runtime_host():
    assert select_engine({"type": "network"}) == "suricata"
    assert select_engine({"type": "runtime"}) == "falco"
    assert select_engine({"type": "host"}) == "wazuh"


def test_candidate_is_template_generated_and_not_sample_specific():
    patterns = mine_patterns([event(i) for i in range(6)], min_support=5, min_confidence=0.85)
    pattern = patterns[0]
    content = render_candidate(pattern, "suricata")
    assert "sid:" in content
    assert "10.0.0.1" not in content
    assert not contains_sample_specific_artifact(content, [event(i) for i in range(6)])
