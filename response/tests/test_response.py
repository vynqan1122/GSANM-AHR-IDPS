from __future__ import annotations

import pytest

from response.container import safe_isolation_plan
from response.firewall import is_lab_ip, temporary_lab_block
from response.policy import ResponseConfig, critical_response_eligible, decide_response
from response.rollback import rollback_record


def critical_incident() -> dict[str, object]:
    return {
        "incident_id": "inc-test",
        "risk_score": 0.91,
        "severity": 9,
        "event_count": 3,
        "source_ips": ["127.0.0.1"],
        "rule_summary": {"matched_rules": [{"rule_id": "sid-1"}], "rule_match_count": 1},
        "ai_summary": {"max_scores": {"network_score": 0.8, "log_score": 0.2, "graph_score": 0.1, "fusion_score": 0.91}},
        "attack_graph": {"edges": [{"relationship": "reached"}, {"relationship": "spawned"}]},
    }


def test_policy_does_not_depend_on_ai_alone() -> None:
    incident = critical_incident()
    incident["rule_summary"] = {"matched_rules": [], "rule_match_count": 0}
    incident["ai_summary"] = {"max_scores": {"network_score": 0.1, "log_score": 0.1, "graph_score": 0.1, "fusion_score": 0.95}}
    incident["attack_graph"] = {"edges": []}
    eligible, reason = critical_response_eligible(incident, ResponseConfig())
    assert not eligible
    assert "AI risk alone" in reason


def test_alert_only_mode_downgrades_automatic_block() -> None:
    decision = decide_response(
        critical_incident(),
        ResponseConfig(mode="alert_only", automatic_block=True, automatic_container_isolation=True),
    )
    assert decision.action == "alert"
    assert decision.level == 1
    assert "alert_only" in decision.reason


def test_lab_firewall_blocks_only_lab_addresses() -> None:
    assert is_lab_ip("127.0.0.1")
    block = temporary_lab_block("127.0.0.1", incident_id="inc-test", ttl_seconds=30)
    assert block.tag.startswith("AHR-IDPS:inc-test")
    assert block.applied is False
    with pytest.raises(ValueError):
        temporary_lab_block("8.8.8.8", incident_id="inc-test")


def test_container_isolation_never_deletes_artifacts() -> None:
    plan = safe_isolation_plan("ahr-idps-dvwa-1")
    assert plan.action == "disconnect_application_network"
    assert not plan.deletes_container
    assert not plan.deletes_volumes
    assert not plan.deletes_logs
    with pytest.raises(ValueError):
        safe_isolation_plan("postgres")


def test_rollback_record_is_non_destructive() -> None:
    record = rollback_record({"response_id": "rsp-1", "action": "lab_block", "target": "127.0.0.1", "rollback_data": {"token": "abc"}})
    assert record["rollback_status"] == "rolled_back"
    assert record["destructive"] is False

