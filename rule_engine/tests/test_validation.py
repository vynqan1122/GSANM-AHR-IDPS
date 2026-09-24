from __future__ import annotations

from rule_engine.validator import metrics_for, passes, syntax_check
from rule_engine.lifecycle import require_valid_state


def test_suricata_syntax_validation_structural():
    result = syntax_check("suricata", 'alert http any any -> any any (msg:"x"; sid:9100001; rev:1;)')
    assert result.valid


def test_replay_metrics_and_thresholds():
    content = '<group><rule id="9100001" level="7"><field name="event_type">alert</field><description>x</description></rule></group>'
    events = [
        {"event_type": "alert", "source": "wazuh", "attack_label": True},
        {"event_type": "alert", "source": "wazuh", "attack_label": True},
        {"event_type": "http", "source": "nginx", "attack_label": False},
    ]
    measured = metrics_for("wazuh", content, events)
    assert measured["tp"] == 2
    assert measured["fp"] == 0
    assert measured["precision"] == 1.0
    assert passes(measured, {"min_precision": 0.9, "min_recall": 0.75, "max_fpr": 0.02, "min_positive_matches": 2})


def test_lifecycle_states_are_explicit():
    assert require_valid_state("SHADOW") == "shadow"
