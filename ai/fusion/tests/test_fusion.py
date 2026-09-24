from __future__ import annotations

from ai.fusion.dataset import feature_vector
from ai.fusion.scoring import rule_score, weighted_baseline


def test_missing_scores_renormalize_available_weights():
    result = weighted_baseline(
        {
            "rule_score": 0.8,
            "network_score": None,
            "log_score": None,
            "graph_score": 0.4,
            "context_score": 0.2,
        }
    )
    assert result.fusion_score > 0.0
    assert "network_score" in result.missing_scores
    assert abs(sum(result.normalized_weights.values()) - 1.0) < 1e-6
    assert result.normalized_weights["rule_score"] > result.normalized_weights["context_score"]


def test_rule_score_is_not_binary_match():
    low = rule_score({"source": "nginx", "severity": 1, "rule": {"confidence": 0.2}})
    high = rule_score({"source": "suricata", "severity": 9, "rule": {"confidence": 0.9}})
    assert low is not None and high is not None
    assert 0.0 < low < high < 1.0


def test_feature_vector_has_missing_count_and_density():
    event = {
        "event_id": "e1",
        "severity": 5,
        "rule": {"confidence": 0.5},
        "ai": {"network_score": 0.7},
    }
    vector = feature_vector(event, density=10)
    assert len(vector) == 8
    assert vector[-1] > 0.0

