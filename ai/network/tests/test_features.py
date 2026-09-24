from __future__ import annotations

from feature_engine.network_features import build_network_features, feature_names
from feature_engine.versioning import BANNED_LEAKAGE_FIELDS


def test_feature_schema_has_no_label_leakage() -> None:
    assert not BANNED_LEAKAGE_FIELDS.intersection(feature_names())


def test_feature_vector_length_is_stable() -> None:
    row = {
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "http",
        "event_type": "alert",
        "severity": 8,
        "http": {"status": 404},
        "container": {"name": "dvwa"},
        "rule": {"rule_id": "1"},
    }
    assert len(build_network_features(row)) == len(feature_names())
