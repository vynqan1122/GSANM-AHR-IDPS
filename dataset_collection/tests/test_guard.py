from __future__ import annotations

import pytest

from dataset_collection.guard import UnsafeTarget, assert_lab_target


def test_loopback_targets_are_allowed() -> None:
    assert assert_lab_target("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    assert assert_lab_target("http://nginx/") == "http://nginx"


def test_external_target_aborts() -> None:
    with pytest.raises(UnsafeTarget):
        assert_lab_target("https://example.com/")
