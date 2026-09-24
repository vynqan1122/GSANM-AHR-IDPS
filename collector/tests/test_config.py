from __future__ import annotations

from pathlib import Path

import pytest

from collector.config import CollectorConfig


def test_compose_environment_aliases() -> None:
    config = CollectorConfig.from_env(
        {
            "REDIS_HOST": "cache",
            "REDIS_PORT": "6380",
            "REDIS_PASSWORD": "secret",
            "CHECKPOINT_DIR": "/state",
            "COLLECTOR_HEARTBEAT_PATH": "/health/collector.json",
        }
    )
    assert config.redis_url == "redis://cache:6380/0"
    assert config.redis_password == "secret"
    assert str(config.checkpoint_path) == "/state/checkpoints.sqlite3"
    assert str(config.health_path) == "/health/collector.json"
    assert next(source.path for source in config.file_sources if source.name == "nginx").as_posix() == (
        "/var/log/ahr-nginx/access.jsonl"
    )


def test_yaml_retention_and_source_defaults_are_loaded(tmp_path) -> None:
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text(
        "streams:\n  raw: security.events.raw\n"
        "storage:\n"
        "  raw_event_retention_days: 31\n"
        "  normalized_event_retention_days: 91\n"
        "  cleanup_enabled: false\n"
        "collector:\n"
        "  poll_interval_seconds: 0.25\n"
        "  start_at_end_for_new_files: false\n"
        "  sources:\n    nginx: /tmp/nginx.jsonl\n",
        encoding="utf-8",
    )
    config = CollectorConfig.from_env({"COLLECTOR_CONFIG": str(config_file)})
    assert config.raw_event_retention_days == 31
    assert config.normalized_event_retention_days == 91
    assert config.poll_interval_seconds == 0.25
    assert config.start_at_end_for_new_files is False
    assert next(source.path for source in config.file_sources if source.name == "nginx") == Path("/tmp/nginx.jsonl")


def test_phase3_rejects_destructive_cleanup_enablement(tmp_path) -> None:
    config_file = tmp_path / "pipeline.yml"
    config_file.write_text("storage:\n  cleanup_enabled: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cleanup"):
        CollectorConfig.from_env({"COLLECTOR_CONFIG": str(config_file)})
