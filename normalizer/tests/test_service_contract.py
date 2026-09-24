from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from normalizer.config import Settings
from normalizer.migration import migration_files
from normalizer.normalizer import Heartbeat, NormalizerService, stream_groups


def test_required_streams_are_created_via_groups_without_seed_events(monkeypatch, tmp_path):
    monkeypatch.setenv("MIGRATIONS_DIR", str(tmp_path))
    settings = Settings.from_env()
    groups = stream_groups(settings)
    assert set(groups) == {
        "security.events.raw",
        "security.events.normalized",
        "security.predictions",
        "security.incidents",
        "security.rules",
        "security.responses",
    }
    assert groups["security.events.raw"] == ("normalizer",)
    # This declaration contains only group metadata; ensure no event/body field exists.
    assert all(isinstance(group, str) for names in groups.values() for group in names)


def test_retention_config_is_loaded_but_cleanup_stays_disabled(monkeypatch, tmp_path):
    config = tmp_path / "pipeline.yml"
    config.write_text(
        "storage:\n"
        "  raw_event_retention_days: 31\n"
        "  normalized_event_retention_days: 91\n"
        "  cleanup_enabled: false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PIPELINE_CONFIG", str(config))
    settings = Settings.from_env()
    assert settings.raw_event_retention_days == 31
    assert settings.normalized_event_retention_days == 91
    assert settings.cleanup_enabled is False


def test_normalizer_rejects_cleanup_enablement(monkeypatch, tmp_path):
    config = tmp_path / "pipeline.yml"
    config.write_text("storage:\n  cleanup_enabled: true\n", encoding="utf-8")
    monkeypatch.setenv("PIPELINE_CONFIG", str(config))
    with pytest.raises(ValueError, match="cleanup"):
        Settings.from_env()


def test_migration_inventory_is_ordered_and_checksummed():
    directory = Path(__file__).parents[1] / "migrations"
    files = migration_files(directory)
    assert [version for version, _, _ in files] == sorted(version for version, _, _ in files)
    assert files[0][0] == "001"
    assert len(files[0][2]) == 64


def test_migration_inventory_rejects_duplicate_versions(tmp_path):
    (tmp_path / "001_first.sql").write_text("SELECT 1;", encoding="utf-8")
    (tmp_path / "001_second.sql").write_text("SELECT 2;", encoding="utf-8")
    with pytest.raises(RuntimeError, match="duplicate migration version"):
        migration_files(tmp_path)


@pytest.mark.asyncio
async def test_transient_dependency_failure_stays_pending(tmp_path):
    class FakeRedis:
        def __init__(self):
            self.acked = False
            self.deleted = False

        def register_script(self, _script):
            async def unused(*_args, **_kwargs):
                return "0-0"

            return unused

        async def incr(self, _key):
            return 999

        async def expire(self, _key, _ttl):
            return True

        async def xack(self, *_args):
            self.acked = True

        async def delete(self, *_args):
            self.deleted = True

    client = FakeRedis()
    settings = SimpleNamespace(publication_ttl_seconds=3600)
    heartbeat = Heartbeat(tmp_path / "heartbeat.json")
    service = NormalizerService(settings, client, object(), heartbeat)
    await service._record_transient_failure("1-0", {}, ConnectionError("temporary"))
    assert client.acked is False
    assert client.deleted is False
    assert heartbeat.counters["transient_errors"] == 1
