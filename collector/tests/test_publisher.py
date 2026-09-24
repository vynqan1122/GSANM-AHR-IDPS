from __future__ import annotations

import pytest

from collector.base import RedisPublisher, make_raw_event
from collector.health import HealthRegistry


class FakeRedis:
    def __init__(self) -> None:
        self.ids: set[str] = set()
        self.calls = 0

    async def eval(self, _script, _keys, dedupe_key, _stream, *_args):
        self.calls += 1
        if dedupe_key in self.ids:
            return ""
        self.ids.add(dedupe_key)
        return "1-0"


@pytest.mark.asyncio
async def test_atomic_publisher_deduplicates_event_id(tmp_path) -> None:
    client = FakeRedis()
    publisher = RedisPublisher(
        client,
        stream="security.events.raw",
        maxlen=100,
        dedupe_ttl_seconds=60,
        retry_initial_seconds=0.001,
        retry_max_seconds=0.01,
        health=HealthRegistry(tmp_path / "health.json"),
    )
    event = make_raw_event(
        source="nginx",
        source_event_id="request-1",
        observed_at="2026-01-01T00:00:00Z",
        payload={"status": 200},
    )
    assert await publisher.publish(event) is True
    assert await publisher.publish(event) is False
    assert client.calls == 2

