from __future__ import annotations

from datetime import datetime, timezone

import pytest

from normalizer.schemas import RawEnvelope


@pytest.fixture
def envelope_factory():
    def build(source: str, payload: dict, **overrides) -> RawEnvelope:
        values = {
            "schema_version": "1.0",
            "event_id": f"{source}-event-1",
            "source_event_id": f"{source}-source-1",
            "observed_at": datetime(2026, 8, 13, 1, 2, 3, tzinfo=timezone.utc),
            "ingested_at": datetime(2026, 8, 13, 1, 2, 4, tzinfo=timezone.utc),
            "source": source,
            "payload": payload,
            "metadata": {},
        }
        values.update(overrides)
        return RawEnvelope(**values)

    return build
