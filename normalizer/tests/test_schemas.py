from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from normalizer.schemas import RawEnvelope


def test_wire_envelope_preserves_separate_observed_and_ingested_times():
    envelope = RawEnvelope.from_stream_fields(
        {
            "schema_version": "1.0",
            "event_id": "evt-1",
            "source_event_id": "src-1",
            "source": "nginx",
            "observed_at": "2026-08-13T01:02:03Z",
            "ingested_at": "2026-08-13T01:02:05Z",
            "payload": json.dumps({"status": 200}),
            "metadata": "{}",
        }
    )
    assert envelope.observed_at.isoformat() == "2026-08-13T01:02:03+00:00"
    assert envelope.ingested_at.isoformat() == "2026-08-13T01:02:05+00:00"


def test_wire_envelope_backward_compatible_ingestion_fallback():
    envelope = RawEnvelope.from_stream_fields(
        {
            "event_id": "evt-1",
            "source": "system",
            "observed_at": "2026-08-13T01:02:03+00:00",
            "payload": "{}",
            "metadata": "{}",
        }
    )
    assert envelope.ingested_at == envelope.observed_at


@pytest.mark.parametrize("payload", ["{", "[]", "null", "\udcff"])
def test_malformed_or_non_object_payload_is_rejected(payload):
    with pytest.raises((ValueError, UnicodeEncodeError)):
        RawEnvelope.from_stream_fields(
            {
                "event_id": "evt-1",
                "source": "system",
                "observed_at": "2026-08-13T01:02:03+00:00",
                "payload": payload,
                "metadata": "{}",
            }
        )


def test_missing_event_identity_is_rejected():
    with pytest.raises(ValidationError):
        RawEnvelope.from_stream_fields(
            {
                "source": "system",
                "observed_at": "2026-08-13T01:02:03+00:00",
                "payload": "{}",
                "metadata": "{}",
            }
        )
