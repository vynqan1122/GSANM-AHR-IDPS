"""Mapping for observed host/service telemetry emitted by the system collector."""

from __future__ import annotations

from normalizer.schemas import RawEnvelope, SecurityEvent

from .common import actual_labels, as_str, base, first


def map_system(envelope: RawEnvelope) -> SecurityEvent:
    data = envelope.payload
    event_type = as_str(first(data, "event_type", "type")) or "telemetry"
    category = as_str(first(data, "category")) or "system.telemetry"
    values = base(envelope, event_type, category)
    values.update(severity=None, labels=actual_labels(envelope))
    return SecurityEvent(**values)

