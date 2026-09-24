"""Defensive extraction helpers shared by source mappings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from normalizer.schemas import RawEnvelope


def first(data: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        # Falco and some Wazuh decoders use literal dotted keys.  Prefer the
        # exact key before interpreting dots as nested-object traversal.
        if path in data and data[path] is not None and data[path] != "":
            return data[path]
        current: Any = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current is not None and current != "":
            return current
    return None


def as_str(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value)


def as_int(value: Any, *, minimum: int = 0, maximum: int | None = None) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if number < minimum or (maximum is not None and number > maximum):
        return None
    return number


def as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return None


def timestamp(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            raw = float(value)
        except (OverflowError, ValueError):
            return fallback
        # Docker timeNano and common millisecond timestamps are both accepted.
        if raw > 1e17:
            raw /= 1e9
        elif raw > 1e12:
            raw /= 1e3
        try:
            parsed = datetime.fromtimestamp(raw, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return fallback
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return fallback
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            try:
                return timestamp(float(candidate), fallback)
            except ValueError:
                return fallback
    else:
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def base(envelope: RawEnvelope, event_type: str, category: str | None) -> dict[str, Any]:
    return {
        "schema_version": envelope.schema_version,
        "event_id": envelope.event_id,
        "source_event_id": envelope.source_event_id,
        "timestamp": timestamp(
            first(
                envelope.payload,
                "timestamp",
                "time",
                "@timestamp",
                "time_iso8601",
            ),
            envelope.observed_at,
        ),
        "ingestion_timestamp": envelope.ingested_at,
        "source": envelope.source.lower(),
        "event_type": event_type,
        "category": category,
        "raw": envelope.payload,
        "metadata": envelope.metadata,
    }


def nonempty(model_type: type, **values: Any) -> Any:
    cleaned = {
        key: value
        for key, value in values.items()
        if value is not None and value != {} and value != []
    }
    return model_type(**cleaned) if cleaned else None


def actual_labels(envelope: RawEnvelope, *candidates: Any) -> dict[str, str | int | float | bool | None]:
    result: dict[str, str | int | float | bool | None] = {}
    for candidate in (envelope.metadata.get("labels"), *candidates):
        if not isinstance(candidate, dict):
            continue
        for key, value in candidate.items():
            if isinstance(key, str) and (
                value is None or isinstance(value, (str, int, float, bool))
            ):
                result[key] = value
    return result
