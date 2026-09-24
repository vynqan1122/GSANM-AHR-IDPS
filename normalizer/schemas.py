"""Canonical, lossless-enough event models used across AHR-IDPS.

The optional fields are intentional: a normalizer must not manufacture a value
that the originating sensor did not observe.  The complete source record is
always retained in ``raw`` for evidence and future parsers.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator


JsonScalar = str | int | float | bool | None
Port = Annotated[int, Field(ge=0, le=65535)]


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HTTPDetails(StrictModel):
    method: str | None = None
    host: str | None = None
    uri: str | None = None
    status: int | None = Field(default=None, ge=100, le=999)
    user_agent: str | None = None
    referer: str | None = None
    request_length: int | None = Field(default=None, ge=0)
    response_length: int | None = Field(default=None, ge=0)


class ContainerDetails(StrictModel):
    id: str | None = None
    name: str | None = None
    image: str | None = None
    runtime: str | None = None
    namespace: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class ProcessDetails(StrictModel):
    pid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    name: str | None = None
    parent_name: str | None = None
    exe: str | None = None
    cmdline: str | None = None


class UserDetails(StrictModel):
    name: str | None = None
    uid: str | None = None
    effective_name: str | None = None
    effective_uid: str | None = None


class FileDetails(StrictModel):
    path: str | None = None
    name: str | None = None
    directory: str | None = None
    operation: str | None = None
    hash_sha256: str | None = None


class NetworkDetails(StrictModel):
    interface: str | None = None
    direction: str | None = None
    flow_id: str | None = None
    community_id: str | None = None
    packets_to_server: int | None = Field(default=None, ge=0)
    packets_to_client: int | None = Field(default=None, ge=0)
    bytes_to_server: int | None = Field(default=None, ge=0)
    bytes_to_client: int | None = Field(default=None, ge=0)
    state: str | None = None


class RuleDetails(StrictModel):
    engine: str | None = None
    rule_id: str | None = None
    name: str | None = None
    category: str | None = None
    severity: int | None = Field(default=None, ge=0, le=10)
    tags: list[str] = Field(default_factory=list)


class AIFields(StrictModel):
    network_score: float | None = None
    network_class: str | None = None
    log_score: float | None = None
    graph_score: float | None = None
    fusion_score: float | None = None
    risk_level: str | None = None
    model_versions: dict[str, str] = Field(default_factory=dict)


class SecurityEvent(StrictModel):
    schema_version: str = "1.0"
    event_id: str = Field(min_length=1, max_length=256)
    source_event_id: str | None = Field(default=None, max_length=512)
    timestamp: datetime
    ingestion_timestamp: datetime
    source: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=128)
    category: str | None = Field(default=None, max_length=128)
    src_ip: str | None = Field(default=None, max_length=128)
    src_port: Port | None = None
    dst_ip: str | None = Field(default=None, max_length=128)
    dst_port: Port | None = None
    protocol: str | None = Field(default=None, max_length=32)
    http: HTTPDetails | None = None
    container: ContainerDetails | None = None
    process: ProcessDetails | None = None
    user: UserDetails | None = None
    file: FileDetails | None = None
    network: NetworkDetails | None = None
    rule: RuleDetails | None = None
    severity: int | None = Field(default=None, ge=0, le=10)
    labels: dict[str, JsonScalar] = Field(default_factory=dict)
    ai: AIFields = Field(default_factory=AIFields)
    raw: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", "ingestion_timestamp")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class RawEnvelope(StrictModel):
    schema_version: str = Field(default="1.0", min_length=1, max_length=32)
    event_id: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=64)
    source_event_id: str | None = Field(default=None, max_length=512)
    observed_at: datetime
    ingested_at: datetime
    payload: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @classmethod
    def from_stream_fields(cls, fields: dict[str, Any]) -> "RawEnvelope":
        def text(name: str, default: str | None = None) -> str | None:
            value = fields.get(name, default)
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="strict")
            return value

        try:
            payload_value = text("payload")
            metadata_value = text("metadata", "{}")
            payload = json.loads(payload_value or "")
            metadata = json.loads(metadata_value or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("raw stream payload/metadata is not valid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(metadata, dict):
            raise ValueError("raw stream payload and metadata must be JSON objects")
        observed_at = text("observed_at")
        return cls(
            schema_version=text("schema_version", "1.0"),
            event_id=text("event_id"),
            source=text("source"),
            source_event_id=text("source_event_id") or None,
            observed_at=observed_at,
            # Compatibility with early collectors that only emitted observed_at.
            ingested_at=text("ingested_at") or observed_at,
            payload=payload,
            metadata=metadata,
        )
