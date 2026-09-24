"""Environment-backed configuration for the normalizer service."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path

import yaml


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    redis_host: str
    redis_port: int
    redis_password: str | None
    postgres_host: str
    postgres_port: int
    postgres_db: str
    postgres_user: str
    postgres_password: str
    raw_stream: str
    normalized_stream: str
    quarantine_stream: str
    group: str
    consumer: str
    batch_size: int
    block_ms: int
    claim_idle_ms: int
    stream_maxlen: int
    publication_ttl_seconds: int
    migrations_dir: Path
    heartbeat_path: Path
    heartbeat_max_age_seconds: int
    pipeline_config: Path
    raw_event_retention_days: int
    normalized_event_retention_days: int
    cleanup_enabled: bool

    @classmethod
    def from_env(cls) -> "Settings":
        password = os.getenv("REDIS_PASSWORD") or None
        pipeline_config = Path(
            os.getenv("PIPELINE_CONFIG", "/opt/ahr-idps/pipeline/config.yml")
        )
        document: dict = {}
        if pipeline_config.is_file():
            loaded = yaml.safe_load(pipeline_config.read_text(encoding="utf-8"))
            if loaded is not None and not isinstance(loaded, dict):
                raise ValueError("PIPELINE_CONFIG must contain a YAML object")
            document = loaded or {}
        stream_config = document.get("streams", {})
        storage_config = document.get("storage", {})
        if not isinstance(stream_config, dict) or not isinstance(storage_config, dict):
            raise ValueError("PIPELINE_CONFIG streams/storage must be YAML objects")
        cleanup_value = storage_config.get("cleanup_enabled", False)
        if not isinstance(cleanup_value, bool):
            raise ValueError("storage.cleanup_enabled must be a boolean")
        if cleanup_value:
            raise ValueError(
                "automatic retention cleanup is intentionally unavailable in Phase 3"
            )
        raw_retention = int(storage_config.get("raw_event_retention_days", 30))
        normalized_retention = int(
            storage_config.get("normalized_event_retention_days", 90)
        )
        if raw_retention <= 0 or normalized_retention <= 0:
            raise ValueError("retention days must be positive integers")
        return cls(
            redis_host=os.getenv("REDIS_HOST", "redis"),
            redis_port=_positive_int("REDIS_PORT", 6379),
            redis_password=password,
            postgres_host=os.getenv("POSTGRES_HOST", "postgres"),
            postgres_port=_positive_int("POSTGRES_PORT", 5432),
            postgres_db=os.getenv("POSTGRES_DB", "ahr_idps"),
            postgres_user=os.getenv("POSTGRES_USER", "ahr_app"),
            postgres_password=os.getenv("POSTGRES_PASSWORD", ""),
            raw_stream=os.getenv(
                "RAW_STREAM", str(stream_config.get("raw", "security.events.raw"))
            ),
            normalized_stream=os.getenv(
                "NORMALIZED_STREAM",
                str(stream_config.get("normalized", "security.events.normalized")),
            ),
            quarantine_stream=os.getenv(
                "QUARANTINE_STREAM",
                str(stream_config.get("quarantine", "security.events.quarantine")),
            ),
            group=os.getenv("NORMALIZER_GROUP", "normalizer"),
            consumer=os.getenv(
                "NORMALIZER_CONSUMER", f"normalizer-{socket.gethostname()}-{os.getpid()}"
            ),
            batch_size=_positive_int("NORMALIZER_BATCH_SIZE", 100),
            block_ms=_positive_int("NORMALIZER_BLOCK_MS", 5000),
            claim_idle_ms=_positive_int("NORMALIZER_CLAIM_IDLE_MS", 60000),
            stream_maxlen=_positive_int("NORMALIZED_STREAM_MAXLEN", 500000),
            publication_ttl_seconds=_positive_int(
                "NORMALIZED_PUBLICATION_TTL_SECONDS", 7776000
            ),
            migrations_dir=Path(
                os.getenv(
                    "MIGRATIONS_DIR", "/opt/ahr-idps/normalizer/migrations"
                )
            ),
            heartbeat_path=Path(
                os.getenv(
                    "NORMALIZER_HEARTBEAT_PATH",
                    "/var/lib/ahr-idps/normalizer-heartbeat.json",
                )
            ),
            heartbeat_max_age_seconds=_positive_int(
                "NORMALIZER_HEARTBEAT_MAX_AGE_SECONDS", 30
            ),
            pipeline_config=pipeline_config,
            raw_event_retention_days=raw_retention,
            normalized_event_retention_days=normalized_retention,
            cleanup_enabled=cleanup_value,
        )
