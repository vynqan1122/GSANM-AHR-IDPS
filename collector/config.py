"""Environment-backed configuration for the collector process.

Configuration deliberately has no implicit network-facing defaults.  The only
network dependency is Redis and source files are read from explicit paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def _config_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return _bool(str(value), default)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError("COLLECTOR_CONFIG must contain a YAML object")
    return loaded


def _positive_int(value: str | None, default: int, name: str) -> int:
    parsed = default if value is None else int(value)
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return parsed


def _positive_float(value: str | None, default: float, name: str) -> float:
    parsed = default if value is None else float(value)
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return parsed


@dataclass(frozen=True, slots=True)
class FileSourceConfig:
    name: str
    path: Path
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    redis_url: str = "redis://redis:6379/0"
    redis_password: str | None = None
    raw_stream: str = "security.events.raw"
    stream_maxlen: int = 250_000
    dedupe_ttl_seconds: int = 2_592_000
    checkpoint_path: Path = Path("/var/lib/ahr-idps/collector/checkpoints.sqlite3")
    dead_letter_path: Path = Path("/var/lib/ahr-idps/collector/dead-letter.jsonl")
    health_path: Path = Path("/var/lib/ahr-idps/collector/health.json")
    poll_interval_seconds: float = 0.5
    heartbeat_interval_seconds: float = 5.0
    max_line_bytes: int = 8 * 1024 * 1024
    start_at_end_for_new_files: bool = True
    redis_retry_initial_seconds: float = 0.25
    redis_retry_max_seconds: float = 15.0
    file_sources: tuple[FileSourceConfig, ...] = field(default_factory=tuple)
    docker_events_enabled: bool = False
    docker_socket: Path = Path("/var/run/docker.sock")
    docker_api_version: str = "v1.41"
    system_metrics_enabled: bool = False
    system_interval_seconds: float = 30.0
    pipeline_config: Path = Path("/opt/ahr-idps/pipeline/config.yml")
    raw_event_retention_days: int = 30
    normalized_event_retention_days: int = 90
    cleanup_enabled: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "CollectorConfig":
        values = os.environ if env is None else env
        pipeline_config = Path(
            values.get(
                "COLLECTOR_CONFIG",
                values.get("PIPELINE_CONFIG", "/opt/ahr-idps/pipeline/config.yml"),
            )
        )
        document = _load_yaml(pipeline_config)
        collector_document = document.get("collector", {})
        stream_document = document.get("streams", {})
        storage_document = document.get("storage", {})
        if not all(
            isinstance(section, dict)
            for section in (collector_document, stream_document, storage_document)
        ):
            raise ValueError("COLLECTOR_CONFIG collector/streams/storage must be YAML objects")
        source_document = collector_document.get("sources", {})
        if not isinstance(source_document, dict):
            raise ValueError("COLLECTOR_CONFIG collector.sources must be a YAML object")
        cleanup_enabled = _config_bool(storage_document.get("cleanup_enabled"), False)
        if cleanup_enabled:
            raise ValueError(
                "automatic retention cleanup is intentionally unavailable in Phase 3"
            )
        raw_retention = int(storage_document.get("raw_event_retention_days", 30))
        normalized_retention = int(
            storage_document.get("normalized_event_retention_days", 90)
        )
        if raw_retention <= 0 or normalized_retention <= 0:
            raise ValueError("retention days must be positive integers")
        checkpoint_dir = Path(values.get("CHECKPOINT_DIR", "/var/lib/ahr-idps/collector"))
        sources = (
            FileSourceConfig(
                "suricata",
                Path(
                    values.get(
                        "COLLECTOR_SURICATA_PATH",
                        str(source_document.get("suricata", "/var/log/suricata/eve.json")),
                    )
                ),
                _bool(values.get("COLLECTOR_SURICATA_ENABLED"), True),
            ),
            FileSourceConfig(
                "falco",
                Path(
                    values.get(
                        "COLLECTOR_FALCO_PATH",
                        str(source_document.get("falco", "/var/log/falco/events.jsonl")),
                    )
                ),
                _bool(values.get("COLLECTOR_FALCO_ENABLED"), True),
            ),
            FileSourceConfig(
                "wazuh",
                Path(
                    values.get(
                        "COLLECTOR_WAZUH_PATH",
                        str(source_document.get("wazuh", "/var/log/wazuh/alerts/alerts.json")),
                    )
                ),
                _bool(values.get("COLLECTOR_WAZUH_ENABLED"), True),
            ),
            FileSourceConfig(
                "nginx",
                Path(
                    values.get(
                        "COLLECTOR_NGINX_PATH",
                        str(source_document.get("nginx", "/var/log/ahr-nginx/access.jsonl")),
                    )
                ),
                _bool(values.get("COLLECTOR_NGINX_ENABLED"), True),
            ),
        )
        raw_stream = values.get(
            "RAW_STREAM",
            values.get(
                "COLLECTOR_RAW_STREAM",
                str(stream_document.get("raw", "security.events.raw")),
            ),
        ).strip()
        if raw_stream != "security.events.raw":
            raise ValueError("COLLECTOR_RAW_STREAM must be security.events.raw")
        docker_api_version = values.get("COLLECTOR_DOCKER_API_VERSION", "v1.41").strip()
        if not docker_api_version.startswith("v1."):
            raise ValueError("COLLECTOR_DOCKER_API_VERSION must be a Docker v1 API version")
        redis_url = values.get("REDIS_URL")
        if not redis_url:
            redis_host = values.get("REDIS_HOST", "redis")
            redis_port = int(values.get("REDIS_PORT", "6379"))
            redis_url = f"redis://{redis_host}:{redis_port}/0"
        return cls(
            redis_url=redis_url,
            redis_password=values.get("REDIS_PASSWORD") or None,
            raw_stream=raw_stream,
            stream_maxlen=_positive_int(values.get("COLLECTOR_STREAM_MAXLEN"), 250_000, "COLLECTOR_STREAM_MAXLEN"),
            dedupe_ttl_seconds=_positive_int(
                values.get("COLLECTOR_DEDUPE_TTL_SECONDS"), 2_592_000, "COLLECTOR_DEDUPE_TTL_SECONDS"
            ),
            checkpoint_path=Path(
                values.get("COLLECTOR_CHECKPOINT_PATH", str(checkpoint_dir / "checkpoints.sqlite3"))
            ),
            dead_letter_path=Path(
                values.get("COLLECTOR_DEAD_LETTER_PATH", str(checkpoint_dir / "dead-letter.jsonl"))
            ),
            health_path=Path(
                values.get(
                    "COLLECTOR_HEARTBEAT_PATH",
                    values.get("COLLECTOR_HEALTH_PATH", str(checkpoint_dir / "health.json")),
                )
            ),
            poll_interval_seconds=_positive_float(
                values.get("COLLECTOR_POLL_INTERVAL_SECONDS"),
                float(collector_document.get("poll_interval_seconds", 0.5)),
                "COLLECTOR_POLL_INTERVAL_SECONDS",
            ),
            heartbeat_interval_seconds=_positive_float(
                values.get("COLLECTOR_HEARTBEAT_INTERVAL_SECONDS"), 5.0, "COLLECTOR_HEARTBEAT_INTERVAL_SECONDS"
            ),
            max_line_bytes=_positive_int(
                values.get("COLLECTOR_MAX_LINE_BYTES"), 8 * 1024 * 1024, "COLLECTOR_MAX_LINE_BYTES"
            ),
            start_at_end_for_new_files=_bool(
                values.get("COLLECTOR_START_AT_END"),
                _config_bool(collector_document.get("start_at_end_for_new_files"), True),
            ),
            redis_retry_initial_seconds=_positive_float(
                values.get("COLLECTOR_REDIS_RETRY_INITIAL_SECONDS"),
                0.25,
                "COLLECTOR_REDIS_RETRY_INITIAL_SECONDS",
            ),
            redis_retry_max_seconds=_positive_float(
                values.get("COLLECTOR_REDIS_RETRY_MAX_SECONDS"), 15.0, "COLLECTOR_REDIS_RETRY_MAX_SECONDS"
            ),
            file_sources=sources,
            docker_events_enabled=_bool(values.get("COLLECTOR_DOCKER_EVENTS_ENABLED"), False),
            docker_socket=Path(values.get("COLLECTOR_DOCKER_SOCKET", "/var/run/docker.sock")),
            docker_api_version=docker_api_version,
            system_metrics_enabled=_bool(values.get("COLLECTOR_SYSTEM_METRICS_ENABLED"), False),
            system_interval_seconds=_positive_float(
                values.get("COLLECTOR_SYSTEM_INTERVAL_SECONDS"), 30.0, "COLLECTOR_SYSTEM_INTERVAL_SECONDS"
            ),
            pipeline_config=pipeline_config,
            raw_event_retention_days=raw_retention,
            normalized_event_retention_days=normalized_retention,
            cleanup_enabled=cleanup_enabled,
        )
