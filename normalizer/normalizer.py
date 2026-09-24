"""Redis Streams -> canonical schema -> PostgreSQL/Redis normalization worker."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncpg
import redis.asyncio as redis
from pydantic import ValidationError
from redis.exceptions import ResponseError

from ahr_common.logging import configure_logging

from .config import Settings
from .migration import run_migrations
from .mappings import normalize
from .repository import EventIdentityConflict, EventRepository
from .schemas import RawEnvelope, SecurityEvent


LOGGER = logging.getLogger("ahr_idps.normalizer")

PUBLISH_LUA = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return redis.call('GET', KEYS[1])
end
local output_id = redis.call(
  'XADD', KEYS[2], 'MAXLEN', '~', ARGV[1], '*',
  'schema_version', ARGV[2],
  'event_id', ARGV[3],
  'source', ARGV[4],
  'event_type', ARGV[5],
  'timestamp', ARGV[6],
  'payload', ARGV[7]
)
redis.call('SET', KEYS[1], output_id, 'EX', ARGV[8])
return output_id
"""

QUARANTINE_LUA = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return redis.call('GET', KEYS[1])
end
local output_id = redis.call(
  'XADD', KEYS[2], 'MAXLEN', '~', ARGV[1], '*',
  'raw_stream_id', ARGV[2],
  'error_code', ARGV[3],
  'error', ARGV[4],
  'quarantined_at', ARGV[5],
  'fields', ARGV[6]
)
redis.call('SET', KEYS[1], output_id, 'EX', ARGV[7])
return output_id
"""


def _identity_key(prefix: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()
    return f"ahr:normalizer:{prefix}:{digest}"


class Heartbeat:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.started_at = datetime.now(timezone.utc)
        self.counters: dict[str, int] = {
            "processed": 0,
            "inserted": 0,
            "duplicates": 0,
            "quarantined": 0,
            "transient_errors": 0,
        }

    def increment(self, name: str) -> None:
        self.counters[name] = self.counters.get(name, 0) + 1

    def write(self, status: str = "running", error_type: str | None = None) -> None:
        now = datetime.now(timezone.utc)
        data: dict[str, Any] = {
            "service": "normalizer",
            "status": status,
            "pid": os.getpid(),
            "started_at": self.started_at.isoformat(),
            "updated_at": now.isoformat(),
            "counters": self.counters,
        }
        if error_type:
            # Only the class is exposed; exception text may contain a credential/DSN.
            data["error_type"] = error_type
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, self.path)


def stream_groups(settings: Settings) -> dict[str, tuple[str, ...]]:
    """Materialize required stream/group metadata without inserting fake records."""
    return {
        settings.raw_stream: (settings.group,),
        settings.normalized_stream: (
            "feature-engine",
            "ai-network",
            "ai-log",
            "graph-builder",
            "dashboard-publisher",
        ),
        "security.predictions": (
            "fusion-engine",
            "incident-engine",
            "dashboard-publisher",
        ),
        "security.incidents": ("dashboard-publisher",),
        "security.rules": ("dashboard-publisher",),
        "security.responses": ("dashboard-publisher",),
    }


class NormalizerService:
    def __init__(
        self,
        settings: Settings,
        redis_client: redis.Redis,
        repository: EventRepository,
        heartbeat: Heartbeat,
    ) -> None:
        self.settings = settings
        self.redis = redis_client
        self.repository = repository
        self.heartbeat = heartbeat
        self.stop_event = asyncio.Event()
        self.publish_script = self.redis.register_script(PUBLISH_LUA)
        self.quarantine_script = self.redis.register_script(QUARANTINE_LUA)

    async def ensure_streams(self) -> None:
        for stream, groups in stream_groups(self.settings).items():
            for group in groups:
                try:
                    await self.redis.xgroup_create(
                        name=stream,
                        groupname=group,
                        id="0-0",
                        mkstream=True,
                    )
                except ResponseError as exc:
                    if "BUSYGROUP" not in str(exc):
                        raise

    async def publish_normalized(self, event: SecurityEvent) -> str:
        marker = _identity_key("published", event.event_id)
        result = await self.publish_script(
            keys=[marker, self.settings.normalized_stream],
            args=[
                self.settings.stream_maxlen,
                event.schema_version,
                event.event_id,
                event.source,
                event.event_type,
                event.timestamp.isoformat(),
                event.model_dump_json(exclude_none=False),
                self.settings.publication_ttl_seconds,
            ],
        )
        return result.decode() if isinstance(result, bytes) else str(result)

    async def quarantine(
        self,
        stream_id: str,
        fields: dict[str, Any],
        error_code: str,
        error: BaseException,
    ) -> None:
        safe_fields = {
            str(key): (
                value.decode("utf-8", errors="replace")
                if isinstance(value, bytes)
                else str(value)
            )
            for key, value in fields.items()
        }
        await self.quarantine_script(
            keys=[
                _identity_key("quarantined", stream_id),
                self.settings.quarantine_stream,
            ],
            args=[
                self.settings.stream_maxlen,
                stream_id,
                error_code,
                f"{type(error).__name__}: {str(error)[:800]}",
                datetime.now(timezone.utc).isoformat(),
                json.dumps(safe_fields, separators=(",", ":"), sort_keys=True),
                self.settings.publication_ttl_seconds,
            ],
        )

    async def process_message(self, stream_id: str, fields: dict[str, Any]) -> None:
        try:
            envelope = RawEnvelope.from_stream_fields(fields)
            event = normalize(envelope)
        except (
            ValidationError,
            UnicodeDecodeError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
        ) as exc:
            await self.quarantine(stream_id, fields, "invalid_event", exc)
            await self.redis.xack(self.settings.raw_stream, self.settings.group, stream_id)
            self.heartbeat.increment("quarantined")
            return

        try:
            inserted = await self.repository.persist(event)
            await self.publish_normalized(event)
            await self.redis.xack(self.settings.raw_stream, self.settings.group, stream_id)
            await self.redis.delete(_identity_key("retry", stream_id))
            self.heartbeat.increment("processed")
            self.heartbeat.increment("inserted" if inserted else "duplicates")
        except EventIdentityConflict as exc:
            await self.quarantine(stream_id, fields, "identity_conflict", exc)
            await self.redis.xack(self.settings.raw_stream, self.settings.group, stream_id)
            self.heartbeat.increment("quarantined")
        except (asyncpg.PostgresError, OSError, ConnectionError, ResponseError) as exc:
            await self._record_transient_failure(stream_id, fields, exc)

    async def _record_transient_failure(
        self, stream_id: str, fields: dict[str, Any], error: BaseException
    ) -> None:
        retry_key = _identity_key("retry", stream_id)
        attempts = await self.redis.incr(retry_key)
        if attempts == 1:
            await self.redis.expire(retry_key, self.settings.publication_ttl_seconds)
        self.heartbeat.increment("transient_errors")
        # A dependency outage is not evidence that the event itself is bad.
        # Keep the message pending for XAUTOCLAIM and retry indefinitely; only
        # permanent validation/identity failures may be quarantined and ACKed.
        # This deliberately prefers backpressure over silent event loss.
        LOGGER.warning(
            "transient processing error stream_id=%s attempt=%s error_type=%s",
            stream_id,
            attempts,
            type(error).__name__,
        )

    async def process_batch(self, messages: list[tuple[str, dict[str, Any]]]) -> None:
        for stream_id, fields in messages:
            if self.stop_event.is_set():
                break
            await self.process_message(stream_id, fields)
            self.heartbeat.write()

    async def reclaim_stale(self) -> int:
        result = await self.redis.xautoclaim(
            name=self.settings.raw_stream,
            groupname=self.settings.group,
            consumername=self.settings.consumer,
            min_idle_time=self.settings.claim_idle_ms,
            start_id="0-0",
            count=self.settings.batch_size,
        )
        messages = result[1] if len(result) >= 2 else []
        if messages:
            await self.process_batch(messages)
        return len(messages)

    async def run(self) -> None:
        await self.ensure_streams()
        self.heartbeat.write()
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                await self.reclaim_stale()
                records = await self.redis.xreadgroup(
                    groupname=self.settings.group,
                    consumername=self.settings.consumer,
                    streams={self.settings.raw_stream: ">"},
                    count=self.settings.batch_size,
                    block=self.settings.block_ms,
                )
                for _stream, messages in records:
                    await self.process_batch(messages)
                self.heartbeat.write()
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # process stays alive while a dependency recovers
                LOGGER.exception("normalizer loop degraded error_type=%s", type(exc).__name__)
                self.heartbeat.write("degraded", type(exc).__name__)
                try:
                    await asyncio.wait_for(self.stop_event.wait(), timeout=backoff)
                except TimeoutError:
                    pass
                backoff = min(backoff * 2, 30.0)
        self.heartbeat.write("stopping")


async def bootstrap(settings: Settings, migrate_only: bool = False) -> None:
    heartbeat = Heartbeat(settings.heartbeat_path)
    backoff = 1.0
    while True:
        try:
            await run_migrations(settings)
            break
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("migration dependency unavailable error_type=%s", type(exc).__name__)
            heartbeat.write("starting", type(exc).__name__)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
    if migrate_only:
        heartbeat.write("migrations_complete")
        return

    redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        decode_responses=True,
        health_check_interval=15,
        socket_connect_timeout=5,
        socket_timeout=max(10, settings.block_ms / 1000 + 5),
    )
    repository: EventRepository | None = None
    try:
        backoff = 1.0
        while repository is None:
            try:
                await redis_client.ping()
                repository = await EventRepository.create(settings)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                heartbeat.write("starting", type(exc).__name__)
                LOGGER.warning(
                    "service dependency unavailable error_type=%s", type(exc).__name__
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
        service = NormalizerService(settings, redis_client, repository, heartbeat)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, service.stop_event.set)
            except NotImplementedError:  # pragma: no cover - Windows dev shells
                pass
        await service.run()
    finally:
        if repository is not None:
            await repository.close()
        await redis_client.aclose()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AHR-IDPS event normalizer")
    parser.add_argument(
        "--migrate-only", action="store_true", help="apply SQL migrations and exit"
    )
    return parser.parse_args()


def main() -> None:
    configure_logging("normalizer", os.getenv("LOG_LEVEL", "INFO"))
    args = parse_args()
    asyncio.run(bootstrap(Settings.from_env(), migrate_only=args.migrate_only))


if __name__ == "__main__":
    main()
