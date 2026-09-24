"""Collector primitives: canonical events, atomic Redis publishing and tailing."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Protocol

from .checkpoint import CheckpointStore, DeadLetterStore, FileCheckpoint
from .health import HealthRegistry

LOGGER = logging.getLogger(__name__)
RAW_STREAM_SCHEMA_VERSION = "1"
CHECKPOINT_FINGERPRINT_BYTES = 4096


def rfc3339_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalize_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        # Nanosecond Unix timestamps are common in Falco and Docker.
        numeric = float(value)
        if numeric > 1e17:
            numeric /= 1e9
        elif numeric > 1e14:
            numeric /= 1e6
        elif numeric > 1e11:
            numeric /= 1e3
        try:
            return datetime.fromtimestamp(numeric, UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return rfc3339_now()
    if isinstance(value, str) and value.strip():
        candidate = value.strip()
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
        except ValueError:
            return rfc3339_now()
    return rfc3339_now()


@dataclass(frozen=True, slots=True)
class RawEvent:
    event_id: str
    source: str
    source_event_id: str
    observed_at: str
    ingested_at: str
    payload: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = RAW_STREAM_SCHEMA_VERSION

    def stream_fields(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "observed_at": self.observed_at,
            "ingested_at": self.ingested_at,
            "payload": canonical_json(self.payload),
            "metadata": canonical_json(self.metadata),
        }


def make_raw_event(
    *,
    source: str,
    source_event_id: str,
    observed_at: Any,
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any] | None = None,
) -> RawEvent:
    stable_id = source_event_id.strip() or hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    digest = hashlib.sha256(f"{source}\x00{stable_id}".encode("utf-8")).hexdigest()
    return RawEvent(
        event_id=digest,
        source=source,
        source_event_id=stable_id,
        observed_at=normalize_timestamp(observed_at),
        ingested_at=rfc3339_now(),
        payload=payload,
        metadata=metadata or {},
    )


class EventParser(Protocol):
    def __call__(self, document: Mapping[str, Any], metadata: Mapping[str, Any]) -> RawEvent: ...


_PUBLISH_SCRIPT = """
local inserted = redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX')
if not inserted then
  return ''
end
local stream_id = redis.pcall('XADD', KEYS[2], 'MAXLEN', '~', ARGV[2], '*',
  'schema_version', ARGV[3],
  'event_id', ARGV[4],
  'source', ARGV[5],
  'source_event_id', ARGV[6],
  'observed_at', ARGV[7],
  'ingested_at', ARGV[8],
  'payload', ARGV[9],
  'metadata', ARGV[10])
if type(stream_id) == 'table' and stream_id.err then
  redis.call('DEL', KEYS[1])
  return redis.error_reply(stream_id.err)
end
return stream_id
"""


class RedisPublisher:
    """Publish with an atomic dedupe marker and bounded exponential retry."""

    def __init__(
        self,
        redis_client: Any,
        *,
        stream: str,
        maxlen: int,
        dedupe_ttl_seconds: int,
        retry_initial_seconds: float,
        retry_max_seconds: float,
        health: HealthRegistry,
    ) -> None:
        self.redis = redis_client
        self.stream = stream
        self.maxlen = maxlen
        self.dedupe_ttl_seconds = dedupe_ttl_seconds
        self.retry_initial_seconds = retry_initial_seconds
        self.retry_max_seconds = retry_max_seconds
        self.health = health

    async def publish(self, event: RawEvent) -> bool:
        fields = event.stream_fields()
        delay = self.retry_initial_seconds
        while True:
            try:
                result = await self.redis.eval(
                    _PUBLISH_SCRIPT,
                    2,
                    f"ahr:collector:dedupe:{event.event_id}",
                    self.stream,
                    self.dedupe_ttl_seconds,
                    self.maxlen,
                    fields["schema_version"],
                    fields["event_id"],
                    fields["source"],
                    fields["source_event_id"],
                    fields["observed_at"],
                    fields["ingested_at"],
                    fields["payload"],
                    fields["metadata"],
                )
                self.health.update("redis", "healthy")
                return bool(result)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # redis-py exception classes vary by version
                self.health.update("redis", "retrying", error=type(exc).__name__)
                LOGGER.warning("Redis publish failed; retrying in %.2fs: %s", delay, exc)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self.retry_max_seconds)


class JsonlFileCollector:
    """Poll and tail one append-only JSONL file without losing partial lines."""

    def __init__(
        self,
        *,
        source: str,
        path: Path,
        parser: EventParser,
        checkpoints: CheckpointStore,
        dead_letters: DeadLetterStore,
        publisher: RedisPublisher,
        health: HealthRegistry,
        max_line_bytes: int,
        poll_interval_seconds: float,
        start_at_end_for_new_files: bool = True,
    ) -> None:
        self.source = source
        self.path = path
        self.parser = parser
        self.checkpoints = checkpoints
        self.dead_letters = dead_letters
        self.publisher = publisher
        self.health = health
        self.max_line_bytes = max_line_bytes
        self.poll_interval_seconds = poll_interval_seconds
        self.start_at_end_for_new_files = start_at_end_for_new_files

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                processed = await self.poll_once()
                if processed == 0:
                    await asyncio.wait_for(stop.wait(), timeout=self.poll_interval_seconds)
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                raise
            except (FileNotFoundError, PermissionError, OSError) as exc:
                self.health.update(self.source, "unavailable", path=str(self.path), error=type(exc).__name__)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.poll_interval_seconds)
                except TimeoutError:
                    pass
            except Exception as exc:
                LOGGER.exception("collector source %s failed", self.source)
                self.health.update(self.source, "error", path=str(self.path), error=type(exc).__name__)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.poll_interval_seconds)
                except TimeoutError:
                    pass

    async def poll_once(self) -> int:
        stat = self.path.stat()
        saved = self.checkpoints.get_file(self.source)
        logical_path = str(self.path)

        if saved is None:
            # start-at-end applies only to the first identity ever observed for
            # this source.  A replacement file after rotation always starts at
            # byte zero.
            identity = self._checkpoint_for_path(
                self.path,
                stat,
                generation=0,
                offset=self._initial_offset(stat.st_size),
            )
            self.checkpoints.save_file(identity)
            processed, _identity, _complete = await self._consume_path(self.path, identity)
            return processed

        active_identity_changed = saved.device != int(stat.st_dev) or saved.inode != int(stat.st_ino)
        if active_identity_changed:
            processed = 0
            old_path = self._find_path_by_identity(saved.device, saved.inode)
            if old_path is not None:
                # logrotate commonly renames the active file before creating
                # its replacement.  Continue the durable cursor against that
                # renamed inode first; otherwise records appended between the
                # previous poll and rename would be silently lost.
                old_processed, saved, complete = await self._consume_path(old_path, saved)
                processed += old_processed
                if not complete:
                    self.health.update(
                        self.source,
                        "draining_rotated_file",
                        path=str(old_path),
                        offset=saved.offset,
                    )
                    return processed

                # Catch bytes appended through a writer that still had the
                # renamed inode open while it was being drained.
                try:
                    old_stat = old_path.stat()
                except FileNotFoundError:
                    old_stat = None
                if (
                    old_stat is not None
                    and int(old_stat.st_dev) == saved.device
                    and int(old_stat.st_ino) == saved.inode
                    and old_stat.st_size > saved.offset
                ):
                    more_processed, saved, complete = await self._consume_path(old_path, saved)
                    processed += more_processed
                    if not complete:
                        return processed

            # Re-read the configured path in case another rotation happened
            # while the prior inode was drained.
            stat = self.path.stat()
            identity = self._checkpoint_for_path(
                self.path,
                stat,
                generation=saved.generation + 1,
                offset=0,
            )
            self.checkpoints.save_file(identity)
            self.health.increment(
                self.source,
                "rotations",
                path=logical_path,
                previous_inode=saved.inode,
                inode=identity.inode,
            )
            new_processed, _identity, _complete = await self._consume_path(self.path, identity)
            return processed + new_processed

        rewritten = stat.st_size < saved.offset or not self._fingerprint_matches(self.path, saved)
        if rewritten:
            # Same-inode truncation can be invisible to a size-only check when
            # the writer regrows the file beyond the old offset before this
            # poll.  Resetting is safe because source event IDs are stable and
            # Redis publication is atomic/idempotent.
            identity = self._checkpoint_for_path(
                self.path,
                stat,
                generation=saved.generation + 1,
                offset=0,
            )
            self.checkpoints.save_file(identity)
            self.health.increment(
                self.source,
                "rotations",
                path=logical_path,
                reason="copytruncate_or_rewrite",
            )
        else:
            identity = replace(saved, path=logical_path)
            # Backfill the fingerprint for databases created before this
            # field existed, without resetting an otherwise valid cursor.
            if identity.tail_fingerprint is None:
                identity = self._with_fingerprint(self.path, identity, identity.offset)
                self.checkpoints.save_file(identity)

        processed, _identity, _complete = await self._consume_path(self.path, identity)
        return processed

    async def _consume_path(
        self,
        read_path: Path,
        identity: FileCheckpoint,
    ) -> tuple[int, FileCheckpoint, bool]:
        """Consume one inode, returning count, committed state and EOF safety.

        ``complete`` is false only for a trailing incomplete record.  Rotation
        handling keeps that old inode selected until the writer finishes it.
        """

        processed = 0
        complete = True
        with read_path.open("rb") as handle:
            opened_stat = os.fstat(handle.fileno())
            if int(opened_stat.st_dev) != identity.device or int(opened_stat.st_ino) != identity.inode:
                # The pathname changed between stat/open.  Leave the durable
                # cursor untouched and let the next poll resolve identities.
                return 0, identity, False
            handle.seek(identity.offset)
            while True:
                line_start = handle.tell()
                raw = handle.readline(self.max_line_bytes + 1)
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    # A max-sized buffer means the record is oversized. Drain
                    # the complete physical line before quarantining it.
                    if len(raw) > self.max_line_bytes:
                        while raw and not raw.endswith(b"\n"):
                            raw = handle.readline(self.max_line_bytes + 1)
                        next_offset = handle.tell()
                        self.dead_letters.append(
                            source=self.source,
                            source_path=str(read_path),
                            offset=line_start,
                            reason=f"line exceeds {self.max_line_bytes} bytes",
                            raw=b"<oversized record>",
                        )
                        identity = self._commit(identity, next_offset, handle)
                        self.health.increment(self.source, "malformed", path=str(read_path))
                        processed += 1
                    else:
                        # Writer has not completed the line; leave checkpoint at
                        # line_start so the next poll re-reads it intact.
                        handle.seek(line_start)
                        complete = False
                    break
                next_offset = handle.tell()
                stripped = raw.rstrip(b"\r\n")
                if not stripped:
                    identity = self._commit(identity, next_offset, handle)
                    continue
                try:
                    document = json.loads(stripped)
                    if not isinstance(document, dict):
                        raise ValueError("JSON record must be an object")
                    event = self.parser(
                        document,
                        {
                            "collector": "jsonl",
                            "source_path": str(read_path),
                            "file_generation": identity.generation,
                            "file_offset": line_start,
                        },
                    )
                    inserted = await self.publisher.publish(event)
                    self.health.increment(
                        self.source,
                        "published" if inserted else "deduplicated",
                        path=str(read_path),
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
                    self.dead_letters.append(
                        source=self.source,
                        source_path=str(read_path),
                        offset=line_start,
                        reason=f"{type(exc).__name__}: {exc}",
                        raw=stripped,
                    )
                    self.health.increment(self.source, "malformed", path=str(read_path))
                identity = self._commit(identity, next_offset, handle)
                processed += 1
        self.health.update(self.source, "healthy", path=str(read_path), offset=identity.offset)
        return processed, identity, complete

    def _find_path_by_identity(self, device: int, inode: int) -> Path | None:
        """Find a renamed sibling that still references the saved inode."""

        try:
            candidates = sorted(self.path.parent.iterdir(), key=lambda candidate: candidate.name)
        except (FileNotFoundError, PermissionError, OSError):
            return None
        for candidate in candidates:
            try:
                stat = candidate.stat()
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if int(stat.st_dev) == device and int(stat.st_ino) == inode:
                return candidate
        return None

    def _checkpoint_for_path(
        self,
        read_path: Path,
        stat: os.stat_result,
        *,
        generation: int,
        offset: int,
    ) -> FileCheckpoint:
        checkpoint = FileCheckpoint(
            source=self.source,
            path=str(self.path),
            device=int(stat.st_dev),
            inode=int(stat.st_ino),
            generation=generation,
            offset=offset,
        )
        return self._with_fingerprint(read_path, checkpoint, offset)

    def _fingerprint_matches(self, read_path: Path, checkpoint: FileCheckpoint) -> bool:
        if checkpoint.tail_fingerprint is None:
            # Backward-compatible migration: there is no historical anchor to
            # compare on the very first run after upgrading.
            return True
        expected_bytes = checkpoint.tail_bytes
        if expected_bytes < 0 or expected_bytes > checkpoint.offset:
            return False
        try:
            with read_path.open("rb") as handle:
                handle.seek(checkpoint.offset - expected_bytes)
                data = handle.read(expected_bytes)
        except (FileNotFoundError, PermissionError, OSError):
            return False
        if len(data) != expected_bytes:
            return False
        return hashlib.sha256(data).hexdigest() == checkpoint.tail_fingerprint

    def _with_fingerprint(
        self,
        read_path: Path,
        checkpoint: FileCheckpoint,
        offset: int,
    ) -> FileCheckpoint:
        with read_path.open("rb") as handle:
            return self._with_handle_fingerprint(handle, checkpoint, offset)

    @staticmethod
    def _with_handle_fingerprint(
        handle: BinaryIO,
        checkpoint: FileCheckpoint,
        offset: int,
    ) -> FileCheckpoint:
        current = handle.tell()
        tail_bytes = min(CHECKPOINT_FINGERPRINT_BYTES, offset)
        handle.seek(offset - tail_bytes)
        tail = handle.read(tail_bytes)
        handle.seek(current)
        return replace(
            checkpoint,
            offset=offset,
            tail_fingerprint=hashlib.sha256(tail).hexdigest(),
            tail_bytes=len(tail),
        )

    def _initial_offset(self, size: int) -> int:
        if not self.start_at_end_for_new_files or size == 0:
            return 0
        # If a writer was halfway through a record when the collector first
        # discovered the file, retain that incomplete record instead of
        # starting in its middle when the trailing bytes arrive.
        with self.path.open("rb") as handle:
            handle.seek(size - 1)
            if handle.read(1) in {b"\n", b"\r"}:
                return size
            position = size - 1
            while position > 0:
                read_size = min(4096, position)
                position -= read_size
                handle.seek(position)
                chunk = handle.read(read_size)
                newline = chunk.rfind(b"\n")
                if newline >= 0:
                    return position + newline + 1
            return 0

    def _commit(self, identity: FileCheckpoint, offset: int, handle: BinaryIO) -> FileCheckpoint:
        committed = self._with_handle_fingerprint(handle, identity, offset)
        self.checkpoints.save_file(committed)
        return committed
