from __future__ import annotations

from pathlib import Path

import pytest

from collector.base import JsonlFileCollector
from collector.checkpoint import CheckpointStore, DeadLetterStore
from collector.collectors.nginx import parse_nginx
from collector.health import HealthRegistry


class RecordingPublisher:
    def __init__(self) -> None:
        self.events = []
        self.ids: set[str] = set()

    async def publish(self, event) -> bool:
        inserted = event.event_id not in self.ids
        self.ids.add(event.event_id)
        self.events.append(event)
        return inserted


def make_collector(
    tmp_path: Path,
    source_file: Path,
    publisher: RecordingPublisher,
    *,
    start_at_end: bool = False,
) -> JsonlFileCollector:
    return JsonlFileCollector(
        source="nginx",
        path=source_file,
        parser=parse_nginx,
        checkpoints=CheckpointStore(tmp_path / "checkpoints.sqlite3"),
        dead_letters=DeadLetterStore(tmp_path / "dead-letter.jsonl"),
        publisher=publisher,
        health=HealthRegistry(tmp_path / "health.json"),
        max_line_bytes=4096,
        poll_interval_seconds=0.01,
        start_at_end_for_new_files=start_at_end,
    )


@pytest.mark.asyncio
async def test_incremental_restart_and_partial_line(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    source_file.write_bytes(b'{"time_iso8601":"2026-01-01T00:00:00Z","request_id":"one"}\n')
    publisher = RecordingPublisher()
    first = make_collector(tmp_path, source_file, publisher)
    assert await first.poll_once() == 1
    assert len(publisher.events) == 1
    assert await first.poll_once() == 0

    with source_file.open("ab") as handle:
        handle.write(b'{"time_iso8601":"2026-01-01T00:00:01Z","request_id":"two"}')
    restarted = make_collector(tmp_path, source_file, publisher)
    assert await restarted.poll_once() == 0
    assert len(publisher.events) == 1
    with source_file.open("ab") as handle:
        handle.write(b"\n")
    assert await restarted.poll_once() == 1
    assert len(publisher.events) == 2


@pytest.mark.asyncio
async def test_malformed_record_is_quarantined_and_does_not_block(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    source_file.write_bytes(
        b"not-json\n"
        b'{"time_iso8601":"2026-01-01T00:00:01Z","request_id":"valid"}\n'
    )
    publisher = RecordingPublisher()
    collector = make_collector(tmp_path, source_file, publisher)
    assert await collector.poll_once() == 2
    assert len(publisher.events) == 1
    dead_letter = (tmp_path / "dead-letter.jsonl").read_text(encoding="utf-8")
    assert "not-json" in dead_letter
    assert "JSONDecodeError" in dead_letter


@pytest.mark.asyncio
async def test_truncation_resets_cursor_and_dedupe_id_is_stable(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    original = b'{"time_iso8601":"2026-01-01T00:00:00Z","request_id":"same"}\n'
    source_file.write_bytes(original + b" " * 200 + b"\n")
    publisher = RecordingPublisher()
    collector = make_collector(tmp_path, source_file, publisher)
    assert await collector.poll_once() == 2
    source_file.write_bytes(original)
    assert await collector.poll_once() == 1
    assert len(publisher.ids) == 1
    checkpoint = collector.checkpoints.get_file("nginx")
    assert checkpoint is not None and checkpoint.generation == 1


@pytest.mark.asyncio
async def test_rename_rotation_drains_unread_old_inode_before_new_file(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    source_file.write_bytes(b'{"request_id":"one"}\n')
    publisher = RecordingPublisher()
    collector = make_collector(tmp_path, source_file, publisher)
    assert await collector.poll_once() == 1

    with source_file.open("ab") as handle:
        handle.write(b'{"request_id":"unread-old"}\n')
    rotated_file = tmp_path / "access.jsonl.1"
    source_file.rename(rotated_file)
    source_file.write_bytes(b'{"request_id":"first-new"}\n')

    assert await collector.poll_once() == 2
    assert [event.source_event_id for event in publisher.events] == [
        "one",
        "unread-old",
        "first-new",
    ]
    checkpoint = collector.checkpoints.get_file("nginx")
    active_stat = source_file.stat()
    assert checkpoint is not None
    assert checkpoint.generation == 1
    assert (checkpoint.device, checkpoint.inode) == (active_stat.st_dev, active_stat.st_ino)
    assert checkpoint.offset == active_stat.st_size


@pytest.mark.asyncio
async def test_copytruncate_regrowth_past_cursor_is_detected_by_fingerprint(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    source_file.write_bytes(b'{"request_id":"old","padding":"xxxxxxxxxxxxxxxx"}\n')
    original_identity = (source_file.stat().st_dev, source_file.stat().st_ino)
    publisher = RecordingPublisher()
    collector = make_collector(tmp_path, source_file, publisher)
    assert await collector.poll_once() == 1
    old_checkpoint = collector.checkpoints.get_file("nginx")
    assert old_checkpoint is not None and old_checkpoint.tail_fingerprint

    replacement = (
        b'{"request_id":"replacement-one","padding":"yyyyyyyyyyyyyyyyyyyyyyyyyyyy"}\n'
        b'{"request_id":"replacement-two","padding":"zzzzzzzzzzzzzzzzzzzzzzzzzz"}\n'
    )
    with source_file.open("r+b") as handle:
        handle.truncate(0)
        handle.write(replacement)
        handle.flush()
    assert (source_file.stat().st_dev, source_file.stat().st_ino) == original_identity
    assert source_file.stat().st_size >= old_checkpoint.offset

    assert await collector.poll_once() == 2
    assert [event.source_event_id for event in publisher.events] == [
        "old",
        "replacement-one",
        "replacement-two",
    ]
    checkpoint = collector.checkpoints.get_file("nginx")
    assert checkpoint is not None
    assert checkpoint.generation == 1
    assert checkpoint.offset == len(replacement)


@pytest.mark.asyncio
async def test_unread_rotated_inode_is_recovered_after_restart(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    source_file.write_bytes(b'{"request_id":"before-restart"}\n')
    publisher = RecordingPublisher()
    first = make_collector(tmp_path, source_file, publisher)
    assert await first.poll_once() == 1
    first.checkpoints.close()

    with source_file.open("ab") as handle:
        handle.write(b'{"request_id":"persisted-unread"}\n')
    source_file.rename(tmp_path / "access.jsonl.1")
    source_file.write_bytes(b'{"request_id":"post-rotation"}\n')

    restarted = make_collector(tmp_path, source_file, publisher)
    assert await restarted.poll_once() == 2
    assert [event.source_event_id for event in publisher.events] == [
        "before-restart",
        "persisted-unread",
        "post-rotation",
    ]
    checkpoint = restarted.checkpoints.get_file("nginx")
    assert checkpoint is not None and checkpoint.generation == 1
    restarted.checkpoints.close()


@pytest.mark.asyncio
async def test_new_existing_file_can_start_at_end(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    source_file.write_bytes(b'{"request_id":"old"}\n')
    publisher = RecordingPublisher()
    collector = make_collector(tmp_path, source_file, publisher, start_at_end=True)
    assert await collector.poll_once() == 0
    with source_file.open("ab") as handle:
        handle.write(b'{"request_id":"new"}\n')
    assert await collector.poll_once() == 1
    assert publisher.events[0].source_event_id == "new"


@pytest.mark.asyncio
async def test_start_at_end_retains_record_in_progress(tmp_path) -> None:
    source_file = tmp_path / "access.jsonl"
    source_file.write_bytes(b'{"request_id":"old"}\n{"request_id":"in-progress"')
    publisher = RecordingPublisher()
    collector = make_collector(tmp_path, source_file, publisher, start_at_end=True)
    assert await collector.poll_once() == 0
    with source_file.open("ab") as handle:
        handle.write(b"}\n")
    assert await collector.poll_once() == 1
    assert publisher.events[0].source_event_id == "in-progress"
