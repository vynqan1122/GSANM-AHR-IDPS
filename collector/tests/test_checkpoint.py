from __future__ import annotations

import sqlite3

from collector.checkpoint import CheckpointStore, FileCheckpoint


def test_checkpoint_persists_across_reopen(tmp_path) -> None:
    path = tmp_path / "state" / "checkpoints.sqlite3"
    first = CheckpointStore(path)
    first.save_file(FileCheckpoint("suricata", "/eve.json", 1, 2, 3, 400))
    first.save_cursor("docker", "123456789")
    first.close()

    second = CheckpointStore(path)
    assert second.get_file("suricata") == FileCheckpoint("suricata", "/eve.json", 1, 2, 3, 400)
    assert second.get_cursor("docker") == "123456789"
    second.close()


def test_legacy_checkpoint_schema_is_migrated_in_place(tmp_path) -> None:
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE file_checkpoints (
            source TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            device INTEGER NOT NULL,
            inode INTEGER NOT NULL,
            generation INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "INSERT INTO file_checkpoints VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("nginx", "/access.jsonl", 10, 20, 2, 300, "2026-01-01T00:00:00Z"),
    )
    connection.commit()
    connection.close()

    store = CheckpointStore(path)
    assert store.get_file("nginx") == FileCheckpoint("nginx", "/access.jsonl", 10, 20, 2, 300)
    upgraded = FileCheckpoint("nginx", "/access.jsonl", 10, 20, 2, 320, "abc123", 64)
    store.save_file(upgraded)
    assert store.get_file("nginx") == upgraded
    store.close()
