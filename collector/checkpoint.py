"""Transactional, process-local collector state.

Offsets are committed only after a Redis publish (or a durable dead-letter
write) succeeds.  SQLite gives restart safety without depending on Redis for
the file cursor itself.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class FileCheckpoint:
    source: str
    path: str
    device: int
    inode: int
    generation: int
    offset: int
    # Hash of the bytes immediately preceding ``offset``.  File size alone
    # cannot identify copytruncate when the replacement grows past the old
    # cursor before the next poll.
    tail_fingerprint: str | None = None
    tail_bytes: int = 0


class CheckpointStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS file_checkpoints (
                source TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                device INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                offset INTEGER NOT NULL CHECK (offset >= 0),
                updated_at TEXT NOT NULL
            )
            """
        )
        # Keep existing Phase 3 state volumes usable.  SQLite cannot add both
        # fields in one portable ALTER statement, so migrate each missing
        # column independently after CREATE TABLE IF NOT EXISTS.
        checkpoint_columns = {
            str(row[1])
            for row in self._connection.execute("PRAGMA table_info(file_checkpoints)").fetchall()
        }
        if "tail_fingerprint" not in checkpoint_columns:
            self._connection.execute("ALTER TABLE file_checkpoints ADD COLUMN tail_fingerprint TEXT")
        if "tail_bytes" not in checkpoint_columns:
            self._connection.execute(
                "ALTER TABLE file_checkpoints ADD COLUMN tail_bytes INTEGER NOT NULL DEFAULT 0"
            )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cursors (
                source TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._connection.commit()

    def get_file(self, source: str) -> FileCheckpoint | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT source, path, device, inode, generation, offset,
                       tail_fingerprint, tail_bytes
                FROM file_checkpoints WHERE source = ?
                """,
                (source,),
            ).fetchone()
        return FileCheckpoint(*row) if row else None

    def save_file(self, checkpoint: FileCheckpoint) -> None:
        updated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO file_checkpoints(
                    source, path, device, inode, generation, offset,
                    tail_fingerprint, tail_bytes, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    path = excluded.path,
                    device = excluded.device,
                    inode = excluded.inode,
                    generation = excluded.generation,
                    offset = excluded.offset,
                    tail_fingerprint = excluded.tail_fingerprint,
                    tail_bytes = excluded.tail_bytes,
                    updated_at = excluded.updated_at
                """,
                (
                    checkpoint.source,
                    checkpoint.path,
                    checkpoint.device,
                    checkpoint.inode,
                    checkpoint.generation,
                    checkpoint.offset,
                    checkpoint.tail_fingerprint,
                    checkpoint.tail_bytes,
                    updated_at,
                ),
            )

    def get_cursor(self, source: str) -> str | None:
        with self._lock:
            row = self._connection.execute("SELECT value FROM cursors WHERE source = ?", (source,)).fetchone()
        return str(row[0]) if row else None

    def save_cursor(self, source: str, value: str) -> None:
        updated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO cursors(source, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (source, value, updated_at),
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            file_rows = self._connection.execute(
                """
                SELECT source, path, device, inode, generation, offset,
                       tail_fingerprint, tail_bytes, updated_at
                FROM file_checkpoints
                """
            ).fetchall()
            cursor_rows = self._connection.execute("SELECT source, value, updated_at FROM cursors").fetchall()
        return {
            "files": [
                {
                    "source": row[0],
                    "path": row[1],
                    "device": row[2],
                    "inode": row[3],
                    "generation": row[4],
                    "offset": row[5],
                    "tail_fingerprint": row[6],
                    "tail_bytes": row[7],
                    "updated_at": row[8],
                }
                for row in file_rows
            ],
            "cursors": [
                {"source": row[0], "value": row[1], "updated_at": row[2]} for row in cursor_rows
            ],
        }

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class DeadLetterStore:
    """Append malformed records to a durable local JSONL quarantine."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def append(
        self,
        *,
        source: str,
        source_path: str,
        offset: int,
        reason: str,
        raw: bytes,
    ) -> None:
        record = {
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "source": source,
            "path": source_path,
            "offset": offset,
            "reason": reason,
            "raw_utf8": raw[:65_536].decode("utf-8", errors="replace"),
            "raw_bytes": len(raw),
            "truncated": len(raw) > 65_536,
        }
        encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            with self.path.open("ab", buffering=0) as handle:
                handle.write(encoded)
                handle.flush()
                # buffering=0 makes flush a no-op, but fsync ensures the bad
                # record is durable before its source cursor is advanced.
                import os

                os.fsync(handle.fileno())
