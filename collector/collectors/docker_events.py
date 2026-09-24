"""Optional read-only Docker Engine event stream collector.

The implementation talks directly to the local Unix socket with HTTP GET.  It
does not expose command/container-management methods and never invokes a shell.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from urllib.parse import urlencode

from ..base import RedisPublisher, make_raw_event
from ..checkpoint import CheckpointStore
from ..health import HealthRegistry
from ._common import stable_source_id

LOGGER = logging.getLogger(__name__)


class DockerEventsCollector:
    def __init__(
        self,
        *,
        socket_path: Path,
        api_version: str,
        checkpoints: CheckpointStore,
        publisher: RedisPublisher,
        health: HealthRegistry,
    ) -> None:
        self.socket_path = socket_path
        self.api_version = api_version
        self.checkpoints = checkpoints
        self.publisher = publisher
        self.health = health

    async def run(self, stop: asyncio.Event) -> None:
        delay = 0.5
        while not stop.is_set():
            try:
                await self._stream(stop)
                delay = 0.5
            except asyncio.CancelledError:
                raise
            except (OSError, ValueError, json.JSONDecodeError, asyncio.IncompleteReadError) as exc:
                self.health.update("docker", "unavailable", error=type(exc).__name__)
                LOGGER.warning("Docker event stream unavailable: %s", exc)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                except TimeoutError:
                    pass
                delay = min(delay * 2, 15.0)

    async def _stream(self, stop: asyncio.Event) -> None:
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        try:
            cursor = self.checkpoints.get_cursor("docker")
            query = urlencode({"since": str(int(cursor) // 1_000_000_000)}) if cursor else ""
            target = f"/{self.api_version}/events" + (f"?{query}" if query else "")
            request = (
                f"GET {target} HTTP/1.1\r\n"
                "Host: docker\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
            status_line = header.split(b"\r\n", 1)[0]
            if b" 200 " not in status_line:
                raise OSError(f"Docker Engine returned {status_line.decode('ascii', errors='replace')}")
            chunked = b"transfer-encoding: chunked" in header.lower()
            self.health.update("docker", "healthy", socket=str(self.socket_path))
            buffer = b""
            if chunked:
                while not stop.is_set():
                    size_line = await self._readline_or_stop(reader, stop)
                    if size_line is None:
                        return
                    size = int(size_line.strip().split(b";", 1)[0], 16)
                    if size == 0:
                        return
                    chunk = await reader.readexactly(size)
                    await reader.readexactly(2)
                    buffer += chunk
                    buffer = await self._consume_lines(buffer)
            else:
                while not stop.is_set():
                    line = await self._readline_or_stop(reader, stop)
                    if line is None:
                        return
                    buffer += line
                    buffer = await self._consume_lines(buffer)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _readline_or_stop(self, reader: asyncio.StreamReader, stop: asyncio.Event) -> bytes | None:
        read_task = asyncio.create_task(reader.readline())
        stop_task = asyncio.create_task(stop.wait())
        done, pending = await asyncio.wait({read_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if stop_task in done or not read_task.result():
            return None
        return read_task.result()

    async def _consume_lines(self, buffer: bytes) -> bytes:
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if not line.strip():
                continue
            document = json.loads(line)
            if not isinstance(document, dict):
                raise ValueError("Docker event record is not an object")
            time_nano = document.get("timeNano") or int(document.get("time", 0)) * 1_000_000_000
            source_id = stable_source_id(
                document,
                (
                    document.get("Type") or document.get("type"),
                    document.get("Action") or document.get("action"),
                    document.get("id"),
                    time_nano,
                    document.get("scope"),
                ),
            )
            event = make_raw_event(
                source="docker",
                source_event_id=source_id,
                observed_at=time_nano,
                payload=document,
                metadata={"collector": "docker-engine-events", "socket": str(self.socket_path)},
            )
            inserted = await self.publisher.publish(event)
            self.checkpoints.save_cursor("docker", str(time_nano))
            self.health.increment("docker", "published" if inserted else "deduplicated", status="healthy")
        return buffer

