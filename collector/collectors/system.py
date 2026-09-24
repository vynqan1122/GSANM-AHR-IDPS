"""Optional real host/container resource measurements from procfs."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..base import RedisPublisher, make_raw_event
from ..health import HealthRegistry


def read_system_snapshot(proc_root: Path = Path("/proc")) -> dict[str, Any]:
    load_fields = (proc_root / "loadavg").read_text(encoding="ascii").split()
    mem: dict[str, int] = {}
    for line in (proc_root / "meminfo").read_text(encoding="ascii").splitlines():
        name, _, value = line.partition(":")
        if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            mem[name] = int(value.strip().split()[0]) * 1024
    return {
        "load_1m": float(load_fields[0]),
        "load_5m": float(load_fields[1]),
        "load_15m": float(load_fields[2]),
        "running_processes": int(load_fields[3].split("/")[0]),
        "total_processes": int(load_fields[3].split("/")[1]),
        "memory_bytes": mem,
        "cpu_count": os.cpu_count(),
    }


class SystemCollector:
    def __init__(self, publisher: RedisPublisher, health: HealthRegistry, interval_seconds: float) -> None:
        self.publisher = publisher
        self.health = health
        self.interval_seconds = interval_seconds

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            observed_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
            try:
                payload = read_system_snapshot()
                event = make_raw_event(
                    source="system",
                    source_event_id=observed_at,
                    observed_at=observed_at,
                    payload=payload,
                    metadata={"collector": "procfs"},
                )
                inserted = await self.publisher.publish(event)
                self.health.increment("system", "published" if inserted else "deduplicated", status="healthy")
            except asyncio.CancelledError:
                raise
            except (OSError, ValueError) as exc:
                self.health.update("system", "unavailable", error=type(exc).__name__)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                pass

