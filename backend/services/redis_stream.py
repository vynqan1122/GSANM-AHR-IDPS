"""Redis helpers for health and WebSocket streaming."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import redis.asyncio as redis

from backend.config import Settings


def redis_client(settings: Settings) -> redis.Redis:
    return redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        decode_responses=True,
        health_check_interval=15,
        socket_connect_timeout=5,
        socket_timeout=15,
    )


async def stream_normalized(
    client: redis.Redis, stream: str, *, alerts_only: bool = False
) -> AsyncIterator[dict[str, Any]]:
    last_id = "$"
    while True:
        records = await client.xread({stream: last_id}, count=100, block=5000)
        if not records:
            yield {"type": "heartbeat"}
            continue
        for _stream, messages in records:
            for stream_id, fields in messages:
                last_id = stream_id
                payload_text = fields.get("payload", "{}")
                try:
                    payload = json.loads(payload_text)
                except json.JSONDecodeError:
                    payload = {"raw": payload_text}
                if alerts_only and not (
                    payload.get("event_type") == "alert"
                    or payload.get("rule")
                    or int(payload.get("severity") or 0) >= 7
                ):
                    continue
                yield {
                    "type": "event",
                    "stream_id": stream_id,
                    "event": payload,
                }
