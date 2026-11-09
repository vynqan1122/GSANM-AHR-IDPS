from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis.asyncio as redis
from redis.exceptions import ResponseError

from ai.network.config import Settings
from ai.network.db import connect

from .incident_builder import fetch_event, upsert_incident
from .sessionizer import correlation_key
from .rules import actionable_event, risk_score


def heartbeat(path: Path, status: str = "running", **fields: Any) -> None:
    path.write_text(
        json.dumps({"status": status, "updated_at": datetime.now(UTC).isoformat(), **fields}, separators=(",", ":")),
        encoding="utf-8",
    )


async def prepare_group(redis_client: redis.Redis, stream: str, group: str, *, start_at_end: bool) -> None:
    try:
        await redis_client.xgroup_create(name=stream, groupname=group, id="$" if start_at_end else "0-0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    if start_at_end:
        await redis_client.execute_command("XGROUP", "SETID", stream, group, "$")
        while True:
            pending = await redis_client.xpending_range(stream, group, "-", "+", 250)
            ids = [row["message_id"] for row in pending]
            if not ids:
                break
            await redis_client.xack(stream, group, *ids)


async def service() -> None:
    settings = Settings.from_env()
    group = os.getenv("INCIDENT_GROUP", "incident-engine")
    consumer = os.getenv("INCIDENT_CONSUMER", "incident-engine-1")
    heartbeat_path = Path(os.getenv("INCIDENT_HEARTBEAT", "/tmp/incident-heartbeat.json"))
    incident_stream = os.getenv("INCIDENT_STREAM", "security.incidents")
    start_at_end = os.getenv("INCIDENT_START_AT_END", "true").lower() in {"1", "true", "yes"}
    input_stream = os.getenv('INCIDENT_INPUT_STREAM', settings.predictions_stream)
    redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        decode_responses=True,
        socket_timeout=15,
    )
    connection = await connect(settings)
    processed = 0
    heartbeat(heartbeat_path, "starting", processed=processed)
    try:
        await prepare_group(redis_client, input_stream, group, start_at_end=start_at_end)
        heartbeat(heartbeat_path, "running", processed=processed)
        while True:
            records = await redis_client.xreadgroup(group,consumer,{input_stream:'0'},count=50)
            if not any(messages for _,messages in records):
                records = await redis_client.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={input_stream: ">"},
                count=50,
                block=5000,
            )
            if not records:
                heartbeat(heartbeat_path, "running", processed=processed)
                continue
            for _stream, messages in records:
                grouped={}
                for stream_id, fields in messages:
                    try:
                        event_id = fields.get("event_id") or json.loads(fields.get('payload', '{}')).get('event_id')
                        if not event_id:
                            await redis_client.xack(input_stream, group, stream_id)
                            continue
                        event = await fetch_event(connection, event_id)
                        if event is None:
                            await redis_client.xack(input_stream, group, stream_id)
                            continue
                        if not actionable_event(event):
                            await redis_client.xack(input_stream, group, stream_id)
                            continue
                        key=correlation_key(event).incident_id
                        grouped.setdefault(key,[]).append((stream_id,event))
                    except Exception as exc:
                        heartbeat(heartbeat_path, "degraded", processed=processed, error_type=exc.__class__.__name__)
                        await asyncio.sleep(1)
                        break
                for group_items in grouped.values():
                    try:
                        events=[e for _,e in group_items]
                        representative=max(events,key=risk_score)
                        # Refresh one materialized summary per incident in this batch; keep every evidence link.
                        async with connection.transaction():
                            incident = await upsert_incident(connection, representative, related_events=events)
                        await redis_client.xadd(
                            incident_stream,
                            {
                                "incident_id": incident["incident_id"],
                                "event_id": representative['event_id'],
                                "risk_score": f"{incident['risk_score']:.8f}",
                                "event_count": str(incident["event_count"]),
                            },
                            maxlen=100000,
                            approximate=True,
                        )
                        processed += len(group_items)
                        await redis_client.xack(input_stream, group, *(sid for sid,_ in group_items))
                        heartbeat(heartbeat_path, "running", processed=processed, last_stream_id=group_items[-1][0])
                    except Exception as exc:
                        heartbeat(heartbeat_path, "degraded", processed=processed, error_type=exc.__class__.__name__)
                        # Retain failed evidence for retry; an error is not a processed incident.
                        await asyncio.sleep(1)
                        break
    finally:
        await connection.close()
        await redis_client.aclose()


def main() -> None:
    asyncio.run(service())


if __name__ == "__main__":
    main()

