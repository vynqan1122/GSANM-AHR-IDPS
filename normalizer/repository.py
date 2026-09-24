"""Transactional, idempotent PostgreSQL persistence for normalized events."""

from __future__ import annotations

import json
from typing import Any

import asyncpg

from .config import Settings
from .schemas import SecurityEvent


class EventIdentityConflict(ValueError):
    """An event identity was reused for different source evidence."""


def _json(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=True)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _decoded_json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class EventRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    @classmethod
    async def create(cls, settings: Settings) -> "EventRepository":
        pool = await asyncpg.create_pool(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            min_size=1,
            max_size=5,
            command_timeout=30,
            server_settings={"application_name": "ahr-idps-normalizer"},
        )
        return cls(pool)

    async def close(self) -> None:
        await self.pool.close()

    async def persist(self, event: SecurityEvent) -> bool:
        """Persist one event; return true only when it was newly inserted."""
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                inserted = await connection.fetchval(
                    """
                    INSERT INTO ahr.events (
                        event_id, source_event_id, timestamp, ingestion_timestamp,
                        source, event_type, category, src_ip, src_port, dst_ip,
                        dst_port, protocol, http, container, process, user_details,
                        file_details, network, rule, severity, labels, ai,
                        raw_event, metadata
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                        $13::jsonb, $14::jsonb, $15::jsonb, $16::jsonb,
                        $17::jsonb, $18::jsonb, $19::jsonb, $20, $21::jsonb,
                        $22::jsonb, $23::jsonb, $24::jsonb
                    )
                    ON CONFLICT DO NOTHING
                    RETURNING event_id
                    """,
                    event.event_id,
                    event.source_event_id,
                    event.timestamp,
                    event.ingestion_timestamp,
                    event.source,
                    event.event_type,
                    event.category,
                    event.src_ip,
                    event.src_port,
                    event.dst_ip,
                    event.dst_port,
                    event.protocol,
                    _json(event.http),
                    _json(event.container),
                    _json(event.process),
                    _json(event.user),
                    _json(event.file),
                    _json(event.network),
                    _json(event.rule),
                    event.severity,
                    _json(event.labels),
                    _json(event.ai),
                    _json(event.raw),
                    _json(event.metadata),
                )
                if inserted is None:
                    await self._assert_same_evidence(connection, event)
                    return False
                await self._insert_derived_rows(connection, event)
                return True

    async def _assert_same_evidence(
        self, connection: asyncpg.Connection, event: SecurityEvent
    ) -> None:
        row = await connection.fetchrow(
            """
            SELECT event_id, source, source_event_id, raw_event
            FROM ahr.events
            WHERE event_id = $1
               OR ($2::text IS NOT NULL AND source = $3 AND source_event_id = $2)
            LIMIT 1
            """,
            event.event_id,
            event.source_event_id,
            event.source,
        )
        if row is None:
            # An unrelated unique/index conflict should never be silently accepted.
            raise EventIdentityConflict(f"unresolved identity conflict for {event.event_id}")
        if (
            row["event_id"] != event.event_id
            or row["source"] != event.source
            or _decoded_json(row["raw_event"]) != event.raw
        ):
            raise EventIdentityConflict(
                f"event identity reused with different evidence: {event.event_id}"
            )

    async def _insert_derived_rows(
        self, connection: asyncpg.Connection, event: SecurityEvent
    ) -> None:
        if event.event_type == "alert" or event.rule is not None:
            rule = event.rule
            await connection.execute(
                """
                INSERT INTO ahr.alerts (
                    alert_id, event_id, timestamp, source, engine, rule_id,
                    title, category, severity
                ) VALUES ($1, $1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (alert_id) DO NOTHING
                """,
                event.event_id,
                event.timestamp,
                event.source,
                rule.engine if rule else None,
                rule.rule_id if rule else None,
                rule.name if rule else None,
                event.category,
                event.severity,
            )
        if event.network is not None or event.src_ip is not None or event.dst_ip is not None:
            network = event.network
            await connection.execute(
                """
                INSERT INTO ahr.network_flows (
                    flow_row_id, flow_id, timestamp, src_ip, src_port, dst_ip,
                    dst_port, protocol, packets_to_server, packets_to_client,
                    bytes_to_server, bytes_to_client, state
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (flow_row_id) DO NOTHING
                """,
                event.event_id,
                network.flow_id if network else None,
                event.timestamp,
                event.src_ip,
                event.src_port,
                event.dst_ip,
                event.dst_port,
                event.protocol,
                network.packets_to_server if network else None,
                network.packets_to_client if network else None,
                network.bytes_to_server if network else None,
                network.bytes_to_client if network else None,
                network.state if network else None,
            )
        await connection.execute(
            """
            INSERT INTO ahr.sensor_health (
                sensor, status, last_event_at, last_ingestion_at, details, updated_at
            ) VALUES ($1, 'reporting', $2, $3, $4::jsonb, now())
            ON CONFLICT (sensor) DO UPDATE SET
                status = 'reporting',
                last_event_at = GREATEST(
                    ahr.sensor_health.last_event_at, EXCLUDED.last_event_at
                ),
                last_ingestion_at = GREATEST(
                    ahr.sensor_health.last_ingestion_at, EXCLUDED.last_ingestion_at
                ),
                details = EXCLUDED.details,
                updated_at = now()
            """,
            event.source,
            event.timestamp,
            event.ingestion_timestamp,
            _json({"last_event_type": event.event_type}),
        )
