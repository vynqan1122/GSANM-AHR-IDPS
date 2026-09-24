"""Database operations for scenario metadata, labels, and exports."""

from __future__ import annotations

import asyncpg


async def connect_from_env() -> asyncpg.Connection:
    import os

    return await asyncpg.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        database=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        command_timeout=60,
        server_settings={"application_name": "ahr-idps-dataset-framework"},
    )


async def create_scenario(
    connection: asyncpg.Connection,
    *,
    scenario_id: str,
    name: str,
    label: str,
    attack_type: str | None,
    mode: str,
    source: str,
    target: str,
    notes: str | None,
) -> None:
    await connection.execute(
        """
        INSERT INTO ahr.scenario_runs(
            scenario_id, name, label, attack_type, mode,
            start_time, source, target, notes
        )
        VALUES ($1,$2,$3,$4,$5,now(),$6,$7,$8)
        ON CONFLICT (scenario_id) DO NOTHING
        """,
        scenario_id,
        name,
        label,
        attack_type,
        mode,
        source,
        target,
        notes,
    )


async def finish_scenario(
    connection: asyncpg.Connection, *, scenario_id: str, request_count: int
) -> int:
    await connection.execute(
        """
        UPDATE ahr.scenario_runs
        SET end_time = now(), request_count = $2
        WHERE scenario_id = $1
        """,
        scenario_id,
        request_count,
    )
    return await label_scenario(connection, scenario_id=scenario_id)


async def label_scenario(connection: asyncpg.Connection, *, scenario_id: str) -> int:
    row = await connection.fetchrow(
        """
        SELECT scenario_id, label, attack_type, start_time,
               coalesce(end_time, now()) AS end_time, target
        FROM ahr.scenario_runs
        WHERE scenario_id = $1
        """,
        scenario_id,
    )
    if row is None:
        raise ValueError(f"unknown scenario_id: {scenario_id}")
    marker = row["scenario_id"]
    result = await connection.execute(
        """
        INSERT INTO ahr.event_labels(event_id, scenario_id, label, attack_type, match_reason)
        SELECT event_id, $1, $2, $3, 'scenario_id/time_window/target_marker'
        FROM ahr.events
        WHERE timestamp BETWEEN $4::timestamptz AND ($5::timestamptz + interval '30 seconds')
          AND raw_event::text LIKE '%' || $1 || '%'
        ON CONFLICT (event_id, scenario_id) DO NOTHING
        """,
        marker,
        row["label"],
        row["attack_type"],
        row["start_time"],
        row["end_time"],
    )
    return int(result.split()[-1])
