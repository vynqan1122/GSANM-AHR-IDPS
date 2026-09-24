from __future__ import annotations

import json
from typing import Any

from .attack_chain import build_attack_chain, build_timeline
from .rules import ai_summary, attack_type, risk_score, rule_summary, title_for
from .sessionizer import correlation_key, parse_time


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def row_to_event(row: Any) -> dict[str, Any]:
    data = dict(row)
    for key in (
        "http",
        "container",
        "process",
        "user_details",
        "file_details",
        "network",
        "rule",
        "labels",
        "ai",
        "raw_event",
        "metadata",
    ):
        data[key] = _json(data.get(key))
    return data


async def fetch_event(connection: Any, event_id: str) -> dict[str, Any] | None:
    row = await connection.fetchrow("SELECT * FROM ahr.events WHERE event_id = $1", event_id)
    return row_to_event(row) if row else None


async def fetch_incident_events(connection: Any, incident_id: str) -> list[dict[str, Any]]:
    rows = await connection.fetch(
        """
        SELECT e.*
        FROM ahr.events e
        JOIN ahr.incident_events ie ON ie.event_id = e.event_id
        WHERE ie.incident_id = $1
        ORDER BY e.timestamp ASC
        """,
        incident_id,
    )
    return [row_to_event(row) for row in rows]


async def upsert_incident(connection: Any, event: dict[str, Any]) -> dict[str, Any]:
    session = correlation_key(event)
    incident_id = session.incident_id
    timestamp = parse_time(event["timestamp"])
    initial_risk = risk_score(event)
    await connection.execute(
        """
        INSERT INTO ahr.incidents(
            incident_id, title, description, status, severity, risk_score,
            confidence, first_seen, last_seen, attack_chain_stage, entities
        )
        VALUES ($1,$2,$3,'open',$4,$5,$6,$7,$7,$8::text,$9::jsonb)
        ON CONFLICT (incident_id) DO UPDATE SET
            last_seen = greatest(ahr.incidents.last_seen, excluded.last_seen),
            first_seen = least(ahr.incidents.first_seen, excluded.first_seen),
            severity = greatest(coalesce(ahr.incidents.severity, 0), coalesce(excluded.severity, 0)),
            risk_score = greatest(coalesce(ahr.incidents.risk_score, 0.0), coalesce(excluded.risk_score, 0.0)),
            confidence = greatest(coalesce(ahr.incidents.confidence, 0.0), coalesce(excluded.confidence, 0.0)),
            entities = excluded.entities,
            updated_at = now()
        """,
        incident_id,
        title_for(event, 1),
        "Correlated from realtime security events",
        event.get("severity"),
        initial_risk,
        max(0.5, initial_risk),
        timestamp,
        attack_type(event),
        json.dumps({"correlation_key": session.value, "session": session.parts}),
    )
    await connection.execute(
        """
        INSERT INTO ahr.incident_events(incident_id, event_id, relationship, confidence)
        VALUES ($1,$2,'correlated',$3)
        ON CONFLICT (incident_id, event_id) DO UPDATE SET
            confidence = greatest(coalesce(ahr.incident_events.confidence, 0.0), excluded.confidence)
        """,
        incident_id,
        event["event_id"],
        max(0.5, initial_risk),
    )
    events = await fetch_incident_events(connection, incident_id)
    severities = [int(item.get("severity") or 0) for item in events]
    risks = [risk_score(item) for item in events]
    start = min(parse_time(item["timestamp"]) for item in events)
    end = max(parse_time(item["timestamp"]) for item in events)
    highest = max(severities) if severities else 0
    risk = max(risks) if risks else initial_risk
    source_ips = sorted({str(item.get("src_ip")) for item in events if item.get("src_ip")})
    targets = sorted({str(item.get("dst_ip") or (item.get("container") or {}).get("name")) for item in events if item.get("dst_ip") or item.get("container")})
    chain = build_attack_chain(events)
    timeline = build_timeline(events)
    representative = max(events, key=risk_score)
    await connection.execute(
        """
        UPDATE ahr.incidents
        SET title = $2,
            description = $3,
            severity = $4,
            risk_score = $5,
            confidence = $6,
            first_seen = $7,
            last_seen = $8,
            attack_chain_stage = $9::text,
            attack_type = $9::text,
            source_ips = $10::jsonb,
            targets = $11::jsonb,
            event_count = $12,
            highest_severity = $4,
            ai_summary = $13::jsonb,
            rule_summary = $14::jsonb,
            response_status = coalesce(response_status, 'none'),
            attack_graph = $15::jsonb,
            timeline = $16::jsonb,
            updated_at = now()
        WHERE incident_id = $1
        """,
        incident_id,
        title_for(representative, len(events)),
        f"{len(events)} correlated event(s) from {', '.join(source_ips) or 'unknown source'}",
        highest,
        risk,
        max(0.5, risk),
        start,
        end,
        attack_type(representative),
        json.dumps(source_ips),
        json.dumps(targets),
        len(events),
        json.dumps(ai_summary(events)),
        json.dumps(rule_summary(events)),
        json.dumps(chain),
        json.dumps(timeline),
    )
    return {
        "incident_id": incident_id,
        "event_id": event["event_id"],
        "risk_score": risk,
        "event_count": len(events),
        "attack_graph": chain,
        "timeline": timeline,
    }
