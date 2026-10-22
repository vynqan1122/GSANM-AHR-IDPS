"""Read-only SQL queries for API and dashboard views."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _row(row: Any) -> dict[str, Any]:
    return {key: _jsonable(value) for key, value in row._mapping.items()}


def _page(page: int, page_size: int) -> tuple[int, int, int]:
    safe_page = max(1, page)
    safe_size = min(max(1, page_size), 200)
    return safe_page, safe_size, (safe_page - 1) * safe_size


def _event_filters(filters: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    for field in ("source", "event_type", "src_ip"):
        value = filters.get(field)
        if value:
            clauses.append(f"{field} = :{field}")
            params[field] = value
    severity = filters.get("severity")
    if severity is not None:
        clauses.append("severity >= :severity")
        params["severity"] = severity
    container = filters.get("container")
    if container:
        clauses.append("container ->> 'name' ILIKE :container")
        params["container"] = f"%{container}%"
    time_from = filters.get("time_from")
    if time_from:
        clauses.append("timestamp >= :time_from")
        params["time_from"] = time_from
    time_to = filters.get("time_to")
    if time_to:
        clauses.append("timestamp <= :time_to")
        params["time_to"] = time_to
    return clauses, params


async def list_events(
    session: AsyncSession,
    *,
    page: int,
    page_size: int,
    filters: dict[str, Any],
) -> dict[str, Any]:
    safe_page, safe_size, offset = _page(page, page_size)
    clauses, params = _event_filters(filters)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.update({"limit": safe_size, "offset": offset})
    total = await session.scalar(text(f"SELECT count(*) FROM ahr.events {where}"), params)
    result = await session.execute(
        text(
            f"""
            SELECT event_id, source_event_id, timestamp, ingestion_timestamp,
                   source, event_type, category, src_ip, src_port, dst_ip,
                   dst_port, protocol, http, container, rule, severity,
                   labels, ai, raw_event, metadata
            FROM ahr.events
            {where}
            ORDER BY timestamp DESC, created_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    )
    return {
        "page": safe_page,
        "page_size": safe_size,
        "total": int(total or 0),
        "items": [_row(row) for row in result],
    }


async def get_event(session: AsyncSession, event_id: str) -> dict[str, Any] | None:
    result = await session.execute(
        text("SELECT * FROM ahr.events WHERE event_id = :event_id"),
        {"event_id": event_id},
    )
    row = result.first()
    return _row(row) if row else None


async def list_incidents(
    session: AsyncSession,
    *,
    page: int,
    page_size: int,
    status: str | None = None,
) -> dict[str, Any]:
    safe_page, safe_size, offset = _page(page, page_size)
    clauses = []
    params: dict[str, Any] = {"limit": safe_size, "offset": offset}
    if status:
        clauses.append("status = :status")
        params["status"] = status
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total = await session.scalar(text(f"SELECT count(*) FROM ahr.incidents {where}"), params)
    result = await session.execute(
        text(
            f"""
            SELECT incident_id, title, description, status, severity, risk_score,
                   confidence, first_seen, last_seen, attack_type, source_ips,
                   targets, event_count, highest_severity, ai_summary,
                   rule_summary, response_status, attack_graph, timeline,
                   created_at, updated_at
            FROM ahr.incidents
            {where}
            ORDER BY last_seen DESC, updated_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    )
    return {
        "page": safe_page,
        "page_size": safe_size,
        "total": int(total or 0),
        "items": [_row(row) for row in result],
    }


async def get_incident(session: AsyncSession, incident_id: str) -> dict[str, Any] | None:
    result = await session.execute(
        text(
            """
            SELECT incident_id, title, description, status, severity, risk_score,
                   confidence, first_seen, last_seen, attack_type, source_ips,
                   targets, event_count, highest_severity, ai_summary,
                   rule_summary, response_status, attack_graph, timeline,
                   created_at, updated_at
            FROM ahr.incidents
            WHERE incident_id = :incident_id
            """
        ),
        {"incident_id": incident_id},
    )
    row = result.first()
    if row is None:
        return None
    incident = _row(row)
    events = await session.execute(
        text(
            """
            SELECT e.event_id, e.timestamp, e.source, e.event_type, e.src_ip,
                   e.dst_ip, e.http, e.container, e.rule, e.severity, e.ai,
                   e.raw_event, e.metadata, ie.relationship,
                   ie.confidence AS correlation_confidence
            FROM ahr.incident_events ie
            JOIN ahr.events e ON e.event_id = ie.event_id
            WHERE ie.incident_id = :incident_id
            ORDER BY e.timestamp ASC
            """
        ),
        {"incident_id": incident_id},
    )
    incident["events"] = [_row(item) for item in events]
    from correlation.web_graph import build_web_graph
    incident['attack_graph'] = build_web_graph(incident['events'])
    responses = await session.execute(
        text(
            """
            SELECT response_id, action, action_type, response_level, status,
                   target, reason, risk, started_at, expires_at, rollback_status
            FROM ahr.responses
            WHERE incident_id = :incident_id
            ORDER BY started_at DESC
            """
        ),
        {"incident_id": incident_id},
    )
    incident["responses"] = [_row(item) for item in responses]
    return incident


async def first_web_attacks(session: AsyncSession) -> dict[str, Any]:
    from correlation.web_graph import build_web_graph, detected_web_attack, request_identity
    # Stream chronologically, stopping at twenty accepted records; do not load all historical logs.
    result = await session.stream(text('''
        SELECT event_id, timestamp, source, src_ip, dst_ip, http, container,
               rule, ai, severity, raw_event, metadata
        FROM ahr.events
        WHERE (http->>'uri' IS NOT NULL OR http->>'url' IS NOT NULL)
          AND (coalesce(nullif(rule->>'rule_id',''), rule->>'name', '') <> ''
               OR CASE WHEN jsonb_typeof(ai->'fusion_score') = 'number'
                       THEN (ai->>'fusion_score')::double precision >= 0.55 ELSE false END)
        ORDER BY timestamp ASC, event_id ASC
    ''').execution_options(yield_per=100))
    rows, seen = [], set()
    try:
        async for item in result:
            row = _row(item)
            key = request_identity(row)
            if detected_web_attack(row) and key not in seen:
                rows.append(row); seen.add(key)
                if len(rows) == 20:
                    break
    finally:
        await result.close()
    return build_web_graph(rows)


async def list_responses(
    session: AsyncSession,
    *,
    page: int,
    page_size: int,
    status: str | None = None,
    incident_id: str | None = None,
) -> dict[str, Any]:
    safe_page, safe_size, offset = _page(page, page_size)
    clauses = []
    params: dict[str, Any] = {"limit": safe_size, "offset": offset}
    if status:
        clauses.append("r.status = :status")
        params["status"] = status
    if incident_id:
        clauses.append("r.incident_id = :incident_id")
        params["incident_id"] = incident_id
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total = await session.scalar(text(f"SELECT count(*) FROM ahr.responses r {where}"), params)
    result = await session.execute(
        text(
            f"""
            SELECT r.response_id, r.incident_id, r.event_id,
                   coalesce(r.action, r.action_type) AS action,
                   r.action_type, r.response_level, r.status, r.target,
                   r.reason, r.requested_by, r.risk, r.started_at, r.expires_at,
                   r.completed_at, r.rollback_status, r.parameters, r.rollback_data,
                   e.evidence_id, e.path AS evidence_path, e.bundle_sha256,
                   e.file_count AS evidence_file_count
            FROM ahr.responses r
            LEFT JOIN LATERAL (
                SELECT evidence_id, path, bundle_sha256, file_count
                FROM ahr.evidence
                WHERE response_id = r.response_id
                ORDER BY created_at DESC
                LIMIT 1
            ) e ON true
            {where}
            ORDER BY r.started_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    )
    return {
        "page": safe_page,
        "page_size": safe_size,
        "total": int(total or 0),
        "items": [_row(row) for row in result],
    }


async def get_response(session: AsyncSession, response_id: str) -> dict[str, Any] | None:
    result = await session.execute(
        text(
            """
            SELECT r.response_id, r.incident_id, r.event_id,
                   coalesce(r.action, r.action_type) AS action,
                   r.action_type, r.response_level, r.status, r.target,
                   r.reason, r.requested_by, r.risk, r.started_at, r.expires_at,
                   r.completed_at, r.rollback_status, r.parameters, r.rollback_data,
                   r.action_audit, e.evidence_id, e.path AS evidence_path,
                   e.manifest AS evidence_manifest, e.bundle_sha256,
                   e.file_count AS evidence_file_count
            FROM ahr.responses r
            LEFT JOIN LATERAL (
                SELECT evidence_id, path, manifest, bundle_sha256, file_count
                FROM ahr.evidence
                WHERE response_id = r.response_id
                ORDER BY created_at DESC
                LIMIT 1
            ) e ON true
            WHERE r.response_id = :response_id
            """
        ),
        {"response_id": response_id},
    )
    row = result.first()
    return _row(row) if row else None


async def list_rules(
    session: AsyncSession,
    *,
    page: int,
    page_size: int,
    status: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    safe_page, safe_size, offset = _page(page, page_size)
    clauses = []
    params: dict[str, Any] = {"limit": safe_size, "offset": offset}
    if status:
        clauses.append("r.status = :status")
        params["status"] = status
    if source:
        clauses.append("r.source = :source")
        params["source"] = source
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total = await session.scalar(text(f"SELECT count(*) FROM ahr.rules r {where}"), params)
    result = await session.execute(
        text(
            f"""
            SELECT r.rule_id, r.engine, r.name, r.description, r.status,
                   r.source, r.origin, r.generator, r.pattern, r.support,
                   r.confidence, r.model_versions, r.parent_rule_id,
                   r.shadow_metrics, r.promotion_requires_approval,
                   r.current_version, r.created_at, r.updated_at,
                   rv.content, rv.metadata AS version_metadata,
                   vr.status AS validation_status,
                   vr.syntax_valid AS validation_syntax_valid,
                   vr.replay_metrics AS validation_replay_metrics
            FROM ahr.rules r
            LEFT JOIN ahr.rule_versions rv
              ON rv.rule_id = r.rule_id AND rv.version = r.current_version
            LEFT JOIN LATERAL (
                SELECT status, syntax_valid, replay_metrics
                FROM ahr.rule_validation_runs
                WHERE rule_id = r.rule_id
                ORDER BY started_at DESC
                LIMIT 1
            ) vr ON true
            {where}
            ORDER BY r.updated_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    )
    return {
        "page": safe_page,
        "page_size": safe_size,
        "total": int(total or 0),
        "items": [_row(row) for row in result],
    }


async def get_rule(session: AsyncSession, rule_id: str) -> dict[str, Any] | None:
    result = await session.execute(
        text(
            """
            SELECT r.rule_id, r.engine, r.name, r.description, r.status,
                   r.source, r.origin, r.generator, r.pattern, r.support,
                   r.confidence, r.model_versions, r.parent_rule_id,
                   r.shadow_metrics, r.promotion_requires_approval,
                   r.current_version, r.created_at, r.updated_at,
                   rv.content, rv.metadata AS version_metadata,
                   vr.status AS validation_status,
                   vr.syntax_valid AS validation_syntax_valid,
                   vr.replay_metrics AS validation_replay_metrics
            FROM ahr.rules r
            LEFT JOIN ahr.rule_versions rv
              ON rv.rule_id = r.rule_id AND rv.version = r.current_version
            LEFT JOIN LATERAL (
                SELECT status, syntax_valid, replay_metrics
                FROM ahr.rule_validation_runs
                WHERE rule_id = r.rule_id
                ORDER BY started_at DESC
                LIMIT 1
            ) vr ON true
            WHERE r.rule_id = :rule_id
            """
        ),
        {"rule_id": rule_id},
    )
    row = result.first()
    return _row(row) if row else None


async def list_alerts(
    session: AsyncSession, *, page: int, page_size: int
) -> dict[str, Any]:
    safe_page, safe_size, offset = _page(page, page_size)
    total = await session.scalar(text("SELECT count(*) FROM ahr.alerts"))
    result = await session.execute(
        text(
            """
            SELECT a.alert_id, a.event_id, a.timestamp, a.source, a.engine,
                   a.rule_id, a.title, a.category, a.severity, a.status,
                   e.src_ip, e.dst_ip, e.container, e.raw_event
            FROM ahr.alerts a
            JOIN ahr.events e ON e.event_id = a.event_id
            ORDER BY a.timestamp DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {"limit": safe_size, "offset": offset},
    )
    return {
        "page": safe_page,
        "page_size": safe_size,
        "total": int(total or 0),
        "items": [_row(row) for row in result],
    }


async def get_alert(session: AsyncSession, alert_id: str) -> dict[str, Any] | None:
    result = await session.execute(
        text(
            """
            SELECT a.alert_id, a.event_id, a.timestamp, a.source, a.engine,
                   a.rule_id, a.title, a.category, a.severity, a.status,
                   e.src_ip, e.dst_ip, e.container, e.rule, e.ai, e.raw_event
            FROM ahr.alerts a
            JOIN ahr.events e ON e.event_id = a.event_id
            WHERE a.alert_id = :alert_id
            """
        ),
        {"alert_id": alert_id},
    )
    row = result.first()
    return _row(row) if row else None


async def sensor_rows(session: AsyncSession) -> list[dict[str, Any]]:
    result = await session.execute(
        text(
            """
            SELECT sensor, status, last_event_at, last_ingestion_at,
                   error_count, details, updated_at
            FROM ahr.sensor_health
            ORDER BY sensor
            """
        )
    )
    return [_row(row) for row in result]


async def containers(session: AsyncSession) -> list[dict[str, Any]]:
    result = await session.execute(
        text(
            """
            SELECT container ->> 'name' AS name,
                   container ->> 'image' AS image,
                   count(*) AS event_count,
                   max(timestamp) AS last_seen
            FROM ahr.events
            WHERE container IS NOT NULL AND container ->> 'name' IS NOT NULL
            GROUP BY 1, 2
            ORDER BY event_count DESC, last_seen DESC
            LIMIT 100
            """
        )
    )
    return [_row(row) for row in result]


async def get_container(session: AsyncSession, container_id: str) -> dict[str, Any] | None:
    result = await session.execute(
        text(
            """
            SELECT container ->> 'name' AS name,
                   container ->> 'image' AS image,
                   count(*) AS event_count,
                   max(timestamp) AS last_seen,
                   count(*) FILTER (WHERE source = 'falco') AS falco_alert_count,
                   max(coalesce((ai->>'fusion_score')::double precision, 0.0)) AS current_risk
            FROM ahr.events
            WHERE container IS NOT NULL
              AND (container ->> 'name' = :container_id OR container ->> 'id' = :container_id)
            GROUP BY 1, 2
            """
        ),
        {"container_id": container_id},
    )
    row = result.first()
    return _row(row) if row else None


async def network_summary(session: AsyncSession) -> dict[str, Any]:
    summary = (
        await session.execute(
            text(
                """
                SELECT
                  count(*) FILTER (WHERE timestamp >= now() - interval '1 minute') / 60.0 AS flows_per_sec,
                  coalesce(sum(coalesce((network->>'bytes')::bigint, 0)) FILTER (WHERE timestamp >= now() - interval '1 minute'), 0) / 60.0 AS bytes_per_sec,
                  count(*) FILTER (WHERE source = 'suricata' AND severity >= 5) AS suricata_alerts
                FROM ahr.events
                """
            )
        )
    ).first()
    protocols = await session.execute(
        text(
            """
            SELECT coalesce(protocol, 'unknown') AS protocol, count(*) AS count
            FROM ahr.events
            GROUP BY coalesce(protocol, 'unknown')
            ORDER BY count DESC
            LIMIT 10
            """
        )
    )
    top_sources = await session.execute(
        text(
            """
            SELECT src_ip, count(*) AS count
            FROM ahr.events
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
            """
        )
    )
    top_destinations = await session.execute(
        text(
            """
            SELECT dst_ip, count(*) AS count
            FROM ahr.events
            WHERE dst_ip IS NOT NULL
            GROUP BY dst_ip
            ORDER BY count DESC
            LIMIT 10
            """
        )
    )
    top_ports = await session.execute(
        text(
            """
            SELECT dst_port, count(*) AS count
            FROM ahr.events
            WHERE dst_port IS NOT NULL
            GROUP BY dst_port
            ORDER BY count DESC
            LIMIT 10
            """
        )
    )
    return {
        "summary": _row(summary) if summary else {},
        "protocols": [_row(row) for row in protocols],
        "top_sources": [_row(row) for row in top_sources],
        "top_destinations": [_row(row) for row in top_destinations],
        "top_destination_ports": [_row(row) for row in top_ports],
    }


async def list_models(session: AsyncSession) -> list[dict[str, Any]]:
    result = await session.execute(
        text(
            """
            SELECT model_id, name, model_type, version, status, artifact_uri,
                   artifact_sha256, feature_schema, training_metadata,
                   created_at, activated_at
            FROM ahr.models
            ORDER BY activated_at DESC NULLS LAST, created_at DESC
            """
        )
    )
    return [_row(row) for row in result]


async def get_model(session: AsyncSession, model_id: str) -> dict[str, Any] | None:
    result = await session.execute(text("SELECT * FROM ahr.models WHERE model_id = :model_id"), {"model_id": model_id})
    row = result.first()
    return _row(row) if row else None


async def model_metrics(session: AsyncSession, model_id: str) -> list[dict[str, Any]]:
    result = await session.execute(
        text(
            """
            SELECT model_id, dataset_split, metric_name, metric_value,
                   threshold, measured_at, metadata
            FROM ahr.model_metrics
            WHERE model_id = :model_id
            ORDER BY measured_at DESC, metric_name ASC
            """
        ),
        {"model_id": model_id},
    )
    return [_row(row) for row in result]


async def list_experiments(session: AsyncSession) -> list[dict[str, Any]]:
    result = await session.execute(
        text(
            """
            SELECT r.experiment_id, r.name, r.model_config, r.dataset_split,
                   r.status, r.started_at, r.completed_at, r.results_path,
                   coalesce(jsonb_object_agg(m.metric_name, m.metric_value)
                            FILTER (WHERE m.metric_name IS NOT NULL), '{}'::jsonb) AS metrics
            FROM ahr.experiment_runs r
            LEFT JOIN ahr.experiment_metrics m ON m.experiment_id = r.experiment_id
            GROUP BY r.experiment_id
            ORDER BY r.started_at DESC
            """
        )
    )
    return [_row(row) for row in result]


async def get_experiment(session: AsyncSession, experiment_id: str) -> dict[str, Any] | None:
    result = await session.execute(
        text("SELECT * FROM ahr.experiment_runs WHERE experiment_id = :experiment_id"),
        {"experiment_id": experiment_id},
    )
    row = result.first()
    if not row:
        return None
    experiment = _row(row)
    metrics = await session.execute(
        text("SELECT metric_name, metric_value, metadata FROM ahr.experiment_metrics WHERE experiment_id = :experiment_id ORDER BY metric_name"),
        {"experiment_id": experiment_id},
    )
    experiment["metrics"] = [_row(item) for item in metrics]
    return experiment


async def insert_experiment(session: AsyncSession, run: dict[str, Any], metrics: dict[str, float]) -> None:
    await session.execute(
        text(
            """
            INSERT INTO ahr.experiment_runs(
                experiment_id, name, model_config, dataset_split, status,
                started_at, completed_at, results_path, metadata
            )
            VALUES (
                :experiment_id, :name, CAST(:model_config AS jsonb),
                :dataset_split, 'completed', now(), now(), :results_path,
                CAST(:metadata AS jsonb)
            )
            ON CONFLICT (experiment_id) DO UPDATE SET
                status = excluded.status,
                completed_at = excluded.completed_at,
                results_path = excluded.results_path,
                metadata = excluded.metadata
            """
        ),
        run,
    )
    for name, value in metrics.items():
        await session.execute(
            text(
                """
                INSERT INTO ahr.experiment_metrics(experiment_id, metric_name, metric_value)
                VALUES (:experiment_id, :metric_name, :metric_value)
                ON CONFLICT (experiment_id, metric_name) DO UPDATE SET
                    metric_value = excluded.metric_value,
                    created_at = now()
                """
            ),
            {"experiment_id": run["experiment_id"], "metric_name": name, "metric_value": float(value)},
        )
    await session.commit()


async def overview(session: AsyncSession) -> dict[str, Any]:
    values = (
        await session.execute(
            text(
                """
                SELECT
                  (SELECT count(*) FROM ahr.events) AS total_events,
                  (SELECT count(*) FROM ahr.events
                     WHERE timestamp >= now() - interval '1 minute') AS events_per_min,
                  (SELECT count(*) FROM ahr.alerts
                     WHERE status IN ('new','open')) AS active_alerts,
                  (SELECT count(*) FROM ahr.alerts
                     WHERE severity >= 8 AND status IN ('new','open')) AS critical_alerts,
                  (SELECT count(*) FROM ahr.incidents
                     WHERE status IN ('open','investigating')) AS open_incidents,
                  (SELECT count(*) FROM ahr.incidents
                     WHERE coalesce(risk_score, 0) >= 0.8 AND status IN ('open','investigating')) AS critical_incidents,
                  (SELECT coalesce(max(risk_score), 0) FROM ahr.incidents) AS overall_security_risk,
                  (SELECT count(*) FROM ahr.rules WHERE status = 'active') AS active_rules,
                  (SELECT count(*) FROM ahr.rules WHERE status = 'shadow') AS shadow_rules
                """
            )
        )
    ).first()
    source_rows = await session.execute(
        text(
            """
            SELECT source, count(*) AS count
            FROM ahr.events
            WHERE timestamp >= now() - interval '24 hours'
            GROUP BY source
            ORDER BY count DESC
            """
        )
    )
    severity_rows = await session.execute(
        text(
            """
            SELECT coalesce(severity, 0) AS severity, count(*) AS count
            FROM ahr.alerts
            GROUP BY coalesce(severity, 0)
            ORDER BY severity DESC
            """
        )
    )
    top_src = await session.execute(
        text(
            """
            SELECT src_ip, count(*) AS count
            FROM ahr.events
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
            """
        )
    )
    event_types = await session.execute(
        text(
            """
            SELECT event_type, count(*) AS count
            FROM ahr.events
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
            """
        )
    )
    return {
        "cards": _row(values),
        "events_by_source": [_row(row) for row in source_rows],
        "alerts_by_severity": [_row(row) for row in severity_rows],
        "top_source_ips": [_row(row) for row in top_src],
        "top_event_types": [_row(row) for row in event_types],
    }


async def timeseries(session: AsyncSession, minutes: int = 60) -> list[dict[str, Any]]:
    safe_minutes = min(max(minutes, 5), 24 * 60)
    result = await session.execute(
        text(
            """
            SELECT date_trunc('minute', timestamp) AS bucket,
                   source,
                   count(*) AS count
            FROM ahr.events
            WHERE timestamp >= now() - (:minutes * interval '1 minute')
            GROUP BY bucket, source
            ORDER BY bucket ASC, source ASC
            """
        ),
        {"minutes": safe_minutes},
    )
    return [_row(row) for row in result]
