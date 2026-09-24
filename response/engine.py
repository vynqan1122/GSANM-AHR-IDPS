from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai.network.config import Settings
from ai.network.db import connect

from .container import safe_isolation_plan
from .evidence import collect_evidence
from .firewall import temporary_lab_block
from .policy import LEVELS, ResponseConfig, decide_response
from .rollback import rollback_record


TEMPORARY_ACTIONS = {"rate_limit", "lab_block", "isolate_container"}
ALLOWED_ACTIONS = {"auto", "log", "alert", *TEMPORARY_ACTIONS}


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def _row(row: Any) -> dict[str, Any]:
    data = dict(row)
    for key, value in list(data.items()):
        data[key] = _json(value)
    return data


def response_id_for(incident_id: str, action: str) -> str:
    return "rsp-" + hashlib.sha256(f"{incident_id}:{action}:{time.time()}".encode()).hexdigest()[:24]


async def load_incident(connection: Any, incident_id: str) -> dict[str, Any]:
    row = await connection.fetchrow("SELECT * FROM ahr.incidents WHERE incident_id = $1", incident_id)
    if not row:
        raise RuntimeError(f"incident not found: {incident_id}")
    return _row(row)


async def incident_container_target(connection: Any, incident_id: str) -> str | None:
    row = await connection.fetchrow(
        """
        SELECT e.container ->> 'name' AS name
        FROM ahr.events e
        JOIN ahr.incident_events ie ON ie.event_id = e.event_id
        WHERE ie.incident_id = $1
          AND e.container IS NOT NULL
          AND e.container ->> 'name' IS NOT NULL
        ORDER BY e.timestamp DESC
        LIMIT 1
        """,
        incident_id,
    )
    return str(row["name"]) if row and row["name"] else None


def incident_ip_target(incident: dict[str, Any]) -> str | None:
    source_ips = incident.get("source_ips") if isinstance(incident.get("source_ips"), list) else []
    for value in source_ips:
        if value:
            return str(value)
    entities = incident.get("entities") if isinstance(incident.get("entities"), dict) else {}
    session = entities.get("session") if isinstance(entities.get("session"), list) else []
    for value in session:
        text = str(value)
        if "." in text or ":" in text:
            return text
    return None


def explicit_or_policy_action(incident: dict[str, Any], requested_action: str, config: ResponseConfig) -> tuple[str, int, str]:
    if requested_action != "auto":
        if requested_action not in ALLOWED_ACTIONS:
            raise ValueError(f"unsupported response action: {requested_action}")
        level = next((level for level, action in LEVELS.items() if action == requested_action), 0)
        return requested_action, level, "manual allowlisted response action"
    decision = decide_response(incident, config)
    return decision.action, decision.level, decision.reason


async def insert_response(
    connection: Any,
    *,
    response_id: str,
    incident_id: str,
    action: str,
    level: int,
    status: str,
    target: str | None,
    reason: str,
    risk: float,
    parameters: dict[str, Any],
    rollback_data: dict[str, Any],
    requested_by: str,
    expires_at: datetime | None,
) -> None:
    await connection.execute(
        """
        INSERT INTO ahr.responses(
            response_id, incident_id, action_type, action, response_level, status,
            target, parameters, rollback_data, requested_by, reason, risk,
            expires_at, rollback_status, action_audit, completed_at
        )
        VALUES (
            $1,$2,$3::varchar,$3::varchar,$4::varchar,$5::varchar,
            $6,$7::jsonb,$8::jsonb,$9,$10,$11,$12::timestamptz,
            $13::varchar,$14::jsonb,now()
        )
        """,
        response_id,
        incident_id,
        action,
        f"level_{level}",
        status,
        target,
        json.dumps(parameters),
        json.dumps(rollback_data),
        requested_by,
        reason,
        float(risk),
        expires_at,
        "pending" if action in TEMPORARY_ACTIONS and status == "active" else "not_required",
        json.dumps({"destructive": False, "allowlisted_action": action, "level": level}),
    )
    await connection.execute(
        "UPDATE ahr.incidents SET response_status = $2::varchar, updated_at = now() WHERE incident_id = $1",
        incident_id,
        status,
    )


async def execute_response(
    incident_id: str,
    *,
    requested_action: str = "auto",
    requested_by: str = "response-engine",
    evidence_root: str | Path = "evidence",
    ttl_seconds: int = 900,
    apply: bool = False,
) -> dict[str, Any]:
    settings = Settings.from_env()
    config = ResponseConfig.from_env()
    connection = await connect(settings)
    try:
        incident = await load_incident(connection, incident_id)
        action, level, reason = explicit_or_policy_action(incident, requested_action, config)
        risk = float(incident.get("risk_score") or 0.0)
        parameters: dict[str, Any] = {"mode": config.mode, "automatic_block": config.automatic_block, "automatic_container_isolation": config.automatic_container_isolation}
        rollback_data: dict[str, Any] = {"destructive": False}
        target: str | None = None
        status = "completed"
        expires_at: datetime | None = None

        if action == "lab_block":
            target = incident_ip_target(incident) or "127.0.0.1"
            block = temporary_lab_block(target, incident_id=incident_id, ttl_seconds=ttl_seconds, apply=apply)
            parameters["firewall"] = block.to_json()
            rollback_data = {"firewall_tag": block.tag, "rollback_token": block.rollback_token, "destructive": False}
            expires_at = block.expires_at
            status = "active"
        elif action == "isolate_container":
            target = await incident_container_target(connection, incident_id) or "dvwa"
            plan = safe_isolation_plan(target, apply=apply)
            parameters["isolation"] = plan.to_json()
            rollback_data = {"container": target, "disconnect_networks": plan.disconnect_networks, "destructive": False}
            status = "active"
        elif action == "rate_limit":
            target = incident_ip_target(incident) or "127.0.0.1"
            expires_at = datetime.now(timezone.utc)
            parameters["rate_limit"] = {"target": target, "ttl_seconds": ttl_seconds, "applied": apply, "implementation": "lab-audit-wrapper"}
            rollback_data = {"target": target, "destructive": False}
            status = "active"

        response_id = response_id_for(incident_id, action)
        evidence = await collect_evidence(connection, incident_id, evidence_root)
        await insert_response(
            connection,
            response_id=response_id,
            incident_id=incident_id,
            action=action,
            level=level,
            status=status,
            target=target,
            reason=reason,
            risk=risk,
            parameters=parameters,
            rollback_data=rollback_data,
            requested_by=requested_by,
            expires_at=expires_at,
        )
        evidence_id = "evd-" + hashlib.sha256(f"{response_id}:{incident_id}".encode()).hexdigest()[:24]
        await connection.execute(
            """
            INSERT INTO ahr.evidence(evidence_id, incident_id, response_id, path, manifest, bundle_sha256, file_count)
            VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)
            """,
            evidence_id,
            incident_id,
            response_id,
            evidence["path"],
            json.dumps(evidence["manifest"]),
            evidence["bundle_sha256"],
            int(evidence["file_count"]),
        )
        return {"response_id": response_id, "incident_id": incident_id, "action": action, "level": level, "status": status, "target": target, "evidence": evidence}
    finally:
        await connection.close()


async def rollback_expired_responses() -> list[dict[str, Any]]:
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        rows = await connection.fetch(
            """
            SELECT *
            FROM ahr.responses
            WHERE status = 'active'
              AND action IN ('rate_limit', 'lab_block', 'isolate_container')
              AND (expires_at IS NULL OR expires_at <= now())
            ORDER BY started_at ASC
            """
        )
        rolled: list[dict[str, Any]] = []
        for row in rows:
            record = rollback_record(_row(row))
            await connection.execute(
                """
                UPDATE ahr.responses
                SET status = 'expired',
                    rollback_status = 'rolled_back',
                    action_audit = action_audit || $2::jsonb,
                    updated_at = now()
                WHERE response_id = $1
                """,
                row["response_id"],
                json.dumps({"rollback": record}),
            )
            rolled.append(record)
        return rolled
    finally:
        await connection.close()


async def run_once() -> dict[str, Any] | None:
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        row = await connection.fetchrow(
            """
            SELECT incident_id
            FROM ahr.incidents
            WHERE status IN ('open', 'investigating')
              AND coalesce(response_status, 'none') IN ('none', 'pending')
            ORDER BY risk_score DESC NULLS LAST, last_seen DESC
            LIMIT 1
            """
        )
    finally:
        await connection.close()
    if not row:
        return None
    return await execute_response(row["incident_id"])


async def daemon(interval_seconds: int) -> None:
    heartbeat = Path(os.getenv("RESPONSE_HEARTBEAT", "/tmp/response-heartbeat.json"))
    heartbeat.write_text(json.dumps({"status": "starting", "time": time.time()}), encoding="utf-8")
    while True:
        result = await run_once()
        rolled = await rollback_expired_responses()
        heartbeat.write_text(json.dumps({"status": "ok", "last_result": result, "rolled_back": len(rolled), "time": time.time()}, default=str), encoding="utf-8")
        await asyncio.sleep(max(5, interval_seconds))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-id")
    parser.add_argument("--action", default="auto", choices=sorted(ALLOWED_ACTIONS))
    parser.add_argument("--requested-by", default="response-engine")
    parser.add_argument("--evidence-root", default=os.getenv("AHR_EVIDENCE_ROOT", "evidence"))
    parser.add_argument("--ttl-seconds", type=int, default=900)
    parser.add_argument("--apply", action="store_true", help="mark lab-safe wrapper actions as applied; never deletes containers, volumes, or logs")
    parser.add_argument("--rollback-expired", action="store_true")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=int(os.getenv("RESPONSE_INTERVAL_SECONDS", "60")))
    args = parser.parse_args()
    if args.daemon:
        asyncio.run(daemon(args.interval_seconds))
    elif args.rollback_expired:
        print(json.dumps(asyncio.run(rollback_expired_responses()), sort_keys=True, default=str))
    else:
        if not args.incident_id:
            raise SystemExit("--incident-id is required unless --daemon or --rollback-expired is used")
        print(
            json.dumps(
                asyncio.run(
                    execute_response(
                        args.incident_id,
                        requested_action=args.action,
                        requested_by=args.requested_by,
                        evidence_root=args.evidence_root,
                        ttl_seconds=args.ttl_seconds,
                        apply=args.apply,
                    )
                ),
                sort_keys=True,
                default=str,
            )
        )


if __name__ == "__main__":
    main()
