from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis.asyncio as redis
from redis.exceptions import ResponseError
import xgboost as xgb

from ai.graph.dataset import row_to_event
from ai.network.config import Settings
from ai.network.db import connect

from .dataset import FEATURE_NAMES, event_density, feature_vector
from .scoring import risk_level, score_components, weighted_baseline
from .train import MODEL_ID, MODEL_VERSION


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


async def fetch_event(connection: Any, event_id: str) -> dict[str, Any] | None:
    row = await connection.fetchrow("SELECT * FROM ahr.events WHERE event_id = $1", event_id)
    return row_to_event(row) if row else None


async def persist(
    connection: Any,
    event: dict[str, Any],
    baseline: Any,
    score: float,
    risk: str,
    method: str,
    latency_ms: float,
) -> None:
    prediction_id = f"{MODEL_ID}:{event['event_id']}"
    explanation = {
        **baseline.to_dict(),
        "selected_method": method,
        "latency_ms": latency_ms,
        "features": list(FEATURE_NAMES),
    }
    await connection.execute(
        """
        INSERT INTO ahr.ai_predictions(
            prediction_id, event_id, model_id, model_version, task, score,
            predicted_class, risk_level, confidence, explanation, missing_components
        )
        VALUES ($1,$2,$3,$4,'fusion_risk',$5,$6,$7,$8,$9::jsonb,$10::jsonb)
        ON CONFLICT (prediction_id) DO UPDATE SET
            score = excluded.score,
            predicted_class = excluded.predicted_class,
            risk_level = excluded.risk_level,
            confidence = excluded.confidence,
            explanation = excluded.explanation,
            missing_components = excluded.missing_components
        """,
        prediction_id,
        event["event_id"],
        MODEL_ID,
        MODEL_VERSION,
        score,
        "attack" if score >= 0.55 else "benign",
        risk,
        max(score, 1.0 - score),
        json.dumps(explanation),
        json.dumps(baseline.missing_scores),
    )
    await connection.execute(
        """
        UPDATE ahr.events
        SET ai =
            jsonb_set(
              jsonb_set(
                jsonb_set(
                  jsonb_set(
                    jsonb_set(ai, '{rule_score}', coalesce(to_jsonb($6::double precision), 'null'::jsonb), true),
                    '{context_score}', coalesce(to_jsonb($7::double precision), 'null'::jsonb), true
                  ),
                  '{fusion_score}', coalesce(to_jsonb($2::double precision), 'null'::jsonb), true
                ),
                '{risk_level}', coalesce(to_jsonb($3::text), 'null'::jsonb), true
              ),
              '{fusion_breakdown}', $4::jsonb, true
            )
            || jsonb_build_object('model_versions', coalesce(ai->'model_versions', '{}'::jsonb) || jsonb_build_object('fusion', $5::text))
        WHERE event_id = $1
        """,
        event["event_id"],
        score,
        risk,
        json.dumps(explanation),
        MODEL_VERSION,
        baseline.components.get("rule_score"),
        baseline.components.get("context_score"),
    )


async def fuse_event(connection: Any, model: xgb.Booster | None, event: dict[str, Any]) -> tuple[float, str, Any, str]:
    density = await event_density(connection, event)
    components = score_components(event, density)
    baseline = weighted_baseline(components)
    method = "weighted-baseline"
    score = baseline.fusion_score
    if model is not None:
        vector = feature_vector(event, density)
        try:
            score = float(model.predict(xgb.DMatrix([vector], feature_names=list(FEATURE_NAMES)))[0])
            method = "xgboost-meta-classifier"
        except Exception:
            score = baseline.fusion_score
            method = "weighted-baseline-fallback"
    return score, risk_level(score), baseline, method


async def service() -> None:
    settings = Settings.from_env()
    group = os.getenv("FUSION_GROUP", "fusion-engine")
    consumer = os.getenv("FUSION_CONSUMER", "fusion-engine-1")
    heartbeat_path = Path(os.getenv("FUSION_HEARTBEAT", "/tmp/fusion-heartbeat.json"))
    start_at_end = os.getenv("FUSION_START_AT_END", "true").lower() in {"1", "true", "yes"}
    model_path = Path(os.getenv("FUSION_MODEL_PATH", "/opt/ahr-idps/experiments/models/fusion-hybrid-xgboost.json"))
    model: xgb.Booster | None = None
    if model_path.exists():
        model = xgb.Booster()
        model.load_model(model_path)
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
        await prepare_group(redis_client, settings.predictions_stream, group, start_at_end=start_at_end)
        heartbeat(heartbeat_path, "running", processed=processed, model_loaded=model is not None)
        while True:
            records = await redis_client.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={settings.predictions_stream: ">"},
                count=50,
                block=5000,
            )
            if not records:
                heartbeat(heartbeat_path, "running", processed=processed, model_loaded=model is not None)
                continue
            for _stream, messages in records:
                for stream_id, fields in messages:
                    started = time.perf_counter()
                    if fields.get("model") == MODEL_ID:
                        await redis_client.xack(settings.predictions_stream, group, stream_id)
                        continue
                    event_id = fields.get("event_id")
                    if not event_id:
                        await redis_client.xack(settings.predictions_stream, group, stream_id)
                        continue
                    event = await fetch_event(connection, event_id)
                    if event is None:
                        await redis_client.xack(settings.predictions_stream, group, stream_id)
                        continue
                    score, risk, baseline, method = await fuse_event(connection, model, event)
                    await persist(connection, event, baseline, score, risk, method, (time.perf_counter() - started) * 1000)
                    await redis_client.xadd(
                        settings.predictions_stream,
                        {
                            "event_id": event_id,
                            "model": MODEL_ID,
                            "version": MODEL_VERSION,
                            "fusion_score": f"{score:.8f}",
                            "risk_level": risk,
                            "method": method,
                        },
                        maxlen=100000,
                        approximate=True,
                    )
                    await redis_client.xack(settings.predictions_stream, group, stream_id)
                    processed += 1
                    heartbeat(heartbeat_path, "running", processed=processed, last_stream_id=stream_id, model_loaded=model is not None)
    finally:
        await connection.close()
        await redis_client.aclose()


def main() -> None:
    asyncio.run(service())


if __name__ == "__main__":
    main()
