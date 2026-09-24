from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as redis
import xgboost as xgb

from feature_engine.network_features import build_network_features
from feature_engine.versioning import FEATURES_VERSION

from .config import Settings
from .db import connect


def _payload(fields: dict[str, str]) -> dict[str, Any]:
    return json.loads(fields.get("payload", "{}"))


async def persist_prediction(connection: Any, event: dict[str, Any], score: float, latency_ms: float) -> None:
    predicted = "attack" if score >= 0.5 else "benign"
    risk = "high" if score >= 0.8 else "medium" if score >= 0.5 else "low"
    prediction_id = f"network-xgboost:{event['event_id']}"
    explanation = {"features_version": FEATURES_VERSION, "latency_ms": latency_ms}
    await connection.execute(
        """
        INSERT INTO ahr.ai_predictions(
            prediction_id, event_id, model_id, model_version, task, score,
            predicted_class, risk_level, confidence, explanation
        )
        VALUES ($1,$2,'network-xgboost',$3,'network_detection',$4,$5,$6,$7,$8::jsonb)
        ON CONFLICT (prediction_id) DO UPDATE SET
            score = excluded.score,
            predicted_class = excluded.predicted_class,
            risk_level = excluded.risk_level,
            confidence = excluded.confidence,
            explanation = excluded.explanation
        """,
        prediction_id,
        event["event_id"],
        FEATURES_VERSION,
        score,
        predicted,
        risk,
        max(score, 1.0 - score),
        json.dumps(explanation),
    )
    await connection.execute(
        """
        UPDATE ahr.events
        SET ai = jsonb_set(
            jsonb_set(ai, '{network_score}', to_jsonb($2::double precision), true),
            '{network_class}', to_jsonb($3::text), true
        )
        WHERE event_id = $1
        """,
        event["event_id"],
        score,
        predicted,
    )


async def run_once(settings: Settings) -> int:
    model = xgb.Booster()
    model.load_model(settings.model_path)
    connection = await connect(settings)
    try:
        rows = await connection.fetch(
            """
            SELECT event_id, source, event_type, category, src_ip, src_port,
                   dst_ip, dst_port, protocol, http, container, network, rule,
                   severity, raw_event
            FROM ahr.events
            ORDER BY timestamp DESC
            LIMIT 100
            """
        )
        count = 0
        for row in rows:
            event = dict(row)
            started = time.perf_counter()
            score = float(model.predict(xgb.DMatrix([build_network_features(event)]))[0])
            await persist_prediction(connection, event, score, (time.perf_counter() - started) * 1000)
            count += 1
        return count
    finally:
        await connection.close()


async def service() -> None:
    settings = Settings.from_env()
    model = xgb.Booster()
    model.load_model(settings.model_path)
    redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        decode_responses=True,
        socket_timeout=15,
    )
    connection = await connect(settings)
    last_id = ">"
    settings.heartbeat_path.write_text(
        json.dumps({"status": "running", "updated_at": datetime.now(UTC).isoformat()}),
        encoding="utf-8",
    )
    try:
        while True:
            records = await redis_client.xreadgroup(
                groupname=settings.group,
                consumername=settings.consumer,
                streams={settings.normalized_stream: last_id},
                count=50,
                block=5000,
            )
            if not records:
                settings.heartbeat_path.write_text(
                    json.dumps({"status": "running", "updated_at": datetime.now(UTC).isoformat()}),
                    encoding="utf-8",
                )
                continue
            for _stream, messages in records:
                for stream_id, fields in messages:
                    event = _payload(fields)
                    started = time.perf_counter()
                    score = float(model.predict(xgb.DMatrix([build_network_features(event)]))[0])
                    latency_ms = (time.perf_counter() - started) * 1000
                    await persist_prediction(connection, event, score, latency_ms)
                    await redis_client.xadd(
                        settings.predictions_stream,
                        {
                            "event_id": event["event_id"],
                            "model": "network-xgboost",
                            "version": FEATURES_VERSION,
                            "attack_probability": f"{score:.8f}",
                            "predicted_class": "attack" if score >= 0.5 else "benign",
                            "latency_ms": f"{latency_ms:.4f}",
                        },
                        maxlen=100000,
                        approximate=True,
                    )
                    await redis_client.xack(settings.normalized_stream, settings.group, stream_id)
            settings.heartbeat_path.write_text(
                json.dumps({"status": "running", "updated_at": datetime.now(UTC).isoformat()}),
                encoding="utf-8",
            )
    finally:
        await connection.close()
        await redis_client.aclose()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.once:
        print(json.dumps({"predictions": asyncio.run(run_once(Settings.from_env()))}, sort_keys=True))
    else:
        asyncio.run(service())


if __name__ == "__main__":
    main()
