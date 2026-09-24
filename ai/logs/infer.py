from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import redis.asyncio as redis

from ai.network.config import Settings
from ai.network.db import connect

from .minilm import MiniLMEmbedder
from .representation import normalized_log_text
from .train import MODEL_ID, MODEL_VERSION


def _payload(fields: dict[str, str]) -> dict[str, Any]:
    return json.loads(fields.get("payload", "{}"))


async def persist(connection: Any, event: dict[str, Any], score: float, predicted: str, latency_ms: float) -> None:
    prediction_id = f"{MODEL_ID}:{event['event_id']}"
    await connection.execute(
        """
        INSERT INTO ahr.ai_predictions(
            prediction_id, event_id, model_id, model_version, task, score,
            predicted_class, risk_level, confidence, explanation
        )
        VALUES ($1,$2,$3,$4,'log_anomaly',$5,$6,$7,$8,$9::jsonb)
        ON CONFLICT (prediction_id) DO UPDATE SET
            score = excluded.score,
            predicted_class = excluded.predicted_class,
            risk_level = excluded.risk_level,
            confidence = excluded.confidence,
            explanation = excluded.explanation
        """,
        prediction_id,
        event["event_id"],
        MODEL_ID,
        MODEL_VERSION,
        score,
        predicted,
        "medium" if predicted == "suspicious" else "low",
        score if predicted == "suspicious" else 1.0 - score,
        json.dumps({"latency_ms": latency_ms, "embedding_dim": 384}),
    )
    await connection.execute(
        """
        UPDATE ahr.events
        SET ai = jsonb_set(
            jsonb_set(ai, '{log_score}', to_jsonb($2::double precision), true),
            '{risk_level}', to_jsonb($3::text), true
        )
        WHERE event_id = $1
        """,
        event["event_id"],
        score,
        "medium" if predicted == "suspicious" else "low",
    )


def predict(model: dict[str, Any], embedder: MiniLMEmbedder, event: dict[str, Any]) -> tuple[float, str]:
    vector = embedder.encode([normalized_log_text(event)])
    anomaly_raw = -float(model["iforest"].decision_function(vector)[0])
    anomaly_score = max(0.0, min(1.0, 0.5 + anomaly_raw))
    class_prob = float(model["classifier"].predict_proba(vector)[0][1])
    score = max(anomaly_score, class_prob)
    return score, "suspicious" if score >= 0.5 else "benign"


async def service() -> None:
    settings = Settings.from_env()
    model_path = Path("/opt/ahr-idps/experiments/models/log-ai.joblib")
    model = joblib.load(model_path)
    embedder = MiniLMEmbedder()
    redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        decode_responses=True,
        socket_timeout=15,
    )
    connection = await connect(settings)
    heartbeat = Path("/tmp/log-ai-heartbeat.json")
    heartbeat.write_text(json.dumps({"status": "running", "updated_at": datetime.now(UTC).isoformat()}), encoding="utf-8")
    try:
        while True:
            records = await redis_client.xreadgroup(
                groupname="ai-log",
                consumername="ai-log-1",
                streams={settings.normalized_stream: ">"},
                count=50,
                block=5000,
            )
            if not records:
                heartbeat.write_text(json.dumps({"status": "running", "updated_at": datetime.now(UTC).isoformat()}), encoding="utf-8")
                continue
            for _stream, messages in records:
                for stream_id, fields in messages:
                    event = _payload(fields)
                    started = time.perf_counter()
                    score, predicted = predict(model, embedder, event)
                    latency_ms = (time.perf_counter() - started) * 1000
                    await persist(connection, event, score, predicted, latency_ms)
                    await redis_client.xadd(
                        settings.predictions_stream,
                        {
                            "event_id": event["event_id"],
                            "model": MODEL_ID,
                            "version": MODEL_VERSION,
                            "log_anomaly_score": f"{score:.8f}",
                            "predicted_class": predicted,
                            "latency_ms": f"{latency_ms:.4f}",
                        },
                        maxlen=100000,
                        approximate=True,
                    )
                    await redis_client.xack(settings.normalized_stream, "ai-log", stream_id)
            heartbeat.write_text(json.dumps({"status": "running", "updated_at": datetime.now(UTC).isoformat()}), encoding="utf-8")
    finally:
        await connection.close()
        await redis_client.aclose()


def main() -> None:
    asyncio.run(service())


if __name__ == "__main__":
    main()
