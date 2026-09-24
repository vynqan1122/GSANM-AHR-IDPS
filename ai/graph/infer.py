from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import redis.asyncio as redis
from redis.exceptions import ResponseError

from ai.network.config import Settings
from ai.network.db import connect

from .dataset import EVENT_COLUMNS, row_to_event
from .graph_builder import DEFAULT_WINDOW_SECONDS, build_graphs, graph_json, parse_time, session_key
from .graphsage import MODEL_ID, MODEL_VERSION, GraphSAGEWindowClassifier


def _payload(fields: dict[str, str]) -> dict[str, Any]:
    return json.loads(fields.get("payload", "{}"))


def heartbeat(path: Path, status: str = "running", **fields: Any) -> None:
    payload = {"status": status, "updated_at": datetime.now(UTC).isoformat(), **fields}
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")


async def prepare_consumer_group(redis_client: redis.Redis, stream: str, group: str, *, start_at_end: bool) -> None:
    try:
        await redis_client.xgroup_create(name=stream, groupname=group, id="$" if start_at_end else "0-0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    if not start_at_end:
        return
    await redis_client.execute_command("XGROUP", "SETID", stream, group, "$")
    # The graph service is introduced after Phase 3 materialized its consumer
    # group at 0-0. Old pending entries are historical backlog, not live graph
    # alerts. Clear them in bounded batches so realtime startup is immediate.
    while True:
        pending = await redis_client.xpending_range(stream, group, "-", "+", 250)
        ids = [row["message_id"] for row in pending]
        if not ids:
            break
        await redis_client.xack(stream, group, *ids)


async def fetch_context_graph(connection: Any, event: dict[str, Any], window_seconds: int) -> Any:
    event_time = parse_time(event.get("timestamp"))
    rows = await connection.fetch(
        f"""
        SELECT {EVENT_COLUMNS}
        FROM ahr.events
        WHERE timestamp BETWEEN $1 AND $2
        ORDER BY timestamp ASC
        LIMIT 500
        """,
        event_time - timedelta(seconds=window_seconds),
        event_time + timedelta(seconds=window_seconds),
    )
    events = [row_to_event(row) for row in rows]
    if not any(item.get("event_id") == event.get("event_id") for item in events):
        events.append(event)
    target_key = session_key(event, window_seconds)
    graphs = build_graphs(events, window_seconds)
    for graph in graphs:
        if graph.session_key == target_key:
            return graph
    return graphs[0] if graphs else build_graphs([event], window_seconds)[0]


async def persist(
    connection: Any,
    event: dict[str, Any],
    graph: Any,
    score: float,
    baseline_score: float,
    embedding: list[float],
    explanation: dict[str, Any],
    latency_ms: float,
) -> None:
    predicted = "attack" if score >= 0.5 else "benign"
    risk = "high" if score >= 0.8 else "medium" if score >= 0.5 else "low"
    prediction_id = f"{MODEL_ID}:{event['event_id']}"
    await connection.execute(
        """
        INSERT INTO ahr.graph_windows(
            graph_id, session_key, window_start, window_seconds, event_ids,
            node_count, edge_count, graph_json, embedding, explanation,
            score, model_id, model_version
        )
        VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12,$13)
        ON CONFLICT (graph_id) DO UPDATE SET
            event_ids = excluded.event_ids,
            node_count = excluded.node_count,
            edge_count = excluded.edge_count,
            graph_json = excluded.graph_json,
            embedding = excluded.embedding,
            explanation = excluded.explanation,
            score = excluded.score,
            model_id = excluded.model_id,
            model_version = excluded.model_version,
            updated_at = now()
        """,
        graph.graph_id,
        graph.session_key,
        graph.window_start,
        graph.window_seconds,
        json.dumps([item.get("event_id") for item in graph.events if item.get("event_id")]),
        len(graph.nodes),
        len(graph.edges),
        graph_json(graph),
        json.dumps(embedding[:64]),
        json.dumps(explanation),
        score,
        MODEL_ID,
        MODEL_VERSION,
    )
    await connection.execute(
        """
        INSERT INTO ahr.ai_predictions(
            prediction_id, event_id, model_id, model_version, task, score,
            predicted_class, risk_level, confidence, explanation
        )
        VALUES ($1,$2,$3,$4,'graph_window_detection',$5,$6,$7,$8,$9::jsonb)
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
        risk,
        max(score, 1.0 - score),
        json.dumps({"latency_ms": latency_ms, "baseline_score": baseline_score, **explanation}),
    )
    await connection.execute(
        """
        UPDATE ahr.events
        SET ai = jsonb_set(
            jsonb_set(ai, '{graph_score}', to_jsonb($2::double precision), true),
            '{model_versions,graph}', to_jsonb($3::text), true
        )
        WHERE event_id = $1
        """,
        event["event_id"],
        score,
        MODEL_VERSION,
    )


async def service() -> None:
    settings = Settings.from_env()
    model_path = Path(os.getenv("GRAPH_MODEL_PATH", "/opt/ahr-idps/experiments/models/graphsage-security-event.joblib"))
    window_seconds = int(os.getenv("GRAPH_WINDOW_SECONDS", str(DEFAULT_WINDOW_SECONDS)))
    group = os.getenv("GRAPH_AI_GROUP", "graph-builder")
    consumer = os.getenv("GRAPH_AI_CONSUMER", "graph-builder-1")
    start_at_end = os.getenv("GRAPH_START_AT_END", "true").lower() in {"1", "true", "yes"}
    model = GraphSAGEWindowClassifier.load(str(model_path))
    redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        decode_responses=True,
        socket_timeout=15,
    )
    connection = await connect(settings)
    heartbeat_path = Path(os.getenv("GRAPH_AI_HEARTBEAT", "/tmp/graph-ai-heartbeat.json"))
    processed = 0
    heartbeat(heartbeat_path, "starting", processed=processed)
    try:
        await prepare_consumer_group(redis_client, settings.normalized_stream, group, start_at_end=start_at_end)
        heartbeat(heartbeat_path, "running", processed=processed, start_at_end=start_at_end)
        while True:
            records = await redis_client.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={settings.normalized_stream: ">"},
                count=25,
                block=5000,
            )
            if not records:
                heartbeat(heartbeat_path, "running", processed=processed, start_at_end=start_at_end)
                continue
            for _stream, messages in records:
                for stream_id, fields in messages:
                    try:
                        event = _payload(fields)
                        started = time.perf_counter()
                        graph = await fetch_context_graph(connection, event, window_seconds)
                        score, baseline, embedding = model.predict_proba(graph)
                        latency_ms = (time.perf_counter() - started) * 1000
                        explanation = model.explain(graph, score).to_dict()
                        await persist(connection, event, graph, score, baseline, embedding.tolist(), explanation, latency_ms)
                        await redis_client.xadd(
                            settings.predictions_stream,
                            {
                                "event_id": event["event_id"],
                                "model": MODEL_ID,
                                "version": MODEL_VERSION,
                                "graph_score": f"{score:.8f}",
                                "graph_anomaly_score": f"{abs(score - baseline):.8f}",
                                "predicted_class": "attack" if score >= 0.5 else "benign",
                                "latency_ms": f"{latency_ms:.4f}",
                            },
                            maxlen=100000,
                            approximate=True,
                        )
                        await redis_client.xack(settings.normalized_stream, group, stream_id)
                        processed += 1
                        heartbeat(heartbeat_path, "running", processed=processed, last_stream_id=stream_id)
                    except Exception as exc:
                        heartbeat(heartbeat_path, "degraded", processed=processed, error_type=type(exc).__name__, stream_id=stream_id)
                        raise
            heartbeat(heartbeat_path, "running", processed=processed)
    finally:
        await connection.close()
        await redis_client.aclose()


def main() -> None:
    asyncio.run(service())


if __name__ == "__main__":
    main()
