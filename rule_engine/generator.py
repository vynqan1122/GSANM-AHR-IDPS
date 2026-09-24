from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import redis.asyncio as redis

from ai.graph.dataset import row_to_event
from ai.network.config import Settings
from ai.network.db import connect

from .abstraction import contains_sample_specific_artifact
from .engine_selector import select_engine
from .explainer import explain
from .pattern_miner import mine_patterns
from .templates import falco, suricata, wazuh


GENERATOR = "ahr-rulegen-v1"
MODEL_VERSIONS = {"fusion": "fusion-v1", "graph": "graphsage-v1", "rule_generator": GENERATOR}


def sid_for(pattern: dict[str, Any]) -> int:
    digest = hashlib.sha256(json.dumps(pattern, sort_keys=True).encode("utf-8")).hexdigest()
    return 9100000 + (int(digest[:6], 16) % 899999)


def render_candidate(pattern: dict[str, Any], engine: str) -> str:
    sid = sid_for(pattern)
    if engine == "suricata":
        return suricata.render(pattern, sid)
    if engine == "falco":
        return falco.render(pattern)
    return wazuh.render(pattern, sid)


async def load_recent_events(connection: Any, *, window_minutes: int, limit: int = 5000) -> list[dict[str, Any]]:
    rows = await connection.fetch(
        """
        SELECT *
        FROM ahr.events
        WHERE timestamp >= now() - ($1::int * interval '1 minute')
        ORDER BY timestamp DESC
        LIMIT $2
        """,
        window_minutes,
        limit,
    )
    return [row_to_event(row) for row in rows]


async def store_candidate(connection: Any, pattern: dict[str, Any], content: str, engine: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    rule_id = "gen-" + hashlib.sha256((engine + digest).encode("utf-8")).hexdigest()[:24]
    metadata = {
        "pattern": pattern,
        "support": pattern["support"],
        "confidence": pattern["confidence"],
        "model_versions": MODEL_VERSIONS,
        "explanation": explain(pattern, support=pattern["support"], confidence=pattern["confidence"]),
    }
    await connection.execute(
        """
        INSERT INTO ahr.rules(
            rule_id, engine, name, description, status, source, created_by,
            origin, generator, pattern, support, confidence, model_versions, parent_rule_id
        )
        VALUES ($1,$2,$3,$4,'candidate','generated',$5::text,$6::varchar,$5::varchar,$7::jsonb,$8,$9,$10::jsonb,NULL)
        ON CONFLICT (rule_id) DO UPDATE SET
            status = 'candidate',
            source = 'generated',
            pattern = excluded.pattern,
            support = excluded.support,
            confidence = excluded.confidence,
            model_versions = excluded.model_versions,
            updated_at = now()
        """,
        rule_id,
        engine,
        f"AHR generated {engine} candidate",
        "Candidate rule generated from repeated high-confidence anomaly pattern; not active.",
        GENERATOR,
        "ai_pattern_mining",
        json.dumps(pattern),
        int(pattern["support"]),
        float(pattern["confidence"]),
        json.dumps(MODEL_VERSIONS),
    )
    await connection.execute(
        """
        INSERT INTO ahr.rule_versions(rule_id, version, content, content_sha256, metadata, created_by)
        VALUES ($1,1,$2,$3,$4::jsonb,$5)
        ON CONFLICT (rule_id, version) DO UPDATE SET
            content = excluded.content,
            content_sha256 = excluded.content_sha256,
            metadata = excluded.metadata
        """,
        rule_id,
        content,
        digest,
        json.dumps(metadata),
        GENERATOR,
    )
    return rule_id


async def generate_once(
    *,
    min_support: int = 5,
    min_confidence: float = 0.85,
    window_minutes: int = 60,
    max_candidates: int = 10,
    publish: bool = True,
) -> list[str]:
    settings = Settings.from_env()
    connection = await connect(settings)
    redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        decode_responses=True,
    )
    stored: list[str] = []
    try:
        events = await load_recent_events(connection, window_minutes=window_minutes)
        for pattern in mine_patterns(events, min_support=min_support, min_confidence=min_confidence)[:max_candidates]:
            engine = select_engine(pattern)
            content = render_candidate(pattern, engine)
            examples = [event for event in events if event["event_id"] in set(pattern["example_event_ids"])]
            if contains_sample_specific_artifact(content, examples):
                continue
            rule_id = await store_candidate(connection, pattern, content, engine)
            stored.append(rule_id)
            if publish:
                await redis_client.xadd(
                    "security.rules",
                    {
                        "rule_id": rule_id,
                        "engine": engine,
                        "status": "candidate",
                        "support": str(pattern["support"]),
                        "confidence": f"{pattern['confidence']:.8f}",
                    },
                    maxlen=100000,
                    approximate=True,
                )
        return stored
    finally:
        await connection.close()
        await redis_client.aclose()


async def service() -> None:
    heartbeat = Path(os.getenv("RULEGEN_HEARTBEAT", "/tmp/rulegen-heartbeat.json"))
    interval = int(os.getenv("RULEGEN_INTERVAL_SECONDS", "300"))
    min_support = int(os.getenv("RULEGEN_MIN_SUPPORT", "5"))
    min_confidence = float(os.getenv("RULEGEN_MIN_CONFIDENCE", "0.85"))
    window_minutes = int(os.getenv("RULEGEN_WINDOW_MINUTES", "60"))
    while True:
        try:
            generated = await generate_once(
                min_support=min_support,
                min_confidence=min_confidence,
                window_minutes=window_minutes,
            )
            heartbeat.write_text(
                json.dumps({"status": "running", "updated_at": datetime.now(UTC).isoformat(), "generated": generated}),
                encoding="utf-8",
            )
        except Exception as exc:
            heartbeat.write_text(
                json.dumps({"status": "degraded", "updated_at": datetime.now(UTC).isoformat(), "error_type": exc.__class__.__name__}),
                encoding="utf-8",
            )
        await asyncio.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--min-support", type=int, default=5)
    parser.add_argument("--min-confidence", type=float, default=0.85)
    parser.add_argument("--window-minutes", type=int, default=60)
    parser.add_argument("--max-candidates", type=int, default=10)
    args = parser.parse_args()
    if args.once:
        print(json.dumps(asyncio.run(generate_once(
            min_support=args.min_support,
            min_confidence=args.min_confidence,
            window_minutes=args.window_minutes,
            max_candidates=args.max_candidates,
        )), sort_keys=True))
    else:
        asyncio.run(service())


if __name__ == "__main__":
    main()
