from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    postgres_host: str
    postgres_port: int
    postgres_db: str
    postgres_user: str
    postgres_password: str
    redis_host: str
    redis_port: int
    redis_password: str
    normalized_stream: str
    predictions_stream: str
    group: str
    consumer: str
    model_path: Path
    heartbeat_path: Path

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            postgres_host=os.getenv("POSTGRES_HOST", "postgres"),
            postgres_port=int(os.getenv("POSTGRES_PORT", "5432")),
            postgres_db=os.environ["POSTGRES_DB"],
            postgres_user=os.environ["POSTGRES_USER"],
            postgres_password=os.environ["POSTGRES_PASSWORD"],
            redis_host=os.getenv("REDIS_HOST", "redis"),
            redis_port=int(os.getenv("REDIS_PORT", "6379")),
            redis_password=os.environ["REDIS_PASSWORD"],
            normalized_stream=os.getenv("NORMALIZED_STREAM", "security.events.normalized"),
            predictions_stream=os.getenv("PREDICTIONS_STREAM", "security.predictions"),
            group=os.getenv("NETWORK_AI_GROUP", "ai-network"),
            consumer=os.getenv("NETWORK_AI_CONSUMER", "ai-network-1"),
            model_path=Path(os.getenv("NETWORK_MODEL_PATH", "/opt/ahr-idps/experiments/models/network-xgboost.json")),
            heartbeat_path=Path(os.getenv("NETWORK_AI_HEARTBEAT", "/tmp/network-ai-heartbeat.json")),
        )
