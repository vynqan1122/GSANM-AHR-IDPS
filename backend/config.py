"""Backend runtime configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return int(value)


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
    dashboard_dist: str
    experiments_dir: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            postgres_host=os.getenv("POSTGRES_HOST", "postgres"),
            postgres_port=_int_env("POSTGRES_PORT", 5432),
            postgres_db=os.environ["POSTGRES_DB"],
            postgres_user=os.environ["POSTGRES_USER"],
            postgres_password=os.environ["POSTGRES_PASSWORD"],
            redis_host=os.getenv("REDIS_HOST", "redis"),
            redis_port=_int_env("REDIS_PORT", 6379),
            redis_password=os.environ["REDIS_PASSWORD"],
            normalized_stream=os.getenv(
                "NORMALIZED_STREAM", "security.events.normalized"
            ),
            dashboard_dist=os.getenv(
                "DASHBOARD_DIST", "/opt/ahr-idps/dashboard/dist"
            ),
            experiments_dir=os.getenv(
                "EXPERIMENTS_DIR", "/opt/ahr-idps/experiments"
            ),
        )

    @property
    def sqlalchemy_url(self) -> str:
        return (
            "postgresql+asyncpg://"
            f"{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
