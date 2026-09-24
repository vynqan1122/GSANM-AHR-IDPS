from __future__ import annotations

import asyncpg

from .config import Settings


async def connect(settings: Settings) -> asyncpg.Connection:
    return await asyncpg.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        command_timeout=60,
        server_settings={"application_name": "ahr-idps-network-ai"},
    )
