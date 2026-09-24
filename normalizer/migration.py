"""Small, checksum-enforced SQL migration runner for the app-owned schema."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import asyncpg

from .config import Settings


MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{3,})_[a-z0-9_]+\.sql$")
LOCK_NAME = "ahr-idps-schema-migrations-v1"


async def connect(settings: Settings) -> asyncpg.Connection:
    return await asyncpg.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        command_timeout=60,
        server_settings={"application_name": "ahr-idps-normalizer-migrations"},
    )


def migration_files(directory: Path) -> list[tuple[str, Path, str]]:
    if not directory.is_dir():
        raise RuntimeError(f"migration directory does not exist: {directory}")
    result: list[tuple[str, Path, str]] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.sql")):
        match = MIGRATION_NAME.fullmatch(path.name)
        if not match:
            raise RuntimeError(f"invalid migration filename: {path.name}")
        version = match.group("version")
        if version in seen:
            raise RuntimeError(f"duplicate migration version: {version}")
        seen.add(version)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result.append((version, path, digest))
    if not result:
        raise RuntimeError(f"no SQL migrations found in {directory}")
    return result


async def run_migrations(settings: Settings) -> None:
    connection = await connect(settings)
    locked = False
    try:
        await connection.execute("SELECT pg_advisory_lock(hashtext($1))", LOCK_NAME)
        locked = True
        # Phase 1 provisions the app-owned ``ahr`` schema without granting the
        # application role database-wide CREATE. PostgreSQL still checks that
        # database privilege for ``CREATE SCHEMA IF NOT EXISTS`` even when the
        # schema already exists, so assert ownership instead of attempting to
        # recreate it from the runtime service.
        schema_ready = await connection.fetchval(
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_namespace
                WHERE nspname = 'ahr'
                  AND nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                  AND has_schema_privilege(current_user, 'ahr', 'USAGE,CREATE')
            )
            """
        )
        if not schema_ready:
            raise RuntimeError("app-owned ahr schema is missing or not writable")
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ahr.schema_migrations (
                version text PRIMARY KEY,
                filename text NOT NULL,
                sha256 char(64) NOT NULL,
                applied_at timestamptz NOT NULL DEFAULT now()
            );
            """
        )
        applied_rows = await connection.fetch(
            "SELECT version, filename, sha256 FROM ahr.schema_migrations"
        )
        applied = {row["version"]: row for row in applied_rows}
        for version, path, digest in migration_files(settings.migrations_dir):
            previous = applied.get(version)
            if previous:
                if previous["sha256"].strip() != digest:
                    raise RuntimeError(
                        f"applied migration {version} checksum differs from {path.name}"
                    )
                continue
            sql = path.read_text(encoding="utf-8")
            async with connection.transaction():
                await connection.execute(sql)
                await connection.execute(
                    """
                    INSERT INTO ahr.schema_migrations(version, filename, sha256)
                    VALUES ($1, $2, $3)
                    """,
                    version,
                    path.name,
                    digest,
                )
    finally:
        if locked:
            await connection.execute("SELECT pg_advisory_unlock(hashtext($1))", LOCK_NAME)
        await connection.close()
