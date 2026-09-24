"""Tiny application-state holder used by routers without import cycles."""

from __future__ import annotations

from dataclasses import dataclass

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, AsyncSession

from backend.config import Settings


@dataclass(slots=True)
class AppState:
    settings: Settings
    engine: AsyncEngine
    sessions: async_sessionmaker[AsyncSession]
    redis: redis.Redis


_state: AppState | None = None


def set_state(state: AppState) -> None:
    global _state
    _state = state


def get_state() -> AppState:
    if _state is None:
        raise RuntimeError("backend application state has not been initialized")
    return _state
