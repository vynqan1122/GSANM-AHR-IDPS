from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.main_state import get_state

router = APIRouter()


@router.get("/health")
async def health(session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    await session.execute(text("SELECT 1"))
    await get_state().redis.ping()
    return {"status": "healthy", "service": "backend"}
