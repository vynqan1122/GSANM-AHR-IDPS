from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/dashboard/overview")
async def overview(session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    return await repository.overview(session)


@router.get("/dashboard/timeseries")
async def timeseries(
    minutes: int = Query(60, ge=5, le=1440),
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    return {"items": await repository.timeseries(session, minutes)}
