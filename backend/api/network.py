from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/network/summary")
async def network_summary(session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    return await repository.network_summary(session)

