from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/alerts")
async def alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    return await repository.list_alerts(session, page=page, page_size=page_size)


@router.get("/alerts/{alert_id}")
async def alert_by_id(alert_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    alert = await repository.get_alert(session, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return alert
