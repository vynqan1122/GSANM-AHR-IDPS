from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/incidents")
async def incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    return await repository.list_incidents(session, page=page, page_size=page_size, status=status)


@router.get("/incidents/{incident_id}")
async def incident_by_id(
    incident_id: str, session: AsyncSession = Depends(session_dependency)
) -> dict[str, object]:
    incident = await repository.get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident
