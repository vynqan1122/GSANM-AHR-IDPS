from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/events")
async def events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    source: str | None = None,
    severity: int | None = Query(None, ge=0, le=10),
    event_type: str | None = None,
    src_ip: str | None = None,
    container: str | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    return await repository.list_events(
        session,
        page=page,
        page_size=page_size,
        filters={
            "source": source,
            "severity": severity,
            "event_type": event_type,
            "src_ip": src_ip,
            "container": container,
            "time_from": time_from,
            "time_to": time_to,
        },
    )


@router.get("/events/{event_id}")
async def event_by_id(
    event_id: str, session: AsyncSession = Depends(session_dependency)
) -> dict[str, object]:
    event = await repository.get_event(session, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event
