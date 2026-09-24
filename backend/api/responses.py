from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/responses")
async def responses(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    incident_id: str | None = None,
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    return await repository.list_responses(
        session,
        page=page,
        page_size=page_size,
        status=status,
        incident_id=incident_id,
    )


@router.get("/responses/{response_id}")
async def response_by_id(
    response_id: str,
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    response = await repository.get_response(session, response_id)
    if response is None:
        raise HTTPException(status_code=404, detail="response not found")
    return response

