from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/containers")
async def containers(session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    items = await repository.containers(session)
    return {"items": items, "total": len(items)}


@router.get("/containers/{container_id}")
async def container_by_id(container_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    item = await repository.get_container(session, container_id)
    if item is None:
        raise HTTPException(status_code=404, detail="container not found")
    return item
