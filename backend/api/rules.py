from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository

router = APIRouter()


@router.get("/rules")
async def rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    source: str | None = None,
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    return await repository.list_rules(session, page=page, page_size=page_size, status=status, source=source)


@router.get("/rules/{rule_id}")
async def rule_by_id(rule_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    rule = await repository.get_rule(session, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule
