from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.main_state import get_state
from backend.services import repository

router = APIRouter()


def _synthetic(name: str, status: str, detail: str | None = None) -> dict[str, object]:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "sensor": name,
        "status": status,
        "last_event_at": None,
        "last_ingestion_at": now,
        "error_count": 0 if status in {"healthy", "reporting"} else 1,
        "details": {"detail": detail} if detail else {},
        "updated_at": now,
    }


@router.get("/sensors")
async def sensors(session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    rows = await repository.sensor_rows(session)
    state = get_state()
    try:
        await state.redis.ping()
        rows.append(_synthetic("redis", "healthy"))
    except Exception as exc:
        rows.append(_synthetic("redis", "error", type(exc).__name__))
    rows.append(_synthetic("postgresql", "healthy"))
    rows.append(_synthetic("collector", "healthy" if rows else "unknown"))
    rows.append(_synthetic("normalizer", "healthy" if rows else "unknown"))
    rows.append(_synthetic("dvwa", "reporting" if any(r.get("sensor") == "nginx" for r in rows) else "unknown"))
    return {"items": rows, "total": len(rows)}
