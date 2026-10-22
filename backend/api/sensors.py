from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from backend.db.session import session_dependency
from backend.main_state import get_state
from backend.services import repository
from backend.services.activity import activity_status

router = APIRouter()


def _synthetic(name: str, status: str, detail: str | None = None, last_ingestion=None) -> dict[str, object]:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "sensor": name,
        "status": status,
        "last_event_at": None,
        "last_ingestion_at": last_ingestion,
        "error_count": 0,
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
    last_ingestion = await session.scalar(text('SELECT max(ingestion_timestamp) FROM ahr.events'))
    for name in ('collector','normalizer'):
        rows.append(_synthetic(name,activity_status(last_ingestion),
                               'Observed through normalized event ingestion; process health is reported by Docker.',last_ingestion))
    rows.append(_synthetic("dvwa", "reporting" if any(r.get("sensor") == "nginx" for r in rows) else "unknown"))
    return {"items": rows, "total": len(rows)}
