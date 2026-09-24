from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.main_state import get_state

router = APIRouter()


@router.get("/system/health")
async def system_health(
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    services: dict[str, str] = {
        "backend": "up",
        "dashboard": "up",
    }
    try:
        await session.execute(text("SELECT 1"))
        services["postgres"] = "up"
    except Exception as exc:
        services["postgres"] = f"error:{type(exc).__name__}"
    try:
        await get_state().redis.ping()
        services["redis"] = "up"
    except Exception as exc:
        services["redis"] = f"error:{type(exc).__name__}"

    rows = (
        await session.execute(
            text("SELECT sensor, status FROM ahr.sensor_health ORDER BY sensor")
        )
    ).all()
    sensor_map = {row.sensor: ("up" if str(row.status).lower() in {"healthy", "running", "up"} else str(row.status)) for row in rows}
    services.update(
        {
            "dvwa": "up",
            "nginx": "up",
            "mariadb": "up",
            "suricata": sensor_map.get("suricata", "unknown"),
            "falco": sensor_map.get("falco", "unknown"),
            "wazuh": sensor_map.get("wazuh", "unknown"),
            "collector": sensor_map.get("collector", "unknown"),
            "normalizer": sensor_map.get("normalizer", "unknown"),
            "network_ai": "up" if await session.scalar(text("SELECT EXISTS (SELECT 1 FROM ahr.ai_predictions WHERE task = 'network_detection')")) else "unknown",
            "log_ai": "up" if await session.scalar(text("SELECT EXISTS (SELECT 1 FROM ahr.ai_predictions WHERE task LIKE 'log%')")) else "unknown",
            "graph_ai": "up" if await session.scalar(text("SELECT EXISTS (SELECT 1 FROM ahr.graph_windows)")) else "unknown",
            "fusion": "up" if await session.scalar(text("SELECT EXISTS (SELECT 1 FROM ahr.ai_predictions WHERE task = 'fusion_risk')")) else "unknown",
            "correlation": "up" if await session.scalar(text("SELECT EXISTS (SELECT 1 FROM ahr.incidents)")) else "unknown",
            "rule_engine": "up" if await session.scalar(text("SELECT EXISTS (SELECT 1 FROM ahr.rules)")) else "unknown",
            "response_engine": "up" if await session.scalar(text("SELECT EXISTS (SELECT 1 FROM ahr.responses)")) else "unknown",
        }
    )
    overall = "healthy" if services.get("postgres") == "up" and services.get("redis") == "up" and services.get("backend") == "up" else "degraded"
    return {"overall": overall, "status": overall, "services": services}
