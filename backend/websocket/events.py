from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from sqlalchemy import text

from backend.main_state import get_state
from backend.services.redis_stream import stream_normalized

router = APIRouter()


async def _serve(websocket: WebSocket, *, alerts_only: bool) -> None:
    await websocket.accept()
    state = get_state()
    try:
        async for message in stream_normalized(
            state.redis, state.settings.normalized_stream, alerts_only=alerts_only
        ):
            await websocket.send_json(message)
    except WebSocketDisconnect:
        return


@router.websocket("/events")
async def ws_events(websocket: WebSocket) -> None:
    await _serve(websocket, alerts_only=False)


@router.websocket("/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    await _serve(websocket, alerts_only=True)


@router.websocket("/incidents")
async def ws_incidents(websocket: WebSocket) -> None:
    await websocket.accept()
    state = get_state()
    async with state.sessions() as session:
        rows = await session.execute(text("SELECT incident_id, status, risk_score, last_seen FROM ahr.incidents ORDER BY last_seen DESC LIMIT 25"))
        await websocket.send_json(
            jsonable_encoder({"items": [dict(row._mapping) for row in rows]})
        )


@router.websocket("/system")
async def ws_system(websocket: WebSocket) -> None:
    await websocket.accept()
    state = get_state()
    await websocket.send_json({"redis": await state.redis.ping(), "backend": "up"})
