"""FastAPI application for Phase 4 API, dashboard, and WebSockets."""

from __future__ import annotations

from contextlib import asynccontextmanager
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.api import alerts, containers, dashboard, events, experiments, health, incidents, models, network, responses, rules, sensors, system
from backend.config import Settings
from backend.db.session import create_engine, create_session_factory
from backend.main_state import AppState, set_state
from backend.services.redis_stream import redis_client
from backend.websocket import events as websocket_events


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.from_env()
    engine = create_engine(settings)
    redis = redis_client(settings)
    set_state(AppState(settings, engine, create_session_factory(engine), redis))
    try:
        yield
    finally:
        await redis.aclose()
        await engine.dispose()


app = FastAPI(
    title="AHR-IDPS API",
    version="4.0.0",
    lifespan=lifespan,
)

for router in (
    health.router,
    events.router,
    incidents.router,
    responses.router,
    rules.router,
    network.router,
    models.router,
    experiments.router,
    alerts.router,
    sensors.router,
    containers.router,
    dashboard.router,
    system.router,
):
    app.include_router(router, prefix="/api")

app.include_router(websocket_events.router, prefix="/ws")

dashboard_dist = Path(os.getenv("DASHBOARD_DIST", "/opt/ahr-idps/dashboard/dist"))
if dashboard_dist.exists():
    app.mount("/dashboard", StaticFiles(directory=dashboard_dist, html=True), name="dashboard")


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")
