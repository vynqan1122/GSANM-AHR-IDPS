from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.main_state import get_state
from backend.services import repository

router = APIRouter()


def _artifact_models() -> list[dict[str, object]]:
    root = Path(get_state().settings.experiments_dir) / "models"
    items: list[dict[str, object]] = []
    for meta_path in sorted(root.glob("*.metadata.json")) if root.exists() else []:
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            metadata = {}
        model_id = meta_path.name.replace(".metadata.json", "")
        metrics_path = root / f"{model_id}.metrics.json"
        metrics = {}
        if metrics_path.exists():
            try:
                metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                metrics = {}
        items.append(
            {
                "model_id": model_id,
                "name": metadata.get("name") or model_id,
                "model_type": metadata.get("model_type") or metadata.get("task") or "security_model",
                "version": metadata.get("version") or "artifact",
                "status": "loaded" if metrics else "registered",
                "artifact_uri": str(meta_path),
                "training_metadata": metadata,
                "artifact_metrics": metrics,
            }
        )
    return items


@router.get("/models")
async def models(session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    db_items = await repository.list_models(session)
    by_id = {item["model_id"]: item for item in db_items}
    for item in _artifact_models():
        by_id.setdefault(str(item["model_id"]), item)
    items = list(by_id.values())
    return {"items": items, "total": len(items)}


@router.get("/models/{model_id}")
async def model_by_id(model_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    model = await repository.get_model(session, model_id)
    if model is not None:
        return model
    for item in _artifact_models():
        if item["model_id"] == model_id:
            return item
    raise HTTPException(status_code=404, detail="model not found")


@router.get("/models/{model_id}/metrics")
async def model_metrics(model_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    rows = await repository.model_metrics(session, model_id)
    artifact = next((item for item in _artifact_models() if item["model_id"] == model_id), None)
    return {"model_id": model_id, "items": rows, "artifact_metrics": (artifact or {}).get("artifact_metrics", {})}

