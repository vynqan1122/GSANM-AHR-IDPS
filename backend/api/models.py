from __future__ import annotations

import json
import hashlib
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.main_state import get_state
from backend.services import repository
from backend.services.controls import RuntimePolicy, audit
from sqlalchemy import text

router = APIRouter()


CURRENT_MODELS = {
    'network-ai': ('local-network-v2', 'Network AI', 'network-xgboost', 'network_detection'),
    'log-ai': ('local-log-v2', 'Log AI', 'log-ai', 'log_anomaly'),
    'graph-ai': ('local-graph-v2', 'Graph AI', 'graphsage-security-event', 'graph_detection'),
    'fusion-ai': ('local-fusion-v2', 'Fusion AI', 'fusion-hybrid-xgboost', 'fusion_risk'),
}


def public_model(item: dict, model_id: str, metadata: dict, counts: dict) -> dict:
    _, name, _, task = CURRENT_MODELS[model_id]
    return {
        'model_id': model_id, 'name': name, 'model_type': task,
        'version': item['version'], 'status': item['status'],
        'activated_at': item.get('activated_at'),
        'artifact_metrics': metadata.get('metrics', {}),
        'training_metadata': {
            'provider': 'local', 'training_rows': counts.get('train'),
            'dataset_events': sum(counts.values()), 'split_counts': counts,
            'evaluation_split': metadata.get('evaluation_split'),
            'graph_context': 'single_event_causal',
            'metrics': metadata.get('metrics', {}),
        },
    }


@router.get('/models')
async def models(session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    from backend.api.genti import enabled, status
    if enabled():
        state = await status()
        artifact = state.get('model') or {}
        items = [] if not state.get('ready') else [{
            'model_id': 'genti', 'name': 'GenTI · LLM sinh quy tắc', 'model_type': 'rule_generation',
            'version': artifact.get('artifact_sha256'), 'status': 'active',
            'training_metadata': artifact.get('training', {}), 'artifact_metrics': {},
        }]
        return {'items': items, 'total': len(items)}
    by_id = {item['model_id']: item for item in await repository.list_models(session)}
    worker = await get_state().redis.get('ahr:ai-bundle:runtime')
    version = json.loads(worker).get('bundle_version') if worker else None
    items = []
    bundles = Path(get_state().settings.experiments_dir) / 'bundles'
    for manifest in sorted(bundles.glob('*/manifest.json')):
        if hashlib.sha256(manifest.read_bytes()).hexdigest()[:16] != version:
            continue
        counts = json.loads(manifest.read_text()).get('counts', {})
        for model_id, (internal_id, _, filename, _) in CURRENT_MODELS.items():
            item = by_id.get(internal_id)
            meta = manifest.parent / f'{filename}.metadata.json'
            if item and item['version'] == version and item['status'] == 'active' and meta.is_file():
                items.append(public_model(item, model_id, json.loads(meta.read_text()), counts))
        break
    return {'items': items, 'total': len(items)}


@router.get('/models/runtime')
async def runtime(session: AsyncSession = Depends(session_dependency)):
    row = (await session.execute(text('SELECT * FROM ahr.ai_runtime_policy WHERE singleton'))).mappings().one()
    worker = await get_state().redis.get('ahr:ai-bundle:runtime')
    return {**dict(row), 'worker': json.loads(worker) if worker else None}


@router.post('/models/runtime')
async def update_runtime(request: RuntimePolicy, session: AsyncSession = Depends(session_dependency)):
    result = await session.execute(text('''UPDATE ahr.ai_runtime_policy SET enabled=:enabled,
        fusion_threshold=:threshold,revision=revision+1,updated_at=now()
        WHERE singleton AND revision=:revision RETURNING revision'''),
        {'enabled': request.enabled, 'threshold': request.fusion_threshold, 'revision': request.revision})
    if result.first() is None:
        raise HTTPException(409, 'Cáº¥u hÃ¬nh Ä‘Ã£ thay Ä‘á»•i. Táº£i láº¡i trÆ°á»›c khi lÆ°u.')
    await audit(session, 'ai-bundle', 'runtime-policy', 'Dashboard runtime control', request.model_dump())
    await session.commit()
    return await runtime(session)


@router.get('/models/{model_id}')
async def model_by_id(model_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    for item in (await models(session))['items']:
        if item['model_id'] == model_id:
            return item
    raise HTTPException(status_code=404, detail='Current model not found')


@router.get('/models/{model_id}/metrics')
async def model_metrics(model_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    model = await model_by_id(model_id, session)
    return {'model_id': model_id, 'items': [], 'artifact_metrics': model['artifact_metrics']}
