"""Expose measured test results of the main bundle; never synthesize benchmark metrics."""
import hashlib
import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from backend.db.session import session_dependency
from backend.main_state import get_state
from .models import models

router = APIRouter()
NAMES = {'rule_only': 'Rule-only', 'network': 'Network AI', 'log': 'Log AI',
         'graph': 'Graph AI', 'weighted_hybrid': 'Weighted hybrid', 'fusion_oof': 'Fusion AI',
         'logistic_regression': 'Logistic regression', 'random_forest': 'Random forest'}


def measured_results(manifest_path: Path, version: str) -> list[dict]:
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest()[:16] != version:
        raise ValueError('Manifest does not match the running AI')
    manifest = json.loads(raw)
    path = manifest_path.parent / 'comparison.json'
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != manifest['files']['comparison.json']:
        raise ValueError('Evaluation checksum mismatch')
    rows = []
    for item in json.loads(content):
        if sum(item[k] for k in ('tp', 'fp', 'tn', 'fn')) != manifest['counts']['test']:
            raise ValueError('Evaluation sample count mismatch')
        rows.append({'experiment_id': item['model'], 'name': NAMES.get(item['model'], item['model']),
                     'status': 'completed', 'dataset_split': 'test', 'results_path': str(path),
                     'model_config': {'artifact_hash': version, 'split_counts': manifest['counts']},
                     'metrics': {k: v for k, v in item.items() if k != 'model'}})
    return rows


@router.get('/experiments')
async def experiments(session: AsyncSession = Depends(session_dependency)) -> dict:
    current = (await models(session))['items']
    if not current:
        return {'items': [], 'source': 'Current bundle unavailable'}
    version = current[0]['version']
    root = Path(get_state().settings.experiments_dir) / 'bundles'
    for manifest in sorted(root.glob('*/manifest.json')):
        if hashlib.sha256(manifest.read_bytes()).hexdigest()[:16] == version:
            try:
                return {'items': measured_results(manifest, version), 'source': 'Measured held-out test', 'artifact_hash': version}
            except (ValueError, KeyError, OSError) as exc:
                raise HTTPException(503, 'Current evaluation evidence is invalid or unavailable') from exc
    raise HTTPException(503, 'Current evaluation evidence unavailable')


@router.post('/experiments/run')
async def run_experiments() -> dict:
    raise HTTPException(501, 'Chưa có runner ablation đo thực tế. Trang chỉ đọc kết quả test đã xác minh của AI chính; không tạo metric ước lượng.')


@router.get('/experiments/{experiment_id}')
async def experiment_by_id(experiment_id: str, session: AsyncSession = Depends(session_dependency)) -> dict:
    for item in (await experiments(session))['items']:
        if item['experiment_id'] == experiment_id:
            return item
    raise HTTPException(404, 'Current evaluation not found')
