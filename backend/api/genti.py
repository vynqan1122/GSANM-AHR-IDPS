"""GenTI synthesis uses selected raw evidence, never Fusion scores."""
import hashlib
import json
import os
import re

from fastapi import APIRouter, Depends, HTTPException
import httpx
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ai.genti.contract import decode_output, user_input
from backend.db.session import session_dependency
from backend.main_state import get_state
from backend.services import repository
from backend.services.controls import audit
from feature_engine.event_contract import sanitized_event

router = APIRouter()


def enabled():
    return os.getenv('GENTI_ENABLED', 'false').lower() == 'true'


async def worker(path, payload=None):
    if not enabled():
        raise HTTPException(409, 'Chưa chọn chế độ GenTI. Chạy cấu hình ai/compose.genti.yml.')
    url = os.getenv('GENTI_URL', 'http://genti:8090').rstrip('/') + path
    try:
        async with httpx.AsyncClient(timeout=630 if payload else 3, trust_env=False) as client:
            response = await (client.post(url, json=payload) if payload else client.get(url))
        if not response.is_success:
            detail = response.json().get('detail', 'GenTI worker error')
            raise HTTPException(response.status_code, str(detail)[:500])
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(503, 'Không kết nối được worker GenTI; kiểm tra model và log container.') from exc


@router.get('/genti/status')
async def status():
    if not enabled():
        return {'enabled': False, 'ready': False}
    try:
        return {**await worker('/status'), 'enabled': True}
    except HTTPException as exc:
        return {'enabled': True, 'ready': False, 'error': exc.detail}


class CandidateRequest(BaseModel):
    task: str = Field(min_length=10, max_length=2000)
    event_ids: list[str] = Field(min_length=1, max_length=5)
    benign_event_ids: list[str] = Field(min_length=1, max_length=5)
    cti_references: list[str] = Field(default_factory=list, max_length=5)
    mitre_attack: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode='after')
    def independent_examples(self):
        self.task = self.task.strip()
        if len(self.task) < 10:
            raise ValueError('Describe the detection intent in at least 10 characters')
        ids = self.event_ids + self.benign_event_ids
        if len(ids) != len(set(ids)) or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', x) for x in ids):
            raise ValueError('Event IDs must be distinct and valid')
        if any(len(x) > 500 or not re.match(r'^https?://[^\s]+$', x) for x in self.cti_references):
            raise ValueError('CTI references must be HTTP(S) source URLs')
        if any(not re.fullmatch(r'T\d{4}(?:\.\d{3})?', x) for x in self.mitre_attack):
            raise ValueError('Invalid ATT&CK technique ID')
        if self.mitre_attack and not self.cti_references:
            raise ValueError('Technique IDs need reviewed references')
        return self


def evidence(event):
    e = sanitized_event(event)
    # Provenance IDs are stored beside the prompt, not taught to the model.
    return {k: e.get(k) for k in ('source', 'event_type', 'protocol', 'http')}


async def save_candidate(session, request, payload, result):
    artifact = result.get('artifact_sha256', '')
    if not re.fullmatch(r'[0-9a-f]{64}', artifact):
        raise HTTPException(502, 'Worker không trả model hash hợp lệ.')
    try:
        output = decode_output(json.dumps(result['output']), payload['cti'])
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(502, 'Đầu ra LLM không đạt hợp đồng Candidate.') from exc
    prompt_digest = hashlib.sha256(user_input(payload).encode()).hexdigest()
    identity = hashlib.sha256((artifact + prompt_digest).encode()).hexdigest()
    rule_id = 'genti-' + identity[:24]
    # Serializes the short registry write; inference takes place before this transaction.
    await session.execute(text('SELECT pg_advisory_xact_lock(100029)'))
    existing = await repository.get_rule(session, rule_id)
    if existing:
        return existing
    sid = 10000000 + int(identity[:8], 16) % 1000000
    for _ in range(100):
        collision = await session.scalar(text("SELECT EXISTS(SELECT 1 FROM ahr.rule_versions WHERE content ~ :sid)"),
                                         {'sid': rf'\msid:\s*{sid}\s*;'})
        if not collision:
            break
        sid += 1
    else:
        raise HTTPException(409, 'Không cấp được SID; thử lại sau khi kiểm registry.')
    content = re.sub(r'\bsid:\s*\d+\s*;', f'sid:{sid};', output['rule'])
    digest = hashlib.sha256(content.encode()).hexdigest()
    model_versions = {'genti': artifact}
    pattern = {'type': 'llm', 'support_kind': 'selected_evidence_count', 'example_event_ids': request.event_ids,
               'benign_event_ids': request.benign_event_ids, 'prompt_sha256': prompt_digest,
               'summary': output['summary'], 'cti': output['mitre_attack']}
    params = dict(id=rule_id, name='GenTI · ' + request.task[:100], description=output['summary'],
                  pattern=json.dumps(pattern), models=json.dumps(model_versions), support=len(request.event_ids))
    await session.execute(text('''INSERT INTO ahr.rules
        (rule_id,engine,name,description,status,source,created_by,origin,generator,pattern,support,confidence,model_versions)
        VALUES (:id,'suricata',:name,:description,'candidate','generated','genti-llm','genti_llm','genti-llm',
                CAST(:pattern AS jsonb),:support,NULL,CAST(:models AS jsonb))'''), params)
    metadata = {'task': request.task, 'input': payload, 'model_versions': model_versions,
                'generation_seconds': result.get('seconds'),
                'prompt_sha256': prompt_digest, 'sensor_deployed': False,
                'verification': 'native PCAP replay required; structural event matcher is not applicable'}
    await session.execute(text('''INSERT INTO ahr.rule_versions
        (rule_id,version,content,content_sha256,metadata,created_by)
        VALUES (:id,1,:content,:digest,CAST(:metadata AS jsonb),'genti-llm')'''),
        dict(id=rule_id, content=content, digest=digest, metadata=json.dumps(metadata)))
    await audit(session, rule_id, 'genti-generate', request.task[:500],
                {'model_sha256': artifact, 'prompt_sha256': prompt_digest, 'sensor_deployed': False})
    return await repository.get_rule(session, rule_id)


@router.post('/genti/generate')
async def generate(request: CandidateRequest, session: AsyncSession = Depends(session_dependency)):
    if not enabled():
        raise HTTPException(409, 'Chưa chọn chế độ GenTI.')
    lock = get_state().redis.lock('ahr:genti-generation', timeout=690, blocking_timeout=0)
    if not await lock.acquire(blocking=False):
        raise HTTPException(429, 'GenTI đang sinh một Candidate khác.')
    try:
        return await synthesize(request, session)
    finally:
        await lock.release()


async def synthesize(request, session):
    examples = []
    for event_id in request.event_ids + request.benign_event_ids:
        row = await repository.get_event(session, event_id)
        if row is None:
            raise HTTPException(404, f'Không tìm thấy event {event_id}')
        examples.append(evidence(row))
    await session.rollback()
    n = len(request.event_ids)
    if any(not any((e.get('http') or {}).get('uri') for e in group) for group in (examples[:n], examples[n:])):
        raise HTTPException(422, 'Chọn ít nhất một event có HTTP URI trong mỗi nhóm evidence và benign.')
    payload = {'task': request.task, 'evidence': examples[:n], 'benign_examples': examples[n:],
               'cti': {'references': request.cti_references, 'mitre_attack': request.mitre_attack}}
    result = await worker('/generate', payload)
    rule = await save_candidate(session, request, payload, result)
    await session.commit()
    return rule
