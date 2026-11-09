"""Native receipt gates and HTTP lab enforcement, separate from registry-only actions."""
import hashlib
import hmac
import json
import os
import time
import uuid
from urllib.parse import urlsplit
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ai.genti.automation_contract import PROFILE, PATH, TASK, supported, matches, replay_pass, shadow_pass
from ai.genti.evidence_review import decode_review, shortlist
from backend.api.genti import CandidateRequest, evidence, synthesize, worker, status as model_status
from backend.db.session import session_dependency
from backend.main_state import get_state
from backend.services import repository
from backend.services.controls import audit

router = APIRouter()
POLICY_KEY = 'ahr:automation:policy'


async def policy():
    value = await get_state().redis.get(POLICY_KEY)
    return json.loads(value) if value else {'enabled': True, 'revision': 1}


def internal(request):
    key = os.getenv('AHR_AUTOMATION_KEY', '')
    if not key or not hmac.compare_digest(request.headers.get('X-AHR-Worker', ''), key):
        raise HTTPException(403, 'Worker credential required')


async def authorized_rule(session, rule_id):
    rule = await repository.get_rule(session, rule_id)
    state = await model_status()
    artifact = (state.get('model') or {}).get('artifact_sha256')
    if not (rule and rule['generator'] == 'genti-llm' and supported(rule['content'])
            and state.get('ready') and state.get('self_test', {}).get('status') == 'passed'
            and rule['model_versions'].get('genti') == artifact):
        raise HTTPException(409, 'Rule/model/profile not eligible for automatic deployment')
    return rule


def native_current(rule):
    metrics = rule.get('shadow_metrics') or {}
    return (rule.get('validation_status') == 'passed'
            and rule.get('validation_rule_version') == rule['current_version']
            and metrics.get('rule_sha256') == hashlib.sha256((rule.get('content') or '').encode()).hexdigest()
            and metrics.get('artifact_sha256') == (rule.get('model_versions') or {}).get('genti')
            and replay_pass({'syntax': {'ok': rule.get('validation_syntax_valid')},
                             'replay': rule.get('validation_replay_metrics'),
                             'gateway_parity': metrics.get('gateway_parity')}))


def rule_progress(rule, *, enabled, worker_fresh, artifact, failure=None, counts=(0, 0), now=None):
    now = time.time() if now is None else now
    metrics = rule.get('shadow_metrics') or {}
    yes, no = counts
    elapsed = max(0, int(now - metrics.get('shadow_started', now)))
    profile_ok = supported(rule.get('content') or '')
    model_current = bool(artifact and (rule.get('model_versions') or {}).get('genti') == artifact)
    native_ok = native_current(rule)
    remaining = max(0, int(metrics.get('active_until', 0) - now))
    enforcing = (rule['status'] == 'active' and enabled and worker_fresh and profile_ok
                 and model_current and native_ok and remaining > 0
                 and metrics.get('deployment') == 'nginx-http-auth-request')
    stage, label, reason = 'queued', 'Chờ kiểm định native', 'Worker tự kiểm tra Suricata và replay; đạt mới vào Shadow.'
    if rule['status'] in ('disabled', 'rejected'):
        stage, label, reason = 'stopped', 'Đã dừng', rule.get('disabled_reason') or 'Quy tắc không tham gia tự động triển khai.'
    elif not profile_ok:
        stage, label, reason = 'unsupported', 'Giữ Candidate · ngoài phạm vi', 'Chỉ hồ sơ GET XSS tại /vulnerabilities/xss_r/ đã có kiểm chứng tương đương gateway. Quy tắc này chưa được tự động chặn.'
    elif not model_current:
        stage, label, reason = 'model_mismatch', 'Chờ đúng model', 'Chưa có heartbeat của model hiện tại khớp với model đã sinh quy tắc.'
    elif failure and rule['status'] == 'candidate':
        stage, label, reason = 'native_failed', 'Giữ Candidate · kiểm định lỗi', 'Kiểm định native hoặc đối chiếu gateway không đạt. Xem kết quả lỗi; hệ thống không tự bỏ qua kiểm định.'
    elif not enabled:
        stage, label, reason = 'paused', 'Tự động đang tạm dừng', 'Khôi phục tại Mô hình AI để tiếp tục; gateway hiện không áp dụng chặn tự động.'
    elif not worker_fresh:
        stage, label, reason = 'worker_unavailable', 'Chờ worker phục hồi', 'Worker chưa sẵn sàng. Không chuyển trạng thái; đường HTTP được bảo vệ có thể trả lỗi tạm thời.'
    elif rule['status'] in ('shadow', 'active') and not native_ok:
        stage, label, reason = 'stale_validation', 'Giữ lại · kiểm định không còn khớp', 'Nội dung, model hoặc phiên bản khác với biên nhận native; cần kiểm định lại trước khi thực thi.'
    elif rule['status'] == 'shadow':
        ready = shadow_pass(elapsed, yes, no)
        stage, label, reason = ('ready', 'Đủ điều kiện → tự Active', 'Worker sẽ tự chuyển trong chu kỳ kế tiếp.') if ready else ('shadow', 'Shadow · đang quan sát', 'Tự Active khi đủ cả thời gian và các lượt HTTP khác nhau; Shadow không tự chặn.')
    elif rule['status'] == 'active':
        stage, label, reason = ('active', 'Đang chặn tại HTTP gateway', 'Request khớp được chặn trước DVWA; request hợp lệ tiếp tục đi qua.') if enforcing else ('expired', 'Hết thời hạn thực thi', 'Worker sẽ tự gỡ Active khi hết thời hạn một giờ; hiện không còn chặn bằng quy tắc này.')
    return {'stage': stage, 'label': label, 'reason': reason, 'profile_supported': profile_ok,
            'model_current': model_current, 'native_passed': native_ok, 'enabled': enabled,
            'worker_fresh': worker_fresh, 'enforcing': enforcing, 'lease_remaining_seconds': remaining,
            'shadow': {'elapsed_seconds': elapsed, 'matches': yes, 'nonmatches': no, 'unique': yes + no,
                       'ready': shadow_pass(elapsed, yes, no)}, 'native_failure': failure}


async def describe_rules(session, rules):
    genti = [r for r in rules if r.get('generator') == 'genti-llm']
    if not genti:
        return rules
    redis = get_state().redis
    heartbeat = await redis.get('ahr:automation:heartbeat')
    beat = json.loads(heartbeat) if heartbeat else {}
    fresh = bool(beat and time.time() - beat['time'] < 30)
    enabled = (await policy())['enabled']
    failures = await session.execute(text("""SELECT DISTINCT ON (target) target,details,reason,created_at
        FROM ahr.dashboard_action_audit WHERE target=ANY(:ids) AND action='auto-native-failed'
        ORDER BY target,action_id DESC"""), {'ids': [r['rule_id'] for r in genti]})
    failed = {r.target: dict(r._mapping) for r in failures}
    pipe = redis.pipeline()
    for rule in genti:
        for role in ('yes', 'no'):
            pipe.scard('ahr:shadow:' + rule['rule_id'] + ':' + role)
    counters = await pipe.execute()
    for index, rule in enumerate(genti):
        failure = failed.get(rule['rule_id'])
        if failure and (failure['details'].get('rule_version') != rule['current_version']
                        or failure['details'].get('rule_sha256') != hashlib.sha256((rule.get('content') or '').encode()).hexdigest()):
            failure = None
        rule['automation'] = rule_progress(rule, enabled=enabled, worker_fresh=fresh,
            artifact=beat.get('artifact_sha256'), failure=failure, counts=counters[index*2:index*2+2])
    return rules


@router.get('/automation/status')
async def automation_status(session: AsyncSession = Depends(session_dependency)):
    redis = get_state().redis
    heartbeat = await redis.get('ahr:automation:heartbeat')
    alerts = await session.execute(text("""SELECT action_id,target,action,reason,details,created_at
        FROM ahr.dashboard_action_audit WHERE action LIKE 'auto-%' OR action='ips-block'
        ORDER BY action_id DESC LIMIT 20"""))
    rules = await session.execute(text("""SELECT rule_id,status,current_version,shadow_metrics FROM ahr.rules
        WHERE shadow_metrics->>'profile'=:profile ORDER BY updated_at DESC LIMIT 20"""), {'profile': PROFILE})
    selection = await redis.get('ahr:automation:selection')
    return {'policy': await policy(), 'profile': PROFILE, 'scope': 'GET /vulnerabilities/xss_r/ · HTTP gateway IPS',
            'worker': json.loads(heartbeat) if heartbeat else None,
            'worker_fresh': bool(heartbeat and time.time() - json.loads(heartbeat)['time'] < 30),
            'rules': [dict(r._mapping) for r in rules], 'alerts': [dict(r._mapping) for r in alerts],
            'selection': json.loads(selection) if selection else None,
            'thresholds': {'native_attack': 50, 'native_benign': 50, 'max_fp_fn': 0,
                           'shadow_seconds': 60, 'shadow_unique': 20, 'shadow_matches': 3, 'shadow_nonmatches': 10,
                           'active_lease_seconds': 3600},
            'limits': ['Synthetic controls are not an independent benchmark',
                       'No network-wide NFQUEUE/TLS/body enforcement; unsupported profiles stay Candidate']}


@router.get('/automation/results')
async def automatic_results(session: AsyncSession = Depends(session_dependency)):
    state = await model_status()
    artifact = (state.get('model') or {}).get('artifact_sha256')
    if not artifact:
        return {'items': [], 'counts': {}, 'artifact_sha256': None}
    result = await session.execute(text("""SELECT r.rule_id FROM ahr.rules r
        WHERE r.generator='genti-llm' AND r.model_versions->>'genti'=:artifact
        ORDER BY r.created_at DESC LIMIT 6"""), {'artifact': artifact})
    items = []
    for row in result:
        rule = await repository.get_rule(session, row.rule_id)
        if rule:
            items.append({**rule, 'automatic_supported': supported(rule['content'])})
    stats = await session.execute(text("""SELECT status,count(*) AS count FROM ahr.rules
        WHERE generator='genti-llm' AND model_versions->>'genti'=:artifact GROUP BY status"""), {'artifact': artifact})
    return {'items': await describe_rules(session, items), 'counts': {row.status: row._mapping['count'] for row in stats}, 'artifact_sha256': artifact}


class PolicyChange(BaseModel):
    enabled: bool
    revision: int


@router.post('/automation/policy')
async def set_policy(change: PolicyChange, session: AsyncSession = Depends(session_dependency)):
    lock = get_state().redis.lock('ahr:automation:policy-lock', timeout=10, blocking_timeout=0)
    if not await lock.acquire(blocking=False):
        raise HTTPException(409, 'Policy busy')
    try:
        current = await policy()
        if current['revision'] != change.revision:
            raise HTTPException(409, 'Reload current policy')
        value = {'enabled': change.enabled, 'revision': change.revision + 1}
        await get_state().redis.set(POLICY_KEY, json.dumps(value))
        await audit(session, PROFILE, 'auto-policy', 'User selected automatic lab HTTP protection', value)
        await session.commit()
        return value
    finally:
        await lock.release()


@router.post('/internal/automation/heartbeat')
async def heartbeat(request: Request):
    internal(request)
    state = await model_status()
    if not (state.get('ready') and state.get('self_test', {}).get('status') == 'passed'):
        await get_state().redis.delete('ahr:automation:heartbeat')
        raise HTTPException(503, 'Model boot checks not passed')
    await get_state().redis.set('ahr:automation:heartbeat', json.dumps({'time': time.time(), 'status': 'running',
        'artifact_sha256': state['model']['artifact_sha256']}), ex=15)
    return {'ok': True}


@router.get('/internal/automation/job')
async def job(request: Request, session: AsyncSession = Depends(session_dependency)):
    internal(request)
    if not (await policy())['enabled']:
        return {'job': None}
    state = await model_status()
    if not (state.get('ready') and state.get('self_test', {}).get('status') == 'passed'):
        return {'job': None}
    artifact = state['model']['artifact_sha256']
    rows = await session.execute(text("""SELECT r.rule_id,rv.content,r.current_version,rv.content_sha256
        FROM ahr.rules r JOIN ahr.rule_versions rv ON rv.rule_id=r.rule_id AND rv.version=r.current_version
        WHERE r.generator='genti-llm' AND r.status='candidate' AND r.model_versions->>'genti'=:artifact
        AND NOT EXISTS (SELECT 1 FROM ahr.dashboard_action_audit a WHERE a.target=r.rule_id
            AND a.action='auto-native-failed' AND a.details->>'rule_version'=r.current_version::text
            AND a.details->>'rule_sha256'=rv.content_sha256) ORDER BY r.created_at DESC"""), {'artifact': artifact})
    for row in rows:
        item = dict(row._mapping)
        if supported(item['content']):
            return {'job': {**item, 'artifact_sha256': artifact}}
        held = await session.scalar(text("SELECT EXISTS(SELECT 1 FROM ahr.dashboard_action_audit WHERE target=:id AND action='auto-held')"), {'id': item['rule_id']})
        if not held:
            await audit(session, item['rule_id'], 'auto-held', 'Outside audited lab HTTP profile; kept Candidate', {})
    await session.commit()
    return {'job': None}


@router.post('/internal/automation/generate')
async def auto_generate(request: Request, session: AsyncSession = Depends(session_dependency)):
    internal(request)
    if not (await policy())['enabled']:
        return {'generated': False}
    state = await model_status()
    if not (state.get('ready') and state.get('self_test', {}).get('status') == 'passed'):
        return {'generated': False, 'reason': 'Waiting for current model boot checks'}
    artifact = state['model']['artifact_sha256']
    rows = await session.execute(text("""SELECT event_id,source,event_type,protocol,http FROM ahr.events
        WHERE source='nginx' AND http->>'method'='GET' AND timestamp > now()-interval '30 minutes'
        AND http->>'uri' LIKE '/vulnerabilities/%' ORDER BY timestamp DESC LIMIT 300"""))
    pool = shortlist([{'event_id': row.event_id, 'input': evidence(dict(row._mapping))} for row in rows])
    await session.rollback()
    redis = get_state().redis
    async def progress(status, **details):
        value = {'status': status, 'artifact_sha256': artifact, 'updated_at': datetime.now(timezone.utc).isoformat(),
                 'human_approved': False, **details}
        await redis.set('ahr:automation:selection', json.dumps(value))
        return value
    if len(pool) < 2:
        await progress('waiting', reason='Đang chờ các HTTP request DVWA mới; API, dashboard và tài nguyên tĩnh được loại khỏi đầu vào.')
        return {'generated': False}
    fingerprint = hashlib.sha256(json.dumps([artifact, [r['input'] for r in pool]], sort_keys=True).encode()).hexdigest()
    previous = await redis.get('ahr:automation:selection')
    if previous and json.loads(previous).get('fingerprint') == fingerprint and json.loads(previous)['status'] in ('generated','insufficient'):
        return {'generated': False, 'reason': 'Evidence already processed'}
    lock = redis.lock('ahr:genti-generation', timeout=1320, blocking_timeout=0)
    if not await lock.acquire(blocking=False):
        return {'generated': False, 'reason': 'Model busy'}
    if not await redis.set('ahr:automation:generation-cooldown', '1', nx=True, ex=600):
        await lock.release()
        return {'generated': False, 'reason': 'cooldown'}
    try:
        await progress('reviewing', fingerprint=fingerprint, observations=pool, reason='Model fine-tune đang chọn evidence và phản ví dụ.')
        answer = await worker('/review', {'events': [r['input'] for r in pool]})
        if answer.get('artifact_sha256') != artifact:
            raise HTTPException(409, 'Model changed during evidence review')
        reviewed = decode_review(json.dumps(answer['output']), len(pool))
        selected = [{**r, 'role': 'evidence' if i in reviewed['evidence'] else 'benign' if i in reviewed['benign'] else 'uncertain'} for i, r in enumerate(pool)]
        review = {'fingerprint': fingerprint, 'observations': selected, 'task': reviewed['task'],
                  'reason': reviewed['reason'], 'review_seconds': answer['seconds'], 'reviewer': 'installed-fine-tuned-llm'}
        if not reviewed['evidence'] or not reviewed['benign']:
            await progress('insufficient', **review)
            return {'generated': False, 'reason': 'AI could not confirm both roles'}
        paths = {urlsplit(pool[i]['input']['http']['uri']).path for i in reviewed['evidence'] + reviewed['benign']}
        if len(paths) != 1:
            await progress('insufficient', **{**review, 'reason': 'AI chọn hai nhóm khác endpoint; giữ lại để chờ bằng chứng phù hợp.'})
            return {'generated': False, 'reason': 'Evidence and benign must share an endpoint'}
        intent = reviewed['task']
        if all(matches('GET', pool[i]['input']['http']['uri']) for i in reviewed['evidence']):
            intent = TASK
        await progress('generating', **review)
        rule = await synthesize(CandidateRequest(task=intent,
            event_ids=[pool[i]['event_id'] for i in reviewed['evidence']],
            benign_event_ids=[pool[i]['event_id'] for i in reviewed['benign']]), session)
        if rule['model_versions']['genti'] != artifact:
            raise HTTPException(409, 'Model changed between review and synthesis')
        review.update(artifact_sha256=artifact, human_approved=False)
        await session.execute(text("""UPDATE ahr.rule_versions SET metadata=metadata || CAST(:m AS jsonb)
            WHERE rule_id=:id AND version=:version"""), {'id': rule['rule_id'], 'version': rule['current_version'],
            'm': json.dumps({'automatic_selection': review})})
        await audit(session, rule['rule_id'], 'auto-generated', 'AI tự chọn mẫu, nhận định và sinh Candidate bằng model chính', review)
        await session.commit()
        await progress('generated', **{k:v for k,v in review.items() if k not in ('artifact_sha256','human_approved')}, rule_id=rule['rule_id'])
    except HTTPException as exc:
        await redis.expire('ahr:automation:generation-cooldown', 30)
        await progress('failed', fingerprint=fingerprint, reason=str(exc.detail)[:500])
        await audit(session, PROFILE, 'auto-generation-failed', 'Generation unavailable; automatic retry in 30 seconds',
                    {'status_code': exc.status_code, 'detail': str(exc.detail)[:300]})
        await session.commit()
        raise
    finally:
        await lock.release()
    return {'generated': True, 'rule_id': rule['rule_id']}


@router.post('/internal/automation/receipt')
async def receipt(request: Request, session: AsyncSession = Depends(session_dependency)):
    internal(request)
    value = await request.json()
    rule = await authorized_rule(session, value['rule_id'])
    digest = hashlib.sha256(rule['content'].encode()).hexdigest()
    if (rule['status'] != 'candidate' or value['rule_version'] != rule['current_version']
            or value['rule_sha256'] != digest or value['artifact_sha256'] != rule['model_versions']['genti']):
        raise HTTPException(409, 'Stale receipt')
    if not (await policy())['enabled']:
        raise HTTPException(409, 'Automation disabled')
    verdict = value['verdict']
    if not replay_pass(verdict):
        await audit(session, rule['rule_id'], 'auto-native-failed', 'Native or parity controls failed; kept Candidate', value)
        await session.commit()
        return {'status': 'candidate'}
    metrics = {**verdict['replay'], 'profile': PROFILE, 'rule_sha256': digest, 'native_receipt': value['receipt_path'],
               'artifact_sha256': value['artifact_sha256'], 'shadow_started': time.time(), 'gateway_parity': True}
    await session.execute(text("""INSERT INTO ahr.rule_validation_runs
        (validation_id,rule_id,rule_version,status,syntax_valid,replay_metrics,performance_metrics,completed_at)
        VALUES (:id,:rule,:version,'passed',true,CAST(:metrics AS jsonb),CAST(:perf AS jsonb),now())"""),
        {'id': 'auto-'+uuid.uuid4().hex, 'rule': rule['rule_id'], 'version': rule['current_version'],
         'metrics': json.dumps(verdict['replay']), 'perf': json.dumps({'engine': value['engine_version'], 'rule_sha256': digest})})
    updated = await session.execute(text("""UPDATE ahr.rules SET status='shadow',shadow_metrics=CAST(:metrics AS jsonb),
        promotion_requires_approval=false,updated_at=now() WHERE rule_id=:id AND status='candidate'
        AND current_version=:version RETURNING rule_id"""),
        {'id': rule['rule_id'], 'version': rule['current_version'], 'metrics': json.dumps(metrics)})
    if updated.first() is None:
        raise HTTPException(409, 'Rule changed during native validation')
    await audit(session, rule['rule_id'], 'auto-shadow', 'Native 50 attack + 50 benign and gateway parity passed', value)
    await session.commit()
    return {'status': 'shadow'}


@router.post('/internal/automation/advance')
async def advance(request: Request, session: AsyncSession = Depends(session_dependency)):
    internal(request)
    if not (await policy())['enabled']:
        return {'ok': True}
    rows = await session.execute(text("""SELECT rule_id,status,shadow_metrics FROM ahr.rules
        WHERE shadow_metrics->>'profile'=:p AND status IN ('shadow','active') FOR UPDATE"""), {'p': PROFILE})
    for row in rows:
        metrics = dict(row.shadow_metrics)
        if row.status == 'active' and time.time() >= metrics.get('active_until', 0):
            await session.execute(text("UPDATE ahr.rules SET status='disabled',disabled_reason='Automatic lab lease expired',updated_at=now() WHERE rule_id=:id"), {'id': row.rule_id})
            await audit(session, row.rule_id, 'auto-expired', 'One-hour lab lease expired; enforcement removed', {})
        elif row.status == 'shadow':
            rule = await authorized_rule(session, row.rule_id)
            if not native_current(rule):
                continue
            redis = get_state().redis
            yes = await redis.scard('ahr:shadow:'+row.rule_id+':yes')
            no = await redis.scard('ahr:shadow:'+row.rule_id+':no')
            if shadow_pass(time.time()-metrics['shadow_started'], yes, no):
                metrics.update(shadow_matches=yes, shadow_nonmatches=no, active_until=time.time()+3600,
                               deployment='nginx-http-auth-request', sensor_deployed=False)
                await session.execute(text("UPDATE ahr.rules SET status='active',shadow_metrics=CAST(:m AS jsonb),updated_at=now() WHERE rule_id=:id AND status='shadow'"),
                                      {'id': row.rule_id, 'm': json.dumps(metrics)})
                await audit(session, row.rule_id, 'auto-active', 'Native controls + live Shadow exposure passed; lab gateway enforcement enabled', metrics)
    await session.commit()
    return {'ok': True}


@router.get('/internal/ips/check')
async def ips_check(request: Request, session: AsyncSession = Depends(session_dependency)):
    # Nginx overwrites these headers; /api/internal/ is inaccessible through the public gateway.
    if not (await policy())['enabled']:
        return Response(status_code=204)
    method = request.headers.get('X-Original-Method', '')
    uri = request.headers.get('X-Original-URI', '')
    if not uri.startswith('/vulnerabilities/xss_r/'):
        return Response(status_code=204)
    redis = get_state().redis
    worker = await redis.get('ahr:automation:heartbeat')
    if not worker:
        raise HTTPException(503, 'IPS checker unavailable')
    artifact = json.loads(worker)['artifact_sha256']
    rows = await session.execute(text("""SELECT r.rule_id,r.status,r.current_version,r.shadow_metrics,rv.content,
        rv.content_sha256 FROM ahr.rules r JOIN ahr.rule_versions rv ON rv.rule_id=r.rule_id AND rv.version=r.current_version
        WHERE r.status IN ('shadow','active') AND r.shadow_metrics->>'profile'=:p"""), {'p': PROFILE})
    rows = list(rows)
    # Observe every Shadow before any Active rule returns a blocking decision.
    for row in rows:
        metrics = row.shadow_metrics
        digest = hashlib.sha256(row.content.encode()).hexdigest()
        if (not supported(row.content) or metrics.get('rule_sha256') != digest or row.content_sha256 != digest
                or metrics.get('artifact_sha256') != artifact):
            raise HTTPException(503, 'Deployed rule changed; refusing stale validation')
        hit = matches(method, uri)
        if row.status == 'shadow':
            key = 'ahr:shadow:'+row.rule_id+(':'+'yes' if hit else ':'+'no')
            await redis.sadd(key, hashlib.sha256((method+uri).encode()).hexdigest())
            await redis.expire(key, 7200)
    for row in rows:
        metrics = row.shadow_metrics
        if row.status == 'active' and matches(method, uri) and time.time() < metrics.get('active_until', 0):
            digest = hashlib.sha256(row.content.encode()).hexdigest()
            response_id = 'ips-'+uuid.uuid4().hex
            details = {'rule_id': row.rule_id, 'rule_version': row.current_version, 'rule_sha256': digest,
                       'method': method, 'uri': uri[:2000], 'applied': True, 'enforcement': 'HTTP 403 before DVWA'}
            await session.execute(text("""INSERT INTO ahr.responses
                (response_id,action_type,action,response_level,status,target,parameters,requested_by,reason,completed_at)
                VALUES (:id,'http_block','http_block','level_3','completed',:target,CAST(:details AS jsonb),
                        'genti-automation','Validated Active rule blocked request before upstream',now())"""),
                {'id': response_id, 'target': request.headers.get('X-Client-IP', ''), 'details': json.dumps(details)})
            await audit(session, row.rule_id, 'ips-block', 'IPS blocked HTTP request before DVWA', details)
            await session.commit()
            return Response(status_code=403, headers={'X-AHR-Rule': row.rule_id})
    return Response(status_code=204)
