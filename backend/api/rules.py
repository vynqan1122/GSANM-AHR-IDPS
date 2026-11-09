from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import session_dependency
from backend.services import repository
from backend.api.automation import describe_rules
from backend.services.controls import RuleAction, audit, require_transition
from backend.main_state import get_state
from sqlalchemy import text

router = APIRouter()


@router.get("/rules")
async def rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    source: str | None = None,
    search: str | None = Query(None, max_length=200),
    session: AsyncSession = Depends(session_dependency),
) -> dict[str, object]:
    result = await repository.list_rules(session, page=page, page_size=page_size, status=status, source=source, search=search)
    await describe_rules(session, result['items'])
    return result


@router.get("/rules/{rule_id}")
async def rule_by_id(rule_id: str, session: AsyncSession = Depends(session_dependency)) -> dict[str, object]:
    rule = await repository.get_rule(session, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    await describe_rules(session, [rule])
    return rule


@router.get('/rules/{rule_id}/history')
async def rule_history(rule_id: str, session: AsyncSession = Depends(session_dependency)):
    result = await session.execute(text('''SELECT action_id,action,reason,details,created_at
        FROM ahr.dashboard_action_audit WHERE target=:target ORDER BY action_id DESC LIMIT 30'''),
        {'target': rule_id})
    return {'items': [dict(row._mapping) for row in result]}


@router.post('/rules/{rule_id}/actions')
async def rule_action(rule_id: str, request: RuleAction, session: AsyncSession = Depends(session_dependency)):
    # One action per rule across requests; always release the Redis lock on failure.
    lock = get_state().redis.lock(f'ahr:rule-action:{rule_id}', timeout=300, blocking_timeout=0)
    if not await lock.acquire(blocking=False):
        raise HTTPException(409, 'Quy tắc đang được xử lý. Vui lòng chờ.')
    try:
        rule = await repository.get_rule(session, rule_id)
        if rule is None:
            raise HTTPException(404, 'Không tìm thấy quy tắc.')
        next_status = require_transition(rule, request)
        if request.action == 'validate':
            if rule.get('generator') == 'genti-llm':
                raise HTTPException(409, 'Rule LLM cần native PCAP replay; bộ matcher event/template không kiểm định được rule này. Xem hướng dẫn GenTI triển khai.')
            await session.rollback()
            from rule_engine.validator import validate_rule
            try:
                validation = await validate_rule(rule_id)
            except Exception:
                await session.execute(text("UPDATE ahr.rules SET status=:status WHERE rule_id=:id AND status='validating'"),
                                      {'id': rule_id, 'status': rule['status']})
                await session.commit()
                raise HTTPException(503, 'Validation chưa hoàn tất; trạng thái cũ đã được giữ. Kiểm tra log rồi thử lại.')
            await audit(session, rule_id, 'validate', request.reason, validation)
        else:
            result = await session.execute(text('''UPDATE ahr.rules SET status=:status,
                disabled_reason=:reason,updated_at=now() WHERE rule_id=:id AND status=:old
                AND current_version=:version RETURNING rule_id'''),
                dict(id=rule_id, status=next_status, reason=request.reason if next_status in ('disabled','rejected') else None,
                     old=rule['status'], version=rule['current_version']))
            if result.first() is None:
                raise HTTPException(409, 'Quy tắc đã thay đổi; tải lại trước khi thao tác.')
            await audit(session, rule_id, request.action, request.reason,
                        {'from': rule['status'], 'to': next_status, 'version': rule['current_version'], 'sensor_deployed': False})
        await session.commit()
        return await repository.get_rule(session, rule_id)
    finally:
        await lock.release()
