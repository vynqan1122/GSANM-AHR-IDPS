"""Persistent dashboard controls; sensor deployment stays outside registry actions."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text


class RuleAction(BaseModel):
    action: Literal['validate', 'activate', 'reject', 'disable']
    expected_status: str
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)
    approved: bool = False

    @field_validator('reason')
    @classmethod
    def meaningful_reason(cls, value: str) -> str:
        if len(value.strip()) < 3:
            raise ValueError('Nhập lý do có ít nhất 3 ký tự.')
        return value.strip()


class RuntimePolicy(BaseModel):
    enabled: bool
    fusion_threshold: float = Field(ge=0.05, le=0.95, allow_inf_nan=False)
    revision: int = Field(ge=1)


def require_transition(rule: dict, request: RuleAction) -> str:
    if rule.get('origin') == 'sensor_baseline':
        raise HTTPException(409, 'Luật nền đang nạp trực tiếp tại cảm biến Suricata. Cần sửa cấu hình, kiểm định và nạp lại cảm biến; thao tác registry không bật/tắt được luật này.')
    if rule['status'] != request.expected_status or rule['current_version'] != request.expected_version:
        raise HTTPException(409, 'Quy tắc đã thay đổi. Tải lại trước khi thao tác.')
    allowed = {
        'validate': {'candidate', 'rejected', 'disabled'},
        'activate': {'shadow'},
        'reject': {'candidate', 'shadow'},
        'disable': {'active', 'shadow'},
    }
    if rule['status'] not in allowed[request.action]:
        raise HTTPException(409, 'Thao tác không phù hợp với trạng thái hiện tại.')
    if request.action == 'activate':
        if rule.get('generator') == 'genti-llm':
            raise HTTPException(409, 'GenTI tự Active sau native và Shadow; không thể dùng thao tác registry để bỏ qua các điều kiện này.')
        if not request.approved:
            raise HTTPException(422, 'Cần xác nhận phê duyệt thủ công.')
        if not (rule.get('validation_status') == 'passed' and rule.get('validation_syntax_valid')
                and rule.get('validation_rule_version') == rule['current_version']):
            raise HTTPException(409, 'Phiên bản hiện tại chưa qua validation.')
    return {'validate': 'validating', 'activate': 'active', 'reject': 'rejected', 'disable': 'disabled'}[request.action]


async def audit(session, target: str, action: str, reason: str, details: dict) -> None:
    await session.execute(text('''INSERT INTO ahr.dashboard_action_audit(target,action,reason,details)
        VALUES (:target,:action,:reason,CAST(:details AS jsonb))'''),
        dict(target=target, action=action, reason=reason, details=json.dumps(details)))
