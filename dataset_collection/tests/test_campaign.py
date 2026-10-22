import asyncio
from types import SimpleNamespace

import pytest

from dataset_collection.campaign import TokenParser, local_target, login, make_plan


def test_campaign_plan_has_no_duplicate_markers_and_realistic_labels():
    plan = make_plan(rounds=3, campaign_id='test')
    assert len(plan) == 24
    assert len({row['scenario_id'] for row in plan}) == 24
    assert all(row['simulated_ip'].startswith('192.0.2.') for row in plan)
    cmd = next(row for row in plan if row['attack_type'] == 'command_injection')
    assert cmd['method'] == 'POST'
    assert any(row['label'] == 'benign' and '/vulnerabilities/' in row['path'] for row in plan)


def test_external_target_rejected():
    for url in ('https://example.com', 'http://10.1.1.1', 'http://user:pass@nginx', 'http://nginx/other'):
        with pytest.raises(ValueError):
            local_target(url)


def test_csrf_handles_attributes_in_any_order():
    parser = TokenParser()
    parser.feed('<input value="token123" type="hidden" name="user_token">')
    assert parser.token == 'token123'


def test_login_rejects_return_to_login_page():
    class Client:
        async def get(self, path):
            return SimpleNamespace(text='<input name="user_token" value="abc">', raise_for_status=lambda: None)
        async def post(self, path, **kwargs):
            return SimpleNamespace(text='Login failed', url=SimpleNamespace(path='/login.php'), raise_for_status=lambda: None)
    with pytest.raises(RuntimeError, match='login failed'):
        asyncio.run(login(Client()))
