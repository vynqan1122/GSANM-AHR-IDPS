"""Authenticated DVWA dataset campaign. Default mode prints a plan only.

Execute inside the backend container, which already has database credentials.
Simulated IPs are experimental client metadata, never network source addresses.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import uuid
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


class TokenParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == 'input' and fields.get('name') == 'user_token':
            self.token = fields.get('value')


def local_target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != 'http' or parsed.hostname not in {'nginx', 'localhost', '127.0.0.1', '::1'}:
        raise ValueError('Campaign target must be the local DVWA lab or nginx service')
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('Use a plain lab origin without credentials, path, or query')
    return value.rstrip('/')


def make_plan(rounds=2, seed=42, campaign_id=None):
    rng = random.Random(seed)
    campaign_id = campaign_id or 'dvwa_' + uuid.uuid4().hex[:12]
    tasks = []
    for round_id in range(rounds):
        cases = [
            ('benign', 'GET', '/vulnerabilities/sqli/', {'id': str(rng.randint(1, 5)), 'Submit': 'Submit'}),
            ('benign', 'GET', '/instructions.php', {}),
            ('sql_injection', 'GET', '/vulnerabilities/sqli/', {'id': '1 OR 1=1', 'Submit': 'Submit'}),
            ('xss', 'GET', '/vulnerabilities/xss_r/', {'name': '<script>alert(1)</script>'}),
            ('command_injection', 'POST', '/vulnerabilities/exec/', {'ip': '127.0.0.1; printf AHR_LAB_OK', 'Submit': 'Submit'}),
            ('file_inclusion', 'GET', '/vulnerabilities/fi/', {'page': '../../etc/hostname'}),
            ('brute_force', 'GET', '/vulnerabilities/brute/', {'username': 'admin', 'password': 'wrong-lab-' + str(round_id), 'Login': 'Login'}),
            ('scanner_pattern', 'GET', '/.env', {}),
        ]
        rng.shuffle(cases)
        for index, (family, method, path, fields) in enumerate(cases):
            sid = f'{campaign_id}_r{round_id:03d}_n{index:02d}'
            tasks.append(dict(scenario_id=sid, campaign_id=campaign_id,
                              simulated_ip=f'192.0.2.{1 + (index + round_id) % 200}',
                              label='benign' if family == 'benign' else 'attack',
                              attack_type=None if family == 'benign' else family,
                              method=method, path=path, fields=fields))
    return tasks


async def login(client):
    page = await client.get('/login.php')
    page.raise_for_status()
    parser = TokenParser()
    parser.feed(page.text)
    if not parser.token:
        raise RuntimeError('No DVWA CSRF token; initialize DVWA before collection')
    response = await client.post('/login.php', data={
        'username': os.getenv('DVWA_LAB_USERNAME', 'admin'),
        'password': os.getenv('DVWA_LAB_PASSWORD', 'password'),
        'Login': 'Login', 'user_token': parser.token})
    response.raise_for_status()
    if response.url.path.endswith('/login.php') or 'Login failed' in response.text:
        raise RuntimeError('DVWA login failed; no attack label was created')


async def execute(plan, target, delay=0.5, label_wait=30):
    import httpx
    from .db import connect_from_env, create_scenario, finish_scenario, label_scenario

    connection = await connect_from_env()
    results = []
    try:
        for task in plan:
            # New session per scenario; login is deliberately outside its attack window.
            async with httpx.AsyncClient(base_url=target, follow_redirects=True, timeout=15,
                                         trust_env=False, headers={'Host': 'dvwa.local'}) as client:
                await login(client)
                probe = await client.get('/vulnerabilities/sqli/', params={'id': '1', 'Submit': 'Submit'})
                if probe.url.path.endswith('/login.php') or probe.status_code >= 400:
                    raise RuntimeError('DVWA authenticated challenge probe failed')
                sid = task['scenario_id']
                await create_scenario(connection, scenario_id=sid, name='authenticated-campaign',
                    label=task['label'], attack_type=task['attack_type'], mode='COLLECTION_MODE',
                    source='campaign-auth-v1', target=target,
                    notes=json.dumps({'campaign_id': task['campaign_id'],
                                      'simulated_ip': task['simulated_ip'],
                                      'label_semantics': 'request_intent_not_exploit_success'}))
                params = {'ahr_scenario': sid}
                headers = {'X-AHR-Simulated-IP': task['simulated_ip']}
                fields = dict(task['fields'])
                if task['method'] == 'GET':
                    params.update(fields)
                response = await client.request(task['method'], task['path'], params=params,
                    data=fields if task['method'] == 'POST' else None, headers=headers)
                if response.url.host != urlparse(target).hostname or response.url.path.endswith('/login.php'):
                    raise RuntimeError('Challenge redirected away from authenticated DVWA')
                if response.status_code >= 500:
                    raise RuntimeError(f'Challenge returned {response.status_code}; stop collection and review')
                linked = await finish_scenario(connection, scenario_id=sid, request_count=1)
                deadline = asyncio.get_running_loop().time() + label_wait
                while not linked and asyncio.get_running_loop().time() < deadline:
                    await asyncio.sleep(1)
                    linked = await label_scenario(connection, scenario_id=sid)
                results.append({**task, 'status': response.status_code, 'linked_events': linked,
                                'response_bytes': len(response.content)})
                await asyncio.sleep(delay)
    finally:
        await connection.close()
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', default='http://nginx')
    p.add_argument('--rounds', type=int, default=2)
    p.add_argument('--seed', type=int, default=42)
    p.add_argument('--execute', action='store_true')
    p.add_argument('--delay', type=float, default=0.5)
    p.add_argument('--output', help='Optional JSON plan/results path')
    args = p.parse_args()
    target = local_target(args.target)
    if not 1 <= args.rounds <= 30 or args.delay < 0.2:
        p.error('rounds must be 1..30 and delay at least 0.2s')
    plan = make_plan(args.rounds, args.seed)
    result = dict(mode='execute' if args.execute else 'plan_only', target=target,
                  label_semantics='request_intent_not_exploit_success',
                  ip_semantics='simulated_metadata_not_packet_source',
                  items=asyncio.run(execute(plan, target, args.delay)) if args.execute else plan)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
