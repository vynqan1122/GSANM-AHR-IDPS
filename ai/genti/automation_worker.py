"""Native lab rule validation and lifecycle worker; no Docker socket or host firewall."""
import hashlib
import json
import logging
import os
from pathlib import Path
import struct
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ai.genti.automation_contract import PROFILE, matches, supported
from ai.genti.native_validation import evaluate, load_cases
from ai.genti.pcap import tcp_case

ROOT = Path('/checks/automation')


def api(path, payload=None, timeout=20):
    request = Request('http://backend:8000/api/internal/automation/'+path,
                      data=None if payload is None else json.dumps(payload).encode(),
                      headers={'Content-Type': 'application/json', 'X-AHR-Worker': os.environ['AHR_AUTOMATION_KEY']})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def keep_alive():
    while True:
        try:
            api('heartbeat', {})
            api('advance', {})
        except Exception:
            logging.exception('Automation heartbeat unavailable')
        time.sleep(5)


def validate(job):
    if not supported(job['content']):
        raise ValueError('Unsupported auto-enforcement profile')
    folder = ROOT / (job['rule_id']+'-'+str(time.time_ns()))
    folder.mkdir(parents=True, exist_ok=False)
    cases = []; decisions = {}
    for i in range(100):
        attack = i < 50
        value = (['<script>alert(%d)</script>', '<SCRIPT>test%d', 'prefix<script suffix%d'][i % 3] % i
                 if attack else ['Alice%d', 'script writing%d', 'course report%d', 'hello world%d'][i % 4] % i)
        uri = '/vulnerabilities/xss_r/?'+urlencode({'name': value, 'control': i})
        name = f'case-{i}.pcap'
        with (folder/name).open('xb') as stream:
            stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for n, packet in enumerate(tcp_case(45000+i, 'GET', uri)):
                stream.write(struct.pack('<IIII', int(time.time()), n*1000, len(packet), len(packet)))
                stream.write(packet)
        case_id = f'case-{i}'
        cases.append({'case_id': case_id, 'label': 'attack' if attack else 'benign', 'pcap': name,
                      'method': 'GET', 'uri': uri, 'provenance': 'synthetic controlled lab probe; not independent benchmark'})
        decisions[case_id] = matches('GET', uri)
    cases_path = folder/'cases.jsonl'
    cases_path.write_text(''.join(json.dumps(c)+'\n' for c in cases), encoding='utf-8')
    (folder/'rule.rules').write_text(job['content']+'\n', encoding='utf-8')
    verdict = evaluate(job['content'], '/etc/suricata/suricata.yaml', load_cases(cases_path))
    details = (verdict.get('replay') or {}).get('cases', [])
    verdict['gateway_parity'] = len(details) == 100 and all(c['matched'] == decisions[c['case_id']] for c in details)
    receipt = {'rule_id': job['rule_id'], 'rule_version': job['current_version'],
               'rule_sha256': hashlib.sha256(job['content'].encode()).hexdigest(),
               'artifact_sha256': job['artifact_sha256'], 'profile': PROFILE,
               'engine_version': subprocess.check_output(['suricata', '-V'], text=True, stderr=subprocess.STDOUT).strip(),
               'receipt_path': str(folder/'receipt.json'), 'verdict': verdict}
    (folder/'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    api('receipt', receipt)


def main():
    logging.basicConfig(level=logging.INFO)
    threading.Thread(target=keep_alive, daemon=True).start()
    while True:
        try:
            job = api('job').get('job')
            if job:
                validate(job)
            else:
                api('generate', {}, timeout=1300)
        except HTTPError as exc:
            logging.error('Automation endpoint %s: %s', exc.code, exc.read().decode()[:400])
        except Exception:
            logging.exception('Automation cycle failed; no approval or enforcement implied')
        time.sleep(5)


if __name__ == '__main__':
    main()
