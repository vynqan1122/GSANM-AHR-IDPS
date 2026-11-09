"""One Docker-native smoke test per worker boot; never promotes or installs rules."""
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import struct
import subprocess
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ai.genti.contract import decode_output
from ai.genti.pcap import tcp_case
from ai.genti.native_validation import evaluate, load_cases

ROOT = Path('/checks')
URL = 'http://genti:8090'


def api(path, payload=None):
    req = Request(URL + path, data=None if payload is None else json.dumps(payload).encode(),
                  headers={'Content-Type': 'application/json'})
    with urlopen(req, timeout=630 if payload else 5) as response:
        return json.load(response)


def passed(verdict):
    counts = verdict.get('replay') or {}
    return bool(verdict.get('syntax', {}).get('ok') and counts.get('tp') == 3 and
                counts.get('tn') == 5 and counts.get('fp') == 0 and counts.get('fn') == 0)


def save(report, folder):
    data = json.dumps(report, ensure_ascii=False, indent=2)
    for path in (folder / 'report.json', ROOT / 'latest.json'):
        temp = path.with_suffix('.tmp')
        temp.write_text(data, encoding='utf-8')
        temp.replace(path)


def run(state):
    folder = ROOT / state['startup_id']
    folder.mkdir(exist_ok=False)
    report = {'status': 'running', 'startup_id': state['startup_id'],
              'artifact_sha256': state['model']['artifact_sha256'],
              'started_at': datetime.now(timezone.utc).isoformat(), 'attempts': [],
              'scope': '3 positive + 5 benign synthetic HTTP PCAP controls; not a quality benchmark',
              'sensor_deployed': False, 'human_approved': False}
    save(report, folder)
    try:
        report['engine_version'] = subprocess.check_output(['suricata', '-V'], text=True, stderr=subprocess.STDOUT).strip()
        cases = []; evidence = []; benign = []
        values = ['<script>alert(1)</script>', '<SCRIPT>alert(2)</SCRIPT>', 'prefix <script suffix',
                  'Alice', 'course report', 'script writing', 'normal query', 'hello world']
        for i, value in enumerate(values):
            uri = '/vulnerabilities/xss_r/?' + urlencode({'name': value})
            path = folder / f'case-{i}.pcap'
            with path.open('xb') as stream:
                stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                for n, packet in enumerate(tcp_case(45000 + i, 'GET', uri)):
                    stream.write(struct.pack('<IIII', 1793490000, n * 1000, len(packet), len(packet)))
                    stream.write(packet)
            cases.append({'case_id': f'case-{i}', 'label': 'attack' if i < 3 else 'benign', 'pcap': path.name})
            row = {'protocol': 'http', 'http': {'method': 'GET', 'uri': uri, 'hostname': 'dvwa.local'}}
            (evidence if i < 3 else benign).append(row)
        (folder / 'cases.jsonl').write_text(''.join(json.dumps(c) + '\n' for c in cases), encoding='utf-8')
        controls = load_cases(folder / 'cases.jsonl')
        request = {'task': 'Write one Suricata alert for GET URI beginning /vulnerabilities/xss_r/? and containing case-insensitive <script. Avoid benign names. GET is exactly 3 bytes. Do not claim validation or deployment.',
                   'evidence': evidence[:1], 'benign_examples': benign[:1],
                   'cti': {'references': [], 'mitre_attack': []}}
        for attempt in range(3):
            current = api('/status')
            if current['startup_id'] != report['startup_id'] or current['model']['artifact_sha256'] != report['artifact_sha256']:
                raise RuntimeError('Worker changed during test; discard this result')
            answer = api('/generate', request)
            if answer['artifact_sha256'] != report['artifact_sha256']:
                raise RuntimeError('Generation came from a different model')
            output = decode_output(json.dumps(answer['output']), request['cti'])
            (folder / f'candidate-{attempt}.json').write_text(json.dumps(answer, ensure_ascii=False, indent=2), encoding='utf-8')
            verdict = evaluate(output['rule'], '/etc/suricata/suricata.yaml', controls)
            report['attempts'].append({'attempt': attempt, 'rule_sha256': hashlib.sha256(output['rule'].encode()).hexdigest(),
                                       'generation_seconds': answer['seconds'], **verdict})
            save(report, folder)
            if passed(verdict):
                report['status'] = 'passed'
                break
            feedback = json.dumps(verdict.get('replay') or verdict.get('syntax'), ensure_ascii=False)[:1000]
            request['task'] = (request['task'].split(' Previous draft:')[0] +
                               ' Previous draft: ' + output['rule'] + ' Native feedback: ' + feedback)[:2000]
        else:
            raise RuntimeError('Smoke replay failed after two repairs; no promotion')
    except Exception as exc:
        logging.exception('GenTI self test failed')
        report.update(status='failed', error=f'{type(exc).__name__}: {str(exc)[:400]}')
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    save(report, folder)
    return report


if __name__ == '__main__':
    ROOT.mkdir(parents=True, exist_ok=True)
    seen = None
    while True:
        try:
            state = api('/status')
            if state.get('ready') and state.get('startup_id') != seen:
                seen = state['startup_id']
                saved = ROOT / seen / 'report.json'
                if not saved.exists():
                    print(json.dumps(run(state)), flush=True)
                else:
                    report = json.loads(saved.read_text(encoding='utf-8'))
                    if report['status'] == 'running':
                        report.update(status='failed', error='Validator restarted before completion; restart the GenTI worker to retest')
                    save(report, ROOT / seen)
        except Exception:
            logging.exception('Waiting for the GenTI worker')
        time.sleep(5)
