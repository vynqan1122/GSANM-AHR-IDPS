"""Native Suricata validation required before automatic rule promotion."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from ai.genti.contract import check_rule

def run_rule(rule, config, pcap=None, binary='suricata'):
    rule = check_rule(rule)
    sids = re.findall(r'\bsid:\s*(\d+)\s*;', rule)
    if len(sids) != 1:
        raise ValueError('Exactly one SID is required')
    if not shutil.which(binary):
        raise RuntimeError('Native Suricata missing; no structural fallback')
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder); rules = root / 'candidate.rules'
        rules.write_text(rule + '\n', encoding='utf-8')
        cmd = [binary, '--init-errors-fatal', '--set', 'unix-command.enabled=no',
               '-c', str(Path(config).resolve()), '-S', str(rules), '-l', folder]
        cmd += ['-T'] if pcap is None else ['-r', str(Path(pcap).resolve()), '--runmode', 'single']
        start = time.perf_counter()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        elapsed = time.perf_counter() - start
        if result.returncode:
            return {'ok': False, 'error': (result.stdout + result.stderr)[-3000:], 'seconds': elapsed}
        if pcap is None:
            return {'ok': True, 'seconds': elapsed}
        eve = root / 'eve.json'
        if not eve.exists():
            raise RuntimeError('Replay produced no EVE JSON; enable EVE alert output in the config')
        hits = 0; http_transactions = 0
        for line in eve.open(encoding='utf-8'):
            if not line.strip():continue
            event=json.loads(line)
            http_transactions += event.get('event_type') == 'http'
            hits += (event.get('event_type') == 'alert' and
                     str((event.get('alert') or {}).get('signature_id')) == sids[0])
        if rule.split()[1]=='http' and not http_transactions:
            raise RuntimeError('No HTTP transaction parsed; check PCAP checksums and enable EVE HTTP output before scoring')
        return {'ok': True, 'matched': hits > 0, 'alert_count': hits,
                'http_transactions': http_transactions, 'seconds': elapsed}

def load_cases(path):
    path = Path(path).resolve(); cases = []; ids = set(); hashes = set()
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        c = json.loads(line)
        if c.get('label') not in ('attack', 'benign') or not c.get('case_id') or c['case_id'] in ids:
            raise ValueError('Invalid/duplicate case ID or label')
        pcap = (path.parent / c['pcap']).resolve()
        if not pcap.is_relative_to(path.parent) or not pcap.is_file():
            raise ValueError('PCAP must exist within the cases directory')
        digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
        if digest in hashes:
            raise ValueError('Duplicate PCAP is not an independent test case')
        ids.add(c['case_id']); hashes.add(digest)
        cases.append({**c, 'pcap': str(pcap), 'sha256': digest})
    if not cases or {c['label'] for c in cases} != {'benign', 'attack'}:
        raise ValueError('Need both benign and attack PCAP cases')
    return cases

def evaluate(rule, config, cases=None):
    syntax = run_rule(rule, config)
    out = {'syntax': syntax, 'replay': None, 'eligible_for_human_review': False}
    if not syntax['ok'] or cases is None:
        return out
    counts = dict(tp=0, fp=0, tn=0, fn=0); details = []
    for c in cases:
        result = run_rule(rule, config, c['pcap'])
        if not result['ok']:
            out['replay_error'] = {'case_id': c['case_id'], **result}
            return out
        key = ('tp' if result['matched'] else 'fn') if c['label'] == 'attack' else ('fp' if result['matched'] else 'tn')
        counts[key] += 1
        details.append({'case_id': c['case_id'], 'sha256': c['sha256'], **result})
    tp, fp, tn, fn = (counts[k] for k in ('tp', 'fp', 'tn', 'fn'))
    precision = tp / max(tp + fp, 1); recall = tp / (tp + fn); fpr = fp / (fp + tn)
    out['replay'] = {**counts, 'precision': precision, 'recall': recall, 'fpr': fpr,
                     'unit': 'one labeled PCAP case; independence requires dataset evidence', 'cases': details}
    out['eligible_for_human_review'] = (tp + fn >= 50 and fp + tn >= 50
                                      and precision >= .9 and recall >= .75 and fpr <= .02)
    return out
