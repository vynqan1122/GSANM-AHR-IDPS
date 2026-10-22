"""Read-only probes for research correctness; writes a sanitized evidence JSON."""
from __future__ import annotations
import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='output/pdf/ahr-idps-audit-evidence.json')
    args = parser.parse_args()
    from feature_engine.encoders import port_class
    from rule_engine.validator import rule_matches
    from rule_engine.genti import logic_check
    import xgboost as xgb
    module_spec = importlib.util.spec_from_file_location('trainer', ROOT / 'scripts/train_kaggle_network.py')
    trainer = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(trainer)
    probes = []
    probes.append(dict(id='F04-port-class', runtime_389=port_class(389),
                       offline_389=trainer._port_class(389),
                       inconsistent=port_class(389) != trainer._port_class(389)))
    attack = {'label': 'attack', 'attack_type': 'sql_injection', 'source': 'suricata',
              'event_type': 'http', 'http': {'uri': '/vulnerabilities/sqli/', 'method': 'GET'}}
    mapped = trainer._event_row(attack, 'local.jsonl')
    probes.append(dict(id='F04-label-derived-feature', has_rule=mapped['has_rule'],
                       actual_rule_exists=bool(attack.get('rule')),
                       bug='attack_type is used as rule presence in offline adapter'))
    rule = 'alert http any any -> any any (msg:"x"; http.method; content:"GET"; http.uri; content:"/only-this-path"; sid:9100001; rev:1;)'
    unrelated = {'http': {'method': 'GET', 'uri': '/login.php'}}
    probes.append(dict(id='F06-replay-mismatch', actual_rule_anchor='/only-this-path',
                       input_uri='/login.php', emulated_match=rule_matches('suricata', rule, unrelated)))
    try:
        logic_check('suricata', rule, '{"type":"network","uri_pattern":"/only-this-path"}')
        err = None
    except Exception as exc:
        err = type(exc).__name__
    probes.append(dict(id='F07-json-pattern', pattern_from_asyncpg='JSON text without codec', error=err))
    booster = xgb.train({'objective':'binary:logistic', 'nthread':1},
        xgb.DMatrix([[0,1],[1,0],[0,0],[1,1]], label=[0,1,0,1], feature_names=['a','b']), num_boost_round=1)
    try:
        booster.predict(xgb.DMatrix([[0,1]]))
        err = None
    except Exception as exc:
        err = type(exc).__name__
    probes.append(dict(id='F04-xgb-feature-names', named_model_unnamed_input_error=err))
    results = dict(date='2026-10-08', scope='static_and_in_memory_only',
                   runtime='Docker daemon unavailable; no live traffic generated',
                   probes=probes)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(results, indent=2, ensure_ascii=True))

if __name__ == '__main__':
    main()
