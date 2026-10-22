import ast
import json
from pathlib import Path
import numpy as np
import pytest

from feature_engine.event_contract import routine_navigation,learning_event,clean_uri
from feature_engine.network_features import build_network_features
from correlation.rules import actionable_event
from ai.colab.data import split_groups,sanitized_event,load_events
from ai.colab.bridge import validate_response,remote_event
from ai.colab.train import fit_xgb,xpred,metrics,fusion_matrix


def event(i=0,label='benign'):
    return {'event_id':f'e-{i}','timestamp':'2026-10-19T12:00:00Z','source':'nginx',
            'event_type':'http.access','src_ip':'127.0.0.1','dst_ip':'172.18.0.2','src_port':30000+i,'dst_port':80,
            'protocol':'tcp','http':{'method':'GET','uri':'/login.php','status':200},
            'rule':None,'severity':0,'scenario_id':f's-{i}','label':label,'ai':{'fusion_score':.99}}


def test_login_not_incident_but_local_attacks_not_whitelisted():
    normal=event();assert routine_navigation(normal);assert not actionable_event(normal)
    malicious=event();malicious['http']['uri']='/login.php?id=1%27+OR+1=1'
    assert not routine_navigation(malicious) and actionable_event(malicious)
    signature=event();signature['rule']={'rule_id':'sql-detector'}
    assert actionable_event(signature)
    failed=event();failed['http']['status']=403
    assert actionable_event(failed)


def test_marker_secret_removal_and_json_decode_parity():
    e=event();e['http']['uri']='/x?id=2&ahr_scenario=attack_123&password=secret&user_token=token'
    e['http']=json.dumps(e['http']);a=learning_event(e)
    assert 'secret' not in a['http']['uri'] and 'attack_123' not in a['http']['uri']
    assert a['http']['uri']=='/x?id=2'
    assert build_network_features(e)==build_network_features({**e,'http':json.loads(e['http'])})


def test_operational_attack_labels_are_excluded_not_relabelled(tmp_path):
    path=tmp_path/'events.jsonl'
    benign=event();bad=event(1,'attack');good=event(2,'attack');good['http']['uri']='/vulnerabilities/sqli/?id=1+OR+1=1'
    path.write_text('\n'.join(json.dumps(e) for e in (benign,bad,good)))
    rows,excluded=load_events(path)
    assert {r['event_id'] for r in rows}=={'e-0','e-2'}
    assert excluded['attack_label_on_operational_url']==1


def test_group_disjoint_and_missing_scenario_fails(tmp_path):
    rows=[]
    for i in range(30):
        e=event(i,'attack' if i%2 else 'benign');e['group_id']=e['scenario_id'];rows.append(e)
    splits,y=split_groups(rows)
    sets=[{rows[i]['group_id'] for i in ix} for ix in splits.values()]
    assert not sets[0]&sets[1] and not sets[1]&sets[2] and not sets[0]&sets[2]
    for ix in splits.values():assert len(np.unique(y[ix]))==2


def test_private_export_and_remote_payload_never_send_password_cookie():
    e=event();e.update(raw_event={'cookie':'secret'},metadata={'password':'secret'})
    e['http']['uri']='/login.php?password=secret&user_token=secret'
    sent=remote_event(e)
    assert 'secret' not in json.dumps(sent)
    assert not {'label','attack_type','scenario_id','campaign_id'}&set(sent)


def test_remote_response_rejects_nan_id_mismatch():
    e=event();p={'contract':'colab-local-v2','items':[{'event_id':e['event_id'],'bundle_version':'v2',
       'scores':dict(network_score=.4,log_score=.3,graph_score=.2,fusion_score=.4)}]}
    assert validate_response([e],p)
    p['items'][0]['scores']['fusion_score']=float('nan')
    with pytest.raises(ValueError):validate_response([e],p)


def test_named_model_runtime_input_parity_cpu():
    x=np.array([[i,i%3] for i in range(20)],np.float32);y=np.array([i%2 for i in range(20)])
    model=fit_xgb(x,y,'cpu',2,['a','b'])
    assert xpred(model,x).shape==(20,)


def test_fusion_does_not_depend_on_scenario_or_old_scores():
    a=event();b={**a,'scenario_id':'attack','labels':{'attack_type':'sqli'},'ai':{'fusion_score':1}}
    x,_,_=fusion_matrix([a],np.array([[.2,.3,.4]]))
    z,_,_=fusion_matrix([b],np.array([[.2,.3,.4]]))
    assert np.array_equal(x,z)


def test_notebook_cells_are_python_and_secret_free():
    from scripts.build_colab_kit import notebook
    nb=notebook()
    assert nb['nbformat']==4
    for cell in nb['cells']:
        if cell['cell_type']=='code':ast.parse(''.join(cell['source']))
    assert 'NGROK_AUTHTOKEN' in json.dumps(nb)


def test_colab_blocks_imports_until_restart_and_detects_changed_requirements(tmp_path):
    import os
    import hashlib
    from scripts.build_colab_kit import notebook
    cells=[''.join(c['source']) for c in notebook()['cells'] if c['cell_type']=='code']
    setup=next(c for c in cells if 'CÀI ĐẶT:' in c)
    # The installing kernel must never load the scientific stack after replacing it.
    imports=[n for n in ast.walk(ast.parse(setup)) if isinstance(n,(ast.Import,ast.ImportFrom))]
    imported={alias.name.split('.')[0] for n in imports if isinstance(n,ast.Import) for alias in n.names}
    assert not imported & {'numpy','scipy','pandas','sklearn','xgboost'}
    runtime=next(c for c in cells if "setup['installer_pid']" in c)
    # Execute actual startup guards without proceeding to imports/GPU/Drive calls.
    guards=runtime.split("os.environ['OMP_NUM_THREADS']")[0]
    guards=guards.replace("WORK=Path('/content/ahr-colab')",f'WORK=Path({str(tmp_path)!r})')
    requirements=tmp_path/'ai/colab/requirements.txt'
    requirements.parent.mkdir(parents=True)
    requirements.write_text('numpy==2.3.5')
    marker=tmp_path/'.dependencies-ready.json'
    with pytest.raises(RuntimeError,match='upload/cài đặt'):exec(guards,{})
    state={'installer_pid':os.getpid(),'requirements_sha256':hashlib.sha256(requirements.read_bytes()).hexdigest()}
    marker.write_text(json.dumps(state))
    with pytest.raises(RuntimeError,match='Kernel chưa restart'):exec(guards,{})
    state['installer_pid']=-1
    marker.write_text(json.dumps(state))
    exec(guards,{})
    requirements.write_text('numpy==2.3.4')
    with pytest.raises(RuntimeError,match='Requirements đã đổi'):exec(guards,{})


def test_conflicting_labels_only_excluded_with_explicit_flag(tmp_path):
    a=event();a['http']['uri']='/vulnerabilities/sqli/?id=1'
    b={**a,'label':'attack'}
    c=event(2);c['http']['uri']='/instructions.php'
    path=tmp_path/'data.jsonl';path.write_text('\n'.join(json.dumps(r) for r in (a,b,c)))
    with pytest.raises(ValueError,match='conflicting'):load_events(path)
    rows,excluded=load_events(path,exclude_conflicts=True)
    assert len(rows)==1 and rows[0]['event_id']=='e-2'
    assert excluded['conflicting_event_ids_excluded']==1


def test_https_api_requires_token_and_rejects_bad_request():
    from fastapi.testclient import TestClient
    from ai.colab.serve import create_app
    class FakeScorer:
        def score(self,events):
            assert not any('scenario_id' in e for e in events)
            return [{'event_id':e['event_id'],'scores':{},'bundle_version':'fake'} for e in events]
    token='random-test-token-'+'x'*40
    client=TestClient(create_app('.',token,device='cpu',scorer=FakeScorer()))
    assert client.post('/score',json={'events':[event()]}).status_code==401
    assert client.post('/score',json={'events':[]},headers={'Authorization':'Bearer '+token}).status_code==422
    r=client.post('/score',json={'events':[event()]},headers={'Authorization':'Bearer '+token})
    assert r.status_code==200 and r.json()['contract']=='colab-local-v2'
