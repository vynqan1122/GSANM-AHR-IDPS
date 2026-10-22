from correlation.web_graph import build_web_graph, source_address


def attack(i, ip=None, score=.8, uri='/vulnerabilities/sqli/?id=1'):
    return {'event_id': f'e{i}', 'timestamp': f'2026-10-22T00:00:{i:02d}Z',
            'source': 'nginx', 'src_ip': ip, 'dst_ip': '172.20.0.3',
            'http': {'method': 'GET', 'uri': uri, 'status': 200},
            'ai': {'fusion_score': score}, 'severity': 5}


def test_web_graph_is_limited_and_chronological():
    graph = build_web_graph([attack(i, '10.0.0.8') for i in range(25)])
    assert graph['request_count'] == 20
    assert [row['event_id'] for row in graph['requests']] == [f'e{i}' for i in range(20)]
    assert sum(node['kind'] == 'request' for node in graph['nodes']) == 20
    assert '10.0.0.8' in {node['label'] for node in graph['nodes'] if node['kind'] == 'ip'}


def test_web_graph_does_not_guess_missing_ip_or_trust_forwarded_header():
    row = attack(1, None)
    row['raw_event'] = {'x_forwarded_for': '198.51.100.10', 'agent_ip': '172.20.0.1'}
    assert source_address(row)[0] is None
    node = next(node for node in build_web_graph([row])['nodes'] if node['kind'] == 'unattributed')
    assert node['label'] == 'IP client chưa ghi nhận'


def test_routine_navigation_is_not_web_attack():
    row = attack(1, '10.0.0.8', score=.1, uri='/login.php')
    graph = build_web_graph([row])
    assert graph['request_count'] == 0
    row['ai']['fusion_score']=.99
    row['http']['status']=None
    assert build_web_graph([row])['request_count']==0
    row['http']['uri']='/login.php?id=1%27+OR+1=1'
    assert build_web_graph([row])['request_count']==1
    row['http']['uri']='/dvwa/css/login.css'
    assert build_web_graph([row])['request_count']==0


def test_json_payload_ip_recovery_and_request_identity():
    import json
    row=attack(1,'unknown')
    row['raw_event']=json.dumps({'remote_addr':'2001:db8::8'})
    row['http']=json.dumps({'method':'GET','uri':'/x?password=secret&id=1','status':200})
    row['metadata']={'request_id':'same-request'}
    copy={**row,'event_id':'same-request-second-sensor'}
    graph=build_web_graph([copy,row])
    assert graph['request_count']==1
    assert source_address(row)[0]=='2001:db8::8'
    assert 'secret' not in json.dumps(graph)
    assert graph['requests'][0]['address_source']=='raw.remote_addr'


def test_harmless_acceptance_probe_excluded_but_query_attack_not_exempt():
    row=attack(1,'172.20.0.1',uri='/ahr-suricata-acceptance/ahr_suri_1786543475_4097_32004?source=phase2')
    row['rule']={'rule_id':'9000001'}
    assert build_web_graph([row])['request_count']==0
    row['http']['uri']+='&id=1%27+OR+1=1'
    assert build_web_graph([row])['request_count']==1


def test_malformed_uri_does_not_break_graph_or_expose_credentials():
    row=attack(1,'127.0.0.1',uri='http://[malformed?password=secret')
    row['severity']=0
    graph=build_web_graph([row])
    assert graph['request_count']==1
    assert 'secret' not in str(graph)


def test_score_only_health_admin_assets_and_probes_not_web_attacks():
    for uri in ('/api/health','/dashboard/','/dashboard/assets/app.js','/ahr-phase4/ahr_p4_123'):
        assert build_web_graph([attack(1,'172.20.0.1',uri=uri)])['request_count']==0
    row=attack(1,'172.20.0.1',uri='/login.php?id=1%27+OR+1=1')
    assert build_web_graph([row])['request_count']==1


def test_suricata_http_and_alert_same_transaction_count_once():
    row=attack(1,'172.20.0.1');row['source']='suricata'
    row['raw_event']={'flow_id':123,'tx_id':0}
    other={**row,'event_id':'other-sensor-record'}
    assert build_web_graph([row,other])['request_count']==1
