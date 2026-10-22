"""First twenty detected HTTP attacks; missing telemetry is never an invented IP."""
from ipaddress import ip_address
import re
from urllib.parse import urlsplit, parse_qsl
from feature_engine.event_contract import decode_event, http_details, clean_uri, routine_navigation, NAVIGATION


def source_address(event):
    row = decode_event(event)
    raw = row.get('raw_event') or {}
    data = raw.get('data') if isinstance(raw.get('data'), dict) else {}
    # Forwarded headers and Wazuh agent.ip do not prove the requesting client's IP.
    candidates = [('src_ip', row.get('src_ip')),
                  ('raw.remote_addr', raw.get('remote_addr')),
                  ('raw.src_ip', raw.get('src_ip')),
                  ('raw.srcip', raw.get('srcip')),
                  ('raw.data.srcip', data.get('srcip') or data.get('src_ip'))]
    for origin, value in candidates:
        try:
            address = ip_address(str(value).strip())
            if not address.is_unspecified:
                return str(address), origin
        except ValueError:
            pass
    return None, 'Sensor không ghi nhận IP client; không suy ra từ IP agent hoặc header gửi lên.'


def request_identity(event):
    row=decode_event(event)
    metadata=row.get('metadata') or {}; raw=row.get('raw_event') or {}
    explicit=metadata.get('request_id') or raw.get('trace_id')
    if explicit:return f"{row.get('source')}:{explicit}"
    if row.get('source')=='suricata' and raw.get('flow_id') is not None and raw.get('tx_id') is not None:
        return f"suricata:{raw['flow_id']}:{raw['tx_id']}"
    return str(row['event_id'])


def detected_web_attack(event):
    row = decode_event(event)
    h = http_details(row)
    if not h['uri'] or not h['method'] or routine_navigation(row):
        return False
    rule = row.get('rule') or {}
    try: uri = urlsplit(h['uri'])
    except ValueError: uri = None
    # This graph is for the protected DVWA web, not the SOC's own API/dashboard.
    if uri and (uri.path.startswith(('/api/', '/dashboard/', '/ws/')) or uri.path == '/dashboard'):
        return False
    query = parse_qsl(uri.query) if uri else []
    navigation = uri and (uri.path in NAVIGATION or uri.path in {'/favicon.ico','/api/health','/dashboard/','/dashboard','/ws/events'}
                          or uri.path.startswith(('/dvwa/images/', '/dvwa/css/', '/dvwa/js/', '/dashboard/assets/')))
    # Old Suricata HTTP records can lack response status. A score alone on clean
    # GET navigation does not make the owner's login an attack in this view.
    if (uri and not rule and h['method'] in {'GET', 'HEAD'} and navigation
            and all(k in {'ahr_probe','request_id','trace_id','ahr_scenario'}
                    and re.fullmatch(r'[A-Za-z0-9_-]*',v) for k,v in query)):
        return False
    if (uri and not rule and h['method']=='GET' and re.fullmatch(r'/ahr-phase[1-4]/[A-Za-z0-9_-]+',uri.path)
            and query in ([], [('source','acceptance')])):
        return False
    # Harmless acceptance traffic is detector coverage, not a confirmed web attack.
    if (uri and h['method'] == 'GET' and re.fullmatch(r'/ahr-suricata-acceptance/[A-Za-z0-9_-]+', uri.path)
            and query in ([], [('source', 'phase2')], [('source', 'wazuh')])
            and (not rule or str(rule.get('rule_id')) == '9000001')):
        return False
    score = (row.get('ai') or {}).get('fusion_score')
    return bool(rule.get('rule_id') or rule.get('name')) or (
        isinstance(score, (float, int)) and not isinstance(score, bool) and score >= .55)


def build_web_graph(events):
    nodes, edges, requests, seen = {}, [], [], set()
    for original in sorted(events, key=lambda r: (str(r.get('timestamp') or ''), str(r.get('event_id') or ''))):
        row = decode_event(original)
        if not detected_web_attack(row):
            continue
        eid = str(row['event_id'])
        request_id = request_identity(row)
        if request_id in seen:
            continue
        seen.add(request_id)
        h = http_details(row)
        ip, origin = source_address(row)
        src = f'ip:{ip}' if ip else f'unattributed:{eid}'
        nodes.setdefault(src, {'id': src, 'kind': 'ip' if ip else 'unattributed',
                              'label': ip or 'IP client chưa ghi nhận',
                              'details': {'address_source': origin,
                                          'note': 'Địa chỉ quan sát tại sensor; Docker/NAT có thể che IP máy gốc.' if ip else origin}})
        target_label = str((row.get('container') or {}).get('name') or row.get('dst_ip') or (row.get('http') or {}).get('host') or 'Web được giám sát')
        target = f'target:{target_label}'
        nodes.setdefault(target, {'id': target, 'kind': 'target', 'label': target_label})
        detail = {'event_id': eid, 'timestamp': str(row.get('timestamp') or ''),
                  'source': row.get('source'), 'src_ip': ip, 'address_source': origin,
                  'method': h['method'], 'uri': clean_uri(h['uri']), 'status': h['status'],
                  'rule': row.get('rule'), 'fusion_score': (row.get('ai') or {}).get('fusion_score')}
        req = f'request:{eid}'
        nodes[req] = {'id': req, 'kind': 'request', 'label': f"{len(requests)+1:02d}. {h['method']} {detail['uri']}", 'details': detail}
        edges.extend([{'source': src, 'target': req, 'relationship': 'sent'},
                      {'source': req, 'target': target, 'relationship': 'targeted'}])
        requests.append(detail)
        if len(requests) == 20:
            break
    return {'nodes': list(nodes.values()), 'edges': edges, 'requests': requests,
            'request_count': len(requests), 'limit': 20, 'order': 'timestamp_ascending',
            'criteria': 'Web DVWA: HTTP có rule hoặc Fusion >= 0.55; loại API/dashboard quản trị, điều hướng sạch và probe vô hại đã biết. Đây là phát hiện nghi vấn, chưa xác nhận khai thác thành công.'}
