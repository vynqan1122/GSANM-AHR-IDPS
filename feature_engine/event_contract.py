"""Shared, dependency-light event decoding, privacy and navigation policy.

No source-IP allowlist: the server itself can generate malicious traffic.
Only clean HTTP navigation without security evidence is routine activity.
"""
from __future__ import annotations
import copy
import json
import re
from urllib.parse import urlsplit, parse_qsl, urlencode, unquote

JSON_FIELDS=('http','container','process','network','rule','raw_event','metadata','labels','ai','file_details','user_details')
SENSITIVE={'password','passwd','pwd','user_token','csrf','csrf_token','token','cookie','authorization',
           'ahr_scenario','scenario_id','trace_id','request_id','phpsessid','session_id'}
NAVIGATION={'/','/index.php','/login.php','/logout.php','/instructions.php','/about.php','/security.php','/setup.php','/healthz'}


def decode_event(event):
    row=dict(event)
    for key in JSON_FIELDS:
        value=row.get(key)
        if isinstance(value,str):
            try: row[key]=json.loads(value)
            except (ValueError,TypeError): row[key]=None
    return row


def http_details(event):
    row=decode_event(event)
    h=row.get('http') if isinstance(row.get('http'),dict) else {}
    raw=row.get('raw_event') if isinstance(row.get('raw_event'),dict) else {}
    nested=raw.get('http') if isinstance(raw.get('http'),dict) else {}
    return {'uri':h.get('uri') or h.get('url') or nested.get('url') or raw.get('request_uri') or '',
            'method':h.get('method') or nested.get('http_method') or raw.get('request_method') or '',
            'status':h.get('status') or nested.get('status') or raw.get('status')}


def clean_uri(uri):
    try: parts=urlsplit(str(uri or ''))
    except ValueError:
        return str(uri or '').split('?',1)[0].split('#',1)[0]
    query=[(k,v) for k,v in parse_qsl(parts.query,keep_blank_values=True) if k.lower() not in SENSITIVE]
    return parts.path+('?' + urlencode(query) if query else '')


def routine_navigation(event):
    row=decode_event(event); h=http_details(row)
    # A real rule/runtime event is never silenced by URL or loopback IP.
    if row.get('rule') or float(row.get('severity') or 0)>0 or row.get('source') not in {'nginx','suricata'}:
        return False
    if h['method'].upper() not in {'GET','HEAD'} or h['status'] not in {200,301,302,303,304}:
        return False
    try: parsed=urlsplit(h['uri'])
    except ValueError: return False
    if parsed.path not in NAVIGATION: return False
    # Ignore only correlation markers. Any other query is reviewed, not exempted.
    query=[(k,v) for k,v in parse_qsl(parsed.query,keep_blank_values=True)
           if k.lower() not in {'ahr_scenario','request_id','trace_id'}]
    return not query and not row.get('process')


def operational_path(event):
    """Training-label exclusion, not an immunity from security detections."""
    try: return urlsplit(http_details(event)['uri']).path in NAVIGATION
    except ValueError: return False


def learning_event(event):
    """Remove experimental identifiers from model input; retain detector evidence."""
    row=decode_event(event)
    row=copy.deepcopy(row)
    h=http_details(row)
    row['http']={**(row.get('http') or {}),**h,'uri':clean_uri(h['uri'])}
    # Model must not learn a label/scenario hint or old model output.
    row['labels']={};row['ai']={}
    row.pop('scenario_id',None);row.pop('attack_type',None);row.pop('split',None)
    raw=row.get('raw_event') or {}
    if isinstance(raw,dict):
        if 'request_uri' in raw:raw['request_uri']=clean_uri(raw['request_uri'])
        if isinstance(raw.get('http'),dict):
            if 'url' in raw['http']:raw['http']['url']=clean_uri(raw['http']['url'])
        for k in list(raw):
            if k.lower() in SENSITIVE:raw.pop(k)
    return row
