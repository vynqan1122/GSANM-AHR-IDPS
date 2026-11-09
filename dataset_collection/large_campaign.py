"""Generate varied request plans and collect exact-marker-labeled real lab telemetry.

Plan only unless --execute. Run inside backend container; DB/Redis stay internal.
SQLite records completed requests so a stopped run can resume without replaying them.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import sqlite3
import time
import uuid
import zipfile

import httpx
from feature_engine.event_contract import decode_event, sanitized_event, http_details
from .campaign import local_target, login
from .db import connect_from_env

FAMILIES = (['benign']*60 + ['sqli']*14 + ['sqli_blind']*6 + ['xss']*10
            + ['file_inclusion']*3 + ['command_injection'] + ['auth_failure']*3 + ['recon']*3)
WORDS=('research','student','course','report','request','browser','profile','catalog',
       'document','security','review','example','science','dataset','network','session')


def make_request(run_id,index,seed=42,session_size=500):
    if not re.fullmatch(r'[a-f0-9]{12}',run_id):raise ValueError('run_id must be 12 hex characters')
    rng=random.Random(seed+index*1009)
    family=FAMILIES[(index%100+((index//100)*17))%100]
    marker=f'ahrbulk_{run_id}_{index:06d}'
    a=rng.randint(10,9999); b=a if index%2 else a+1
    word=' '.join(rng.choice(WORDS) for _ in range(4))
    # Same nuisance fields on both classes, not a label-only padding token.
    fields={'q':word,'page_size':str(rng.choice([5,10,20,50]))}
    method='GET';intent='attack'
    if family=='benign':
        intent='benign'
        choice=rng.randrange(4)
        if choice==0:path='/vulnerabilities/sqli/';fields.update(id=str(rng.randint(1,5)),Submit='Submit')
        elif choice==1:path='/vulnerabilities/xss_r/';fields.update(name=word)
        elif choice==2:path='/vulnerabilities/fi/';fields.update(page=rng.choice(['include.php','file1.php','file2.php']))
        else:path=rng.choice(['/','/index.php','/instructions.php']);fields={}
    elif family in {'sqli','sqli_blind'}:
        path='/vulnerabilities/sqli_blind/' if family=='sqli_blind' else '/vulnerabilities/sqli/'
        op=rng.choice(['OR','oR','or','AND','aNd'])
        sep=rng.choice([' ','/**/','\t'])
        payload=f"{rng.randint(1,5)}'{sep}{op}{sep}{a}={b} -- "
        fields.update(id=payload,Submit='Submit')
    elif family=='xss':
        path='/vulnerabilities/xss_r/'
        value=f'{rng.choice(WORDS)} {a}'
        fields['name']=rng.choice([f'<script>document.title="{value}"</script>',
                                   f'<img src=x onerror="document.title=\'{value}\'">',
                                   f'<svg onload="document.title=\'{value}\'"></svg>'])
    elif family=='file_inclusion':
        path='/vulnerabilities/fi/'
        fields['page']=rng.choice(['../../../../etc/hostname','/etc/hostname','/etc/./hostname'])
    elif family=='command_injection':
        path='/vulnerabilities/exec/';method='POST'
        fields.update(ip=f'127.0.0.1; printf {marker}',Submit='Submit')
    elif family=='auth_failure':
        path='/vulnerabilities/brute/'
        fields.update(username=rng.choice(['admin','guest','gordonb','pablo']),password=f'wrong-lab-{a}',Login='Login')
    else:
        path=rng.choice(['/.env','/.git/config','/admin/','/server-status','/backup.zip','/phpinfo.php'])
    return {'index':index,'marker':marker,'campaign_id':f'bulk_{run_id}_s{index//session_size:05d}',
            'family':family,'label':intent,'method':method,'path':path,'fields':fields}


def create_plan(directory,requests=100000,seed=42,run_id=None,session_size=500):
    directory=Path(directory)
    if directory.exists():raise ValueError('Output exists; use --resume to continue it, or choose a new folder')
    if not 100 <= requests <= 200000 or not 20 <= session_size <= 1000:raise ValueError('Invalid plan size/session size')
    directory.mkdir(parents=True)
    run_id=run_id or uuid.uuid4().hex[:12]
    counts=Counter();fingerprints=set();plan=directory/'request-plan.jsonl'
    with plan.open('w',encoding='utf-8') as stream:
        for index in range(requests):
            task=make_request(run_id,index,seed,session_size);counts[task['family']]+=1
            fingerprints.add(hashlib.sha256(json.dumps([task['method'],task['path'],task['fields']],sort_keys=True).encode()).hexdigest())
            stream.write(json.dumps(task,ensure_ascii=False)+'\n')
    meta={'contract':'real-dvwa-campaign-v1','run_id':run_id,'seed':seed,'planned_requests':requests,
          'session_size':session_size,'family_counts':dict(counts),'unique_request_content':len(fingerprints),
          'marker_is_not_diversity':True,'request_plan_sha256':hashlib.sha256(plan.read_bytes()).hexdigest(),
          'created_at':datetime.now(timezone.utc).isoformat(),'label_semantics':'request_intent_not_exploit_success',
          'feature_schema':'colab-local-v2','data_state':'plan_only_no_telemetry_created'}
    (directory/'plan-manifest.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    return meta


def open_journal(directory):
    db=sqlite3.connect(Path(directory)/'request-results.sqlite3')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('''CREATE TABLE IF NOT EXISTS results (
        idx INTEGER PRIMARY KEY, marker TEXT UNIQUE, campaign_id TEXT, family TEXT, label TEXT,
        status INTEGER, received_at TEXT, elapsed_ms REAL, response_bytes INTEGER,
        response_sha256 TEXT, observations TEXT, valid INTEGER NOT NULL)''')
    return db


def request_marker(event,prefix):
    row=decode_event(event);h=http_details(row)
    raw=row.get('raw_event') or {};process=row.get('process') or {}
    fields=raw.get('output_fields') if isinstance(raw.get('output_fields'),dict) else {}
    data=raw.get('data') if isinstance(raw.get('data'),dict) else {}
    nested=data.get('output_fields') if isinstance(data.get('output_fields'),dict) else {}
    # Prefer request URI, never infer an attack label from an unrelated referer.
    text=h['uri'] or process.get('cmdline') or fields.get('proc.cmdline') or nested.get('proc.cmdline') or data.get('output') or raw.get('full_log') or ''
    match=re.search(r'\b(ahrbulk_'+re.escape(prefix)+r'_\d{6})(?!\d)',str(text))
    return match.group(1) if match else None


async def fetch_observed(connection,meta,started,include_all=False):
    # Time bound is indexed; fixed prefix narrows actual events to this run only.
    query='''SELECT event_id,timestamp,source,event_type,category,src_ip,dst_ip,src_port,dst_port,
                    protocol,http,network,container,process,rule,severity,raw_event,metadata
             FROM ahr.events WHERE ingestion_timestamp >= $1
             AND (position($2 in coalesce(http->>'uri', http->>'url', ''))>0
                  OR position($2 in coalesce(process->>'cmdline',raw_event->'output_fields'->>'proc.cmdline',raw_event->>'full_log',''))>0)
             ORDER BY timestamp,event_id'''
    return await connection.fetch(query,started,'ahrbulk_'+meta['run_id']+'_')


async def observed_count(connection,meta,started):
    return int(await connection.fetchval('''SELECT count(*) FROM ahr.events
        WHERE ingestion_timestamp >= $1 AND
          (position($2 in coalesce(http->>'uri', http->>'url', ''))>0
           OR position($2 in coalesce(process->>'cmdline',raw_event->'output_fields'->>'proc.cmdline',raw_event->>'full_log',''))>0)''',
        started,'ahrbulk_'+meta['run_id']+'_'))


def export_rows(directory,meta,journal,events):
    out=Path(directory)/'export';out.mkdir(exist_ok=True)
    by_marker={r[1]:r for r in journal.execute('SELECT idx,marker,campaign_id,family,label,valid FROM results WHERE valid=1')}
    counts=Counter();families=Counter();seen=set();missed=set(by_marker);groups={};feature_fp=set()
    path=out/'events-colab.jsonl'
    with path.open('w',encoding='utf-8') as stream:
        for event in events:
            row=decode_event(dict(event));marker=request_marker(row,meta['run_id'])
            if marker not in by_marker or row['event_id'] in seen:continue
            task=by_marker[marker];seen.add(row['event_id']);missed.discard(marker)
            row.update(scenario_id=marker,campaign_id=task[2],label=task[4],
                       attack_type=None if task[4]=='benign' else task[3])
            clean=sanitized_event(row)
            for key in ('timestamp',):
                if isinstance(clean.get(key),datetime):clean[key]=clean[key].isoformat()
            stream.write(json.dumps(clean,ensure_ascii=False)+'\n')
            counts[row['source']]+=1;families[task[3]]+=1
            groups.setdefault(task[2],set()).add(task[4])
            feature_fp.add(hashlib.sha256(json.dumps({k:v for k,v in clean.items() if k not in {
                'event_id','timestamp','scenario_id','campaign_id','label','attack_type','src_port'}},sort_keys=True).encode()).hexdigest())
    report={'contract':'colab-local-v2','real_sensor_events':len(seen),'by_source':dict(counts),
            'by_intent_family':dict(families),'completed_valid_requests':len(by_marker),
            'requests_without_observed_event':len(missed),'campaign_groups':len(groups),
            'groups_with_both_classes':sum(len(v)==2 for v in groups.values()),
            'canonical_fingerprints_without_id_time_src_port':len(feature_fp),
            'dataset_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'provenance':'actual ahr.events joined by exact generated request/command marker; no event fabrication',
            'label_semantics':'request_intent_not_exploit_success; oracle review remains required',
            'limitations':['no packet source spoofing','no inferred labels for markerless host events',
                           'single-event causal graph; not a full temporal GNN','canonical HTTP has no POST body']}
    (out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    archive=out/'colab-dataset.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(path,path.name);z.write(out/'manifest.json','manifest.json')
    return report


async def collect(directory,target='http://nginx',rps=20,workers=4,target_events=100000,resume=False,export_only=False,request_limit=None,sensor_only=False):
    import redis.asyncio as redis
    directory=Path(directory);target=local_target(target)
    if not 1<=rps<=50 or not 1<=workers<=8:raise ValueError('rps=1..50, workers=1..8')
    meta=json.loads((directory/'plan-manifest.json').read_text())
    if hashlib.sha256((directory/'request-plan.jsonl').read_bytes()).hexdigest()!=meta['request_plan_sha256']:
        raise ValueError('Plan checksum changed')
    journal=open_journal(directory)
    progress_file=directory/'progress.json'
    previous=json.loads(progress_file.read_text()) if progress_file.exists() else {}
    if previous and not resume:raise ValueError('Run already started; pass --resume')
    started=datetime.fromisoformat(previous.get('started_at') or datetime.now(timezone.utc).isoformat())
    connection=await connect_from_env()
    redis_client=redis.Redis(host=os.getenv('REDIS_HOST','redis'),port=int(os.getenv('REDIS_PORT','6379')),
                             password=os.getenv('REDIS_PASSWORD'),decode_responses=True)
    completed={r[0] for r in journal.execute('SELECT idx FROM results')}
    with (directory/'request-plan.jsonl').open(encoding='utf-8') as stream:
        plan=[json.loads(line) for line in stream if line.strip()]
    if len(plan)!=meta['planned_requests'] or any(t['index']!=i for i,t in enumerate(plan)):
        raise ValueError('Plan length/order mismatch')
    stop=asyncio.Event();gate=asyncio.Lock();next_request=time.monotonic();error_count=0
    flow_allowed=asyncio.Event();flow_allowed.set()
    state={**previous,'run_id':meta['run_id'],'started_at':started.isoformat(),
           'target_events':target_events,'status':'starting','completed_requests':len(completed),
           'request_budget':meta['planned_requests'],'rps_limit':rps,'workers':workers,
           'classification_monitoring':not sensor_only}
    def progress():
        state['updated_at']=datetime.now(timezone.utc).isoformat()
        temporary=progress_file.with_suffix('.tmp');temporary.write_text(json.dumps(state,indent=2));temporary.replace(progress_file)
    async def throttle():
        nonlocal next_request
        while not flow_allowed.is_set() and not stop.is_set():await asyncio.sleep(.25)
        async with gate:
            await asyncio.sleep(max(0,next_request-time.monotonic()))
            next_request=time.monotonic()+1/rps
    async def monitor():
        try:
            while not stop.is_set():
                info=await redis_client.info('memory')
                state['redis_used_bytes']=int(info['used_memory']);state['redis_rss_bytes']=int(info['used_memory_rss'])
                if not sensor_only:
                    groups=await redis_client.xinfo_groups('security.events.normalized')
                    active=next((g for g in groups if g['name']=='local-bundle-v2'),None)
                    state['local_ai_backlog']=int((active or {}).get('lag') or 0)
                    prediction_groups=await redis_client.xinfo_groups('security.predictions')
                    state['incident_backlog']=max((int(g.get('lag') or 0) for g in prediction_groups
                                                  if g['name']=='incident-engine'),default=0)
                else:
                    state['local_ai_backlog']=None;state['incident_backlog']=None
                ai_lag=state.get('local_ai_backlog') or 0;incident_lag=state.get('incident_backlog') or 0
                if ai_lag>1500 or incident_lag>200000:flow_allowed.clear()
                elif ai_lag<500 and incident_lag<150000:flow_allowed.set()
                state['observed_events']=await observed_count(connection,meta,started)
                if state['redis_rss_bytes']>3.3*1024**3 or shutil.disk_usage(directory).free<10*1024**3:
                    state['status']='paused_resource_limit';stop.set()
                elif ai_lag>10000:
                    state['status']='paused_ai_backlog';stop.set()
                elif state['observed_events']>=int(target_events*1.05):
                    state['status']='target_observed';stop.set()
                else:state['status']='collecting' if flow_allowed.is_set() else 'waiting_for_consumers'
                journal.commit();progress()
                print(json.dumps({k:state.get(k) for k in ('status','completed_requests','observed_events','local_ai_backlog','redis_rss_bytes')}),flush=True)
                try:await asyncio.wait_for(stop.wait(),timeout=15)
                except TimeoutError:pass
        except Exception as exc:
            state['status']='monitor_failed';state['error_type']=type(exc).__name__;stop.set();progress()
    async def worker(worker_id):
        nonlocal error_count
        try:
            sessions=(meta['planned_requests']+meta['session_size']-1)//meta['session_size']
            for session in range(worker_id,sessions,workers):
                if stop.is_set():break
                begin=session*meta['session_size'];end=min(begin+meta['session_size'],meta['planned_requests'])
                if all(i in completed for i in range(begin,end)):continue
                async def guard(request):
                    origin=httpx.URL(target)
                    if (request.url.scheme,request.url.host,request.url.port)!=(origin.scheme,origin.host,origin.port):
                        raise RuntimeError('Request left the lab origin')
                # Short TCP connections keep one sensor flow from containing an entire 500-request campaign.
                async with httpx.AsyncClient(base_url=target,headers={'Host':'dvwa.local','Connection':'close'},trust_env=False,
                    timeout=20,follow_redirects=True,max_redirects=5,event_hooks={'request':[guard]}) as client:
                    await login(client)
                    client.cookies.set('security','low')
                    probe=await client.get('/vulnerabilities/sqli/',params={'id':'1','Submit':'Submit'})
                    visible=re.sub(r'<[^>]*>',' ',probe.text)
                    if probe.url.path.endswith('/login.php') or not re.search(r'Security Level:\s*low',visible):
                        raise RuntimeError('Authenticated low challenge not confirmed')
                    for index in range(begin,end):
                        if request_limit and len(completed)>=request_limit:
                            state['status']='request_limit_reached';stop.set();break
                        if index in completed:continue
                        if stop.is_set():break
                        task=plan[index]
                        await throttle();before=time.perf_counter()
                        params={'ahr_scenario':task['marker']}
                        if task['method']=='GET':params.update(task['fields'])
                        response=await client.request(task['method'],task['path'],params=params,
                            data=task['fields'] if task['method']=='POST' else None)
                        valid=response.status_code<500 and not response.url.path.endswith('/login.php')
                        if not valid:error_count+=1
                        signals={'command_marker':task['marker'] in response.text if task['family']=='command_injection' else None,
                                 'sql_rows':response.text.count('First name:') if task['family']=='sqli' else None,
                                 'browser_execution_verified':False}
                        journal.execute('INSERT OR IGNORE INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(
                            index,task['marker'],task['campaign_id'],task['family'],task['label'],response.status_code,
                            datetime.now(timezone.utc).isoformat(),(time.perf_counter()-before)*1000,len(response.content),
                            hashlib.sha256(response.content).hexdigest(),json.dumps(signals),int(valid)))
                        completed.add(index);state['completed_requests']=len(completed)
                        if len(completed)%50==0:journal.commit()
                        if error_count>=20:raise RuntimeError('Too many failed responses; stopped for inspection')
        except Exception as exc:
            state['status']='worker_failed';state['error_type']=type(exc).__name__;state['worker_error']=str(exc)[:180]
            stop.set();progress()
    monitor_task=None
    try:
        progress()
        if not export_only:
            monitor_task=asyncio.create_task(monitor())
            await asyncio.gather(*(worker(i) for i in range(workers)))
            stop.set();await monitor_task
            await asyncio.sleep(8)
        journal.commit()
        events=await fetch_observed(connection,meta,started)
        report=export_rows(directory,meta,journal,events)
        state.update(status='complete' if report['real_sensor_events']>=target_events else 'partial',
                     collection_stop_reason=state['status'],export=report)
        progress();print(json.dumps(state,indent=2),flush=True)
        return state
    finally:
        stop.set()
        if monitor_task and not monitor_task.done():await monitor_task
        journal.commit();journal.close();await connection.close();await redis_client.aclose()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--requests',type=int,default=100000)
    p.add_argument('--session-size',type=int,default=500)
    p.add_argument('--seed',type=int,default=42)
    p.add_argument('--target',default='http://nginx')
    p.add_argument('--target-events',type=int,default=100000)
    p.add_argument('--rps',type=float,default=20)
    p.add_argument('--workers',type=int,default=4)
    p.add_argument('--execute',action='store_true');p.add_argument('--resume',action='store_true')
    p.add_argument('--export-only',action='store_true')
    p.add_argument('--sensor-only',action='store_true',help='Collect sensors without requiring classification workers to consume predictions')
    p.add_argument('--request-limit',type=int,help='Stop after this many journaled requests across resumes')
    args=p.parse_args()
    if not args.resume:
        meta=create_plan(args.output,args.requests,args.seed,session_size=args.session_size)
        print(json.dumps(meta,indent=2),flush=True)
    if args.execute:
        state=asyncio.run(collect(args.output,args.target,args.rps,args.workers,args.target_events,args.resume,args.export_only,args.request_limit,args.sensor_only))
        if state['status']!='complete':raise SystemExit(2)


if __name__=='__main__':main()
