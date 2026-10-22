"""Legacy Redis consumer -> HTTPS Colab scorer -> DB predictions and incident stream.

One outstanding request; errors leave messages pending and emit degraded health.
No open DB/Redis ports, no implicit local model fallback or attack on timeout.
"""
import argparse
import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
from datetime import datetime,timezone
from urllib.parse import urlsplit
import httpx
import redis.asyncio as redis
from ai.network.config import Settings
from ai.network.db import connect
from feature_engine.event_contract import decode_event,routine_navigation
from .data import sanitized_event

MODELS={'network_score':('colab-network-v2','network_detection'),
        'log_score':('colab-log-v2','log_anomaly'),
        'graph_score':('colab-graph-v2','graph_window_detection'),
        'fusion_score':('colab-fusion-v2','fusion_risk')}


def remote_event(event):
    row=sanitized_event(event)
    for key in ('label','attack_type','scenario_id','campaign_id'):row.pop(key,None)
    return row


def validate_response(events,payload):
    items=payload['items']
    if payload.get('contract')!='colab-local-v2' or len(items)!=len(events):raise ValueError('Remote batch contract mismatch')
    by_id={item['event_id']:item for item in items}
    if len(by_id)!=len(events) or set(by_id)!={e['event_id'] for e in events}:raise ValueError('Remote event identity mismatch')
    for item in items:
        if not isinstance(item.get('bundle_version'),str) or len(item['bundle_version'])>64:raise ValueError('Invalid bundle version')
        for key in MODELS:
            v=item['scores'][key]
            if isinstance(v,bool) or not isinstance(v,(int,float)) or not math.isfinite(v) or not 0<=v<=1:raise ValueError('Invalid remote score')
    return by_id


async def persist(connection,client,settings,event,item,latency,provider='colab'):
    scores={k:float(item['scores'][k]) for k in MODELS}
    version=item['bundle_version']
    async with connection.transaction():
        for key,(mid,task) in MODELS.items():
            if provider=='local':mid=mid.replace('colab-','local-')
            score=scores[key];threshold=.55 if key=='fusion_score' else .5
            await connection.execute('''INSERT INTO ahr.models(model_id,name,model_type,version,status,artifact_uri,feature_schema,training_metadata,activated_at)
                VALUES($1,$1,$3,$2,'active',$4,'{}'::jsonb,$5::jsonb,now())
                ON CONFLICT(model_id) DO UPDATE SET version=excluded.version,status='active',model_type=excluded.model_type,
                    artifact_uri=excluded.artifact_uri,training_metadata=excluded.training_metadata ''',
                mid,version,'local-bundle-v2' if provider=='local' else 'colab-remote-v2',
                'local:verified-v2-bundle' if provider=='local' else 'https:remote-ephemeral',json.dumps({'provider':provider}))
            await connection.execute('''INSERT INTO ahr.ai_predictions(prediction_id,event_id,model_id,model_version,task,score,predicted_class,risk_level,confidence,explanation)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) ON CONFLICT(prediction_id) DO NOTHING''',
                f'{mid}:{version}:{event["event_id"]}',event['event_id'],mid,version,task,score,
                'attack' if score>=threshold else 'benign','high' if score>=.8 else 'medium' if score>=threshold else 'low',
                max(score,1-score),json.dumps({'inference_batch_ms' if provider=='local' else 'remote_roundtrip_ms':latency,'provider':provider,
                                             'graph_context':'single_event_causal_v2','routine_navigation':routine_navigation(event)}))
        update={**scores,'risk_level':'high' if scores['fusion_score']>=.55 else 'low','model_versions':{provider:version}}
        await connection.execute('UPDATE ahr.events SET ai=ai || $2::jsonb WHERE event_id=$1',event['event_id'],json.dumps(update))
    # Publish once after complete base+fusion scores. Incident engine still applies local policy.
    await client.xadd(settings.predictions_stream,{'event_id':event['event_id'],'model':f'{provider}-fusion-v2',
        'fusion_score':str(scores['fusion_score']),'version':version},maxlen=100000,approximate=True)


async def service(endpoint,token_file,once=False):
    parsed=urlsplit(endpoint)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Use the exact HTTPS tunnel origin, no credentials/query')
    if parsed.path not in ('','/'):raise ValueError('Endpoint must be HTTPS origin')
    token=Path(token_file).read_text().strip()
    if len(token)<32:raise ValueError('Token file is missing/too short')
    settings=Settings.from_env();connection=await connect(settings)
    client=redis.Redis(host=settings.redis_host,port=settings.redis_port,password=settings.redis_password,decode_responses=True)
    group='colab-v2';consumer='bridge-1'
    heartbeat=Path('/tmp/colab-bridge.json')
    try:
        try:await client.xgroup_create(settings.normalized_stream,group,id='$',mkstream=True)
        except redis.ResponseError as exc:
            if 'BUSYGROUP' not in str(exc):raise
        async with httpx.AsyncClient(base_url=endpoint,headers={'Authorization':'Bearer '+token},timeout=60,trust_env=False) as http:
            failures=0
            while True:
                # Reclaim own pending first; do not discard on Colab timeout.
                records=await client.xreadgroup(group,consumer,{settings.normalized_stream:'0'},count=32)
                if not any(messages for _,messages in records):
                    records=await client.xreadgroup(group,consumer,{settings.normalized_stream:'>'},count=32,block=5000)
                messages=[(sid,json.loads(fields['payload'])) for _,batch in records for sid,fields in batch]
                if not messages:
                    heartbeat.write_text(json.dumps({'status':'idle','updated':datetime.now(timezone.utc).isoformat()}))
                    if once:break
                    continue
                events=[decode_event(e) for _,e in messages]
                try:
                    start=__import__('time').perf_counter()
                    response=await http.post('/score',json={'events':[remote_event(e) for e in events]})
                    response.raise_for_status();result=validate_response(events,response.json())
                    elapsed=(__import__('time').perf_counter()-start)*1000
                    for (sid,_),event in zip(messages,events):
                        await persist(connection,client,settings,event,result[event['event_id']],elapsed)
                        await client.xack(settings.normalized_stream,group,sid)
                    failures=0
                    heartbeat.write_text(json.dumps({'status':'running','updated':datetime.now(timezone.utc).isoformat(),'events':len(events)}))
                    if once:break
                except (httpx.HTTPError,ValueError,KeyError) as exc:
                    failures+=1
                    heartbeat.write_text(json.dumps({'status':'degraded','reason':type(exc).__name__,
                        'updated':datetime.now(timezone.utc).isoformat(),'pending_preserved':True}))
                    if once or failures>=3:raise RuntimeError('Colab unavailable. Pending messages retained; no attack score synthesized.') from None
                    await asyncio.sleep(min(10,failures*3))
    finally:await connection.close();await client.aclose()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--endpoint',default=os.getenv('COLAB_ENDPOINT'))
    p.add_argument('--token-file',default='/run/secrets/colab_token');p.add_argument('--once',action='store_true')
    a=p.parse_args()
    if not a.endpoint:p.error('Set COLAB_ENDPOINT to your current HTTPS Colab tunnel')
    asyncio.run(service(a.endpoint,a.token_file,a.once))
