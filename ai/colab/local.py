"""Run the verified Colab bundle on local CPU using the existing persistence path."""
import asyncio
import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone

import redis.asyncio as redis
from ai.network.config import Settings
from ai.network.db import connect
from feature_engine.event_contract import decode_event
from .bridge import persist, validate_response, remote_event
from .scorer import BundleScorer


async def service():
    scorer = BundleScorer(os.getenv('MODEL_BUNDLE_DIR', '/models'), device='cpu')
    settings = Settings.from_env()
    connection = await connect(settings)
    client = redis.Redis(host=settings.redis_host, port=settings.redis_port,
                         password=settings.redis_password, decode_responses=True)
    group, consumer = 'local-bundle-v2', 'local-1'
    heartbeat = Path('/tmp/local-bundle.json')
    try:
        try: await client.xgroup_create(settings.normalized_stream, group, id='$', mkstream=True)
        except redis.ResponseError as exc:
            if 'BUSYGROUP' not in str(exc): raise
        while True:
            records = await client.xreadgroup(group, consumer, {settings.normalized_stream:'0'}, count=32)
            if not any(batch for _,batch in records):
                records = await client.xreadgroup(group, consumer, {settings.normalized_stream:'>'}, count=32, block=5000)
            messages = [(sid,decode_event(json.loads(fields['payload']))) for _,batch in records for sid,fields in batch]
            if messages:
                started = time.perf_counter()
                events = [e for _,e in messages]
                items = scorer.score([remote_event(e) for e in events])
                by_id = validate_response(events, {'contract':'colab-local-v2','items':items})
                elapsed = (time.perf_counter()-started)*1000
                for sid,event in messages:
                    await persist(connection,client,settings,event,by_id[event['event_id']],elapsed,provider='local')
                    await client.xack(settings.normalized_stream,group,sid)
            heartbeat.write_text(json.dumps({'status':'running' if messages else 'idle',
                'updated':datetime.now(timezone.utc).isoformat(),'bundle_version':scorer.version,'events':len(messages)}))
    finally:
        await connection.close(); await client.aclose()


if __name__ == '__main__':
    asyncio.run(service())
