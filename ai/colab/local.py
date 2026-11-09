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
from .bridge import persist_batch, validate_response, remote_event
from .scorer import BundleScorer


async def service():
    scorer = BundleScorer(os.getenv('MODEL_BUNDLE_DIR', '/models'), device='cpu')
    settings = Settings.from_env()
    connection = await connect(settings)
    client = redis.Redis(host=settings.redis_host, port=settings.redis_port,
                         password=settings.redis_password, decode_responses=True)
    group, consumer = 'local-bundle-v2', 'local-1'
    heartbeat = Path('/tmp/local-bundle.json')
    registered=False
    try:
        try: await client.xgroup_create(settings.normalized_stream, group, id='$', mkstream=True)
        except redis.ResponseError as exc:
            if 'BUSYGROUP' not in str(exc): raise
        while True:
            policy = dict(await connection.fetchrow('SELECT enabled,fusion_threshold,revision FROM ahr.ai_runtime_policy WHERE singleton'))
            if not policy['enabled']:
                state = {'status': 'paused', 'updated': datetime.now(timezone.utc).isoformat(),
                         'bundle_version': scorer.version, 'events': 0, **policy}
                heartbeat.write_text(json.dumps(state))
                await client.set('ahr:ai-bundle:runtime', json.dumps(state), ex=90)
                await asyncio.sleep(1)
                continue
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
                await persist_batch(connection,client,settings,events,by_id,elapsed,
                                    provider='local',register_models=not registered,
                                    fusion_threshold=policy['fusion_threshold'])
                registered=True
                await client.xack(settings.normalized_stream,group,*(sid for sid,_ in messages))
            state = {'status':'running' if messages else 'idle',
                'updated':datetime.now(timezone.utc).isoformat(),'bundle_version':scorer.version,
                'events':len(messages), **policy}
            heartbeat.write_text(json.dumps(state))
            await client.set('ahr:ai-bundle:runtime', json.dumps(state), ex=90)
    finally:
        await connection.close(); await client.aclose()


if __name__ == '__main__':
    asyncio.run(service())
