"""Optional Colab inference endpoint. Authenticated, bounded, no DB secrets."""
import asyncio
import hmac
import json
import os
import time
from fastapi import FastAPI,Request,HTTPException
from .scorer import BundleScorer
from .data import sanitized_event


def create_app(folder,token,device='cuda',scorer=None):
    if not token or len(token)<32:raise ValueError('Use a random >=32-character inference token')
    model=scorer or BundleScorer(folder,device)
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    lock=asyncio.Semaphore(1)
    @app.get('/health')
    def health():return {'ready':True,'contract':'colab-local-v2'}
    @app.post('/score')
    async def score(request:Request):
        auth=request.headers.get('authorization','')
        if not hmac.compare_digest(auth,'Bearer '+token):raise HTTPException(401,'unauthorized')
        if lock.locked():raise HTTPException(429,'GPU scorer busy; retry later')
        data=bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data)>1024*1024:raise HTTPException(413,'payload too large')
        try:
            payload=json.loads(data)
            events=payload['events']
            if not isinstance(events,list) or not 1<=len(events)<=128:raise ValueError('events count')
            if any(not isinstance(e,dict) or not isinstance(e.get('event_id'),str) or not e['event_id'] or len(e['event_id'])>256 for e in events):raise ValueError('event_id')
            events=[sanitized_event(e) for e in events]
            # Defense in depth: inference never accepts experimental labels/groups as inputs.
            for event in events:
                for key in ('label','attack_type','scenario_id','campaign_id'):
                    event.pop(key,None)
        except (ValueError,KeyError,TypeError):raise HTTPException(422,'invalid canonical event batch') from None
        async with lock:
            started=time.perf_counter()
            result=await asyncio.to_thread(model.score,events)
        return {'contract':'colab-local-v2','items':result,'server_batch_ms':(time.perf_counter()-started)*1000}
    return app
