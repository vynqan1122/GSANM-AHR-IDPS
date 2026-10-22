from __future__ import annotations
import hashlib
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit,parse_qsl,urlencode

import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from feature_engine.event_contract import decode_event,learning_event,http_details,operational_path


def load_events(path,max_events=500000,exclude_conflicts=False):
    rows=[]; ids={}; conflicts=set(); removed=Counter()
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            if not line.strip():continue
            row=decode_event(json.loads(line))
            if row.get('label') not in {'benign','attack'}:
                removed['unlabelled']+=1;continue
            if operational_path(row) and row['label']=='attack':
                # Exclude bad historical labels; do not silently relabel them as benign.
                removed['attack_label_on_operational_url']+=1;continue
            group=row.get('campaign_id') or row.get('scenario_id')
            if not group:raise ValueError('Missing scenario_id/campaign_id: cannot split independent sessions')
            eid=row.get('event_id')
            if not eid:raise ValueError('Missing stable event_id')
            if eid in ids:
                if ids[eid]['label']!=row['label']:conflicts.add(eid)
                removed['duplicate_event_id']+=1;continue
            raw=row.get('raw_event') or {}
            if not row.get('http'):row['http']=http_details(row)
            row['group_id']=str(group)
            # Keep groups in evaluation metadata only; learning_event strips them.
            ids[eid]=row;rows.append(row)
            if len(rows)>max_events:raise ValueError('max_events exceeded: increase explicitly, never truncate silently')
    if conflicts:
        if not exclude_conflicts:raise ValueError(f'{len(conflicts)} conflicting event labels; review dataset first or explicitly quarantine/exclude')
        rows=[r for r in rows if r['event_id'] not in conflicts]
        removed['conflicting_event_ids_excluded']=len(conflicts)
    if not rows:raise ValueError('No labeled telemetry')
    return rows,dict(removed)


def split_groups(rows,seed=42):
    y=np.array([r['label']=='attack' for r in rows],dtype=np.int32)
    groups=np.array([r['group_id'] for r in rows]); all_idx=np.arange(len(rows))
    if len(set(groups))<10:raise ValueError('Need >=10 independent scenario/campaign groups')
    for attempt in range(40):
        tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=seed+attempt).split(all_idx,y,groups))
        va0,te0=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=seed+100+attempt).split(rest,y[rest],groups[rest]))
        va,te=rest[va0],rest[te0]
        if all(len(np.unique(y[ix]))==2 for ix in (tr,va,te)):
            return {'train':tr,'validation':va,'test':te},y
    raise ValueError('Cannot produce group-disjoint two-class train/val/test. Collect more benign/attack groups.')


def graph_for(event):
    # Shared live/Colab contract: context is the current event, no future samples.
    from ai.graph.graph_builder import build_graphs
    return build_graphs([learning_event(event)],30)[0]


def sanitized_event(event):
    """Allowlist for private Colab export/API; credentials/raw bodies never uploaded."""
    e=learning_event(event)
    out={k:e.get(k) for k in ('event_id','timestamp','source','event_type','category','protocol',
                              'src_ip','dst_ip','src_port','dst_port','severity','http','network','rule')}
    h=out.get('http') or {}
    h={k:h.get(k) for k in ('method','uri','status','request_length','response_length')}
    h['uri']=__import__('feature_engine.event_contract',fromlist=['clean_uri']).clean_uri(h.get('uri',''))
    out['http']=h
    # Graph context retains only role/name, never container IDs, command line, file contents.
    for key in ('container','process'):
        obj=e.get(key) or {}
        out[key]={k:obj[k] for k in ('name','parent_name','image') if obj.get(k)} or None
    rule=out.get('rule')
    if isinstance(rule,dict):
        out['rule']={k:rule[k] for k in ('rule_id','name','category','confidence','engine') if k in rule}
    out['raw_event']={}
    for key in ('scenario_id','campaign_id','label','attack_type'):
        if key in event:out[key]=event[key]
    return out
