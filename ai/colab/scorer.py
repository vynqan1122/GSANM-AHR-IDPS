"""Same trained v2 event contract on Colab and local CPU fallback."""
import hashlib
import json
from pathlib import Path
import joblib
import numpy as np
import xgboost as xgb
from feature_engine.event_contract import learning_event,routine_navigation
from .train import predict_base,fusion_matrix,xpred


class BundleScorer:
    def __init__(self,folder,device='cuda'):
        folder=Path(folder)
        manifest=json.loads((folder/'manifest.json').read_text())
        if manifest.get('contract')!='colab-local-v2':raise ValueError('Unsupported model contract')
        for name,expected in manifest['files'].items():
            p=folder/name
            if Path(name).name!=name or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
                raise ValueError('Bundle checksum mismatch')
        network=xgb.Booster();network.load_model(folder/'network-xgboost.json');network.set_param({'device':device})
        fusion=xgb.Booster();fusion.load_model(folder/'fusion-hybrid-xgboost.json');fusion.set_param({'device':device})
        # Only load trusted bundle created by our notebook; joblib is executable Python serialization.
        self.models={'network':network,'log':joblib.load(folder/'log-ai.joblib'),
                     'graph':joblib.load(folder/'graphsage-security-event.joblib')}
        self.fusion=fusion
        self.version=hashlib.sha256((folder/'manifest.json').read_bytes()).hexdigest()[:16]

    def score(self,events):
        if not events:return []
        base=predict_base(self.models,events);x,weighted,rules=fusion_matrix(events,base)
        fusion=xpred(self.fusion,x)
        items=[]
        for i,e in enumerate(events):
            score={key:float(value) for key,value in zip(('network_score','log_score','graph_score'),base[i])}
            score.update(fusion_score=float(fusion[i]),rule_score=float(rules[i]),weighted_score=float(weighted[i]))
            if not all(np.isfinite(v) and 0<=v<=1 for v in score.values()):raise ValueError('Invalid model output')
            items.append({'event_id':e['event_id'],'scores':score,'bundle_version':self.version,
                          'routine_navigation':routine_navigation(e),'graph_context':'single_event_causal_v2'})
        return items
