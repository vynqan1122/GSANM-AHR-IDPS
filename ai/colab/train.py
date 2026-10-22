"""Leakage-aware offline trainer. Four deployable artifacts from labeled DVWA.

Network/Fusion: XGBoost CUDA. Log/Graph: current sklearn CPU implementations.
No GPU memory reservation tricks. Public flow data is a SEPARATE benchmark.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest,RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupKFold
from sklearn.metrics import precision_score,recall_score,f1_score,confusion_matrix,roc_auc_score,average_precision_score

from feature_engine.event_contract import learning_event
from feature_engine.network_features import build_network_features,feature_names
from ai.logs.minilm import MiniLMEmbedder
from ai.logs.representation import normalized_log_text
from ai.graph.graphsage import GraphSAGEWindowClassifier
from ai.fusion.scoring import score_components,weighted_baseline
from ai.fusion.dataset import feature_vector,FEATURE_NAMES
from .data import load_events,split_groups,graph_for


def metrics(y,s,threshold=.5):
    p=np.asarray(s)>=threshold
    tn,fp,fn,tp=confusion_matrix(y,p,labels=[0,1]).ravel()
    return dict(tp=int(tp),fp=int(fp),tn=int(tn),fn=int(fn),
                precision=float(precision_score(y,p,zero_division=0)),recall=float(recall_score(y,p,zero_division=0)),
                f1=float(f1_score(y,p,zero_division=0)),fpr=float(fp/max(1,tn+fp)),
                roc_auc=float(roc_auc_score(y,s)) if len(set(y))==2 else None,
                pr_auc=float(average_precision_score(y,s)) if len(set(y))==2 else None)


def fit_xgb(x,y,device,rounds=120,names=None,validation=None,history=None):
    d=xgb.QuantileDMatrix(x,label=y,feature_names=names,max_bin=256)
    evals=[(d,'train')]
    if validation is not None:
        vx,vy=validation
        vd=xgb.QuantileDMatrix(vx,label=vy,feature_names=names,max_bin=256,ref=d)
        evals.append((vd,'validation'))
    m=xgb.train({'objective':'binary:logistic','eval_metric':['logloss','error','auc'],'tree_method':'hist',
                 'device':device,'max_depth':5,'max_bin':256,'eta':.08,'nthread':4,
                 'subsample':.9,'colsample_bytree':.9,'seed':42},d,num_boost_round=rounds,
                 evals=evals,evals_result=history,verbose_eval=25 if history is not None else False)
    actual=json.loads(m.save_config())['learner']['generic_param']['device']
    if device.startswith('cuda') and not actual.startswith('cuda'):
        raise RuntimeError('CUDA requested but XGBoost fell back to CPU; choose L4 runtime/driver first')
    return m


def xpred(m,x):
    return m.predict(xgb.DMatrix(x,feature_names=m.feature_names))


def log_scores(model,z):
    probability=model['classifier'].predict_proba(z)[:,1]
    anomaly=np.clip(.5-model['iforest'].decision_function(z),0,1)
    # New artifact stores calibration weight; original artifact defaults to maximum.
    alpha=model.get('anomaly_weight',1.)
    return np.maximum(probability,alpha*anomaly)


def graph_prob(model,g):
    return np.array([model.predict_proba(item)[0] for item in g],dtype=np.float32)


def fit_base(events,y,device,rounds,validation=None,histories=None,prefix='final'):
    x=np.array([build_network_features(learning_event(e)) for e in events],np.float32)
    embed=MiniLMEmbedder()
    z=embed.encode([normalized_log_text(e) for e in events])
    graphs=[graph_for(e) for e in events]
    validation_xy=None if validation is None else (
        np.array([build_network_features(learning_event(e)) for e in validation[0]],np.float32),validation[1])
    history={}
    print(f'[{prefix}] Network XGBoost: {len(events):,} rows, {rounds} rounds, {device}',flush=True)
    net=fit_xgb(x,y,device,rounds,feature_names(),validation_xy,history)
    clf=make_pipeline(StandardScaler(),MLPClassifier(hidden_layer_sizes=(32,),max_iter=250,random_state=42))
    clf.fit(z,y)
    forest=IsolationForest(n_estimators=80,max_samples=min(1024,int(sum(y==0))),n_jobs=4,random_state=42)
    forest.fit(z[y==0])
    log={'classifier':clf,'iforest':forest,'version':'log-v1','anomaly_weight':.5,
         'representation':'hashing384-redacted-v2'}
    graph=GraphSAGEWindowClassifier();graph.fit(graphs,y)
    if histories is not None:
        histories[prefix+'/network']=history
        histories[prefix+'/log_mlp']={'train':{'loss':list(clf[-1].loss_curve_)}}
        histories[prefix+'/graph_mlp']={'train':{'loss':list(graph.graph_model[-1].loss_curve_)}}
        histories[prefix+'/graph_baseline_mlp']={'train':{'loss':list(graph.baseline_model[-1].loss_curve_)}}
    return {'network':net,'log':log,'graph':graph}


def predict_base(model,events):
    x=np.array([build_network_features(learning_event(e)) for e in events],np.float32)
    z=MiniLMEmbedder().encode([normalized_log_text(e) for e in events])
    return np.column_stack((xpred(model['network'],x),log_scores(model['log'],z),graph_prob(model['graph'],[graph_for(e) for e in events])))


def fusion_matrix(events,scores):
    vectors=[];weighted=[];rules=[]
    for e,score in zip(events,scores):
        row=learning_event(e)
        row['ai']=dict(zip(('network_score','log_score','graph_score'),map(float,score)))
        comp=score_components(row,0)
        rules.append(float(comp['rule_score'] or 0));weighted.append(weighted_baseline(comp).fusion_score)
        vectors.append(feature_vector(row,0))
    return np.array(vectors,np.float32),np.array(weighted),np.array(rules)


def write_report(out,results,predictions):
    (out/'comparison.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    with (out/'comparison.csv').open('w',newline='',encoding='utf-8') as f:
        fields=['model','threshold','tp','fp','tn','fn','precision','recall','f1','fpr','roc_auc','pr_auc']
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerows(results)
    with (out/'predictions.jsonl').open('w',encoding='utf-8') as f:
        for row in predictions:f.write(json.dumps(row)+'\n')
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig,axes=plt.subplots(1,2,figsize=(13,5),layout='constrained')
        labels=[r['model'] for r in results]
        axes[0].barh(labels,[r['f1'] for r in results]);axes[0].set(xlim=(0,1),title='Held-out test F1')
        axes[1].barh(labels,[r['fpr'] for r in results],color='#cc5533');axes[1].set(xlim=(0,1),title='False positive rate')
        fig.savefig(out/'comparison.png',dpi=180);plt.close(fig)
    except ImportError:pass


def train(input_path,output,device='cuda',rounds=120,seed=42,max_events=500000):
    started=time.perf_counter();out=Path(output);out.mkdir(parents=True,exist_ok=True)
    if (out/'manifest.json').exists():raise ValueError('Output already contains a run; use a new run directory')
    rows,excluded=load_events(input_path,max_events)
    splits,y=split_groups(rows,seed)
    tr=splits['train'];va=splits['validation'];te=splits['test']
    from .visuals import dataset_figures,history_figures,evaluation_figures
    print('Preprocessing / training-only EDA...',flush=True)
    all_x=np.array([build_network_features(learning_event(e)) for e in rows],np.float32)
    from collections import Counter
    dataset_figures(out,all_x,y,splits,feature_names(),
        {'loaded_labeled_events':len(rows),'excluded_records':sum(excluded.values()),
         'train':len(tr),'validation':len(va),'test':len(te)},
        raw_labels=dict(Counter(r.get('attack_type') or r['label'] for r in rows)))
    del all_x
    histories={}
    train_rows=[rows[i] for i in tr];train_y=y[tr];groups=np.array([r['group_id'] for r in train_rows])
    validation=[rows[i] for i in va];test=[rows[i] for i in te]
    # OOF meta-training: base models have never fitted their held-out fold.
    oof=np.zeros((len(tr),3),np.float32)
    fold_ids=np.full(len(tr),-1,int)
    for fold,(a,b) in enumerate(GroupKFold(n_splits=3).split(train_rows,train_y,groups)):
        if len(set(train_y[a]))<2:raise ValueError('OOF fold has a single class; collect more groups')
        fold_models=fit_base([train_rows[i] for i in a],train_y[a],device,rounds,
                             histories=histories,prefix=f'oof_{fold+1}')
        oof[b]=predict_base(fold_models,[train_rows[i] for i in b]);fold_ids[b]=fold
        del fold_models
        __import__('gc').collect()
    meta_x,_,_=fusion_matrix(train_rows,oof)
    final=fit_base(train_rows,train_y,device,rounds,validation=(validation,y[va]),histories=histories)
    val_base=predict_base(final,validation);test_base=predict_base(final,test)
    vx,vw,vr=fusion_matrix(validation,val_base);tx,tw,rr=fusion_matrix(test,test_base)
    histories['final/fusion']={}
    print('Training Fusion on group OOF base scores...',flush=True)
    fusion=fit_xgb(meta_x,train_y,device,rounds,list(FEATURE_NAMES),
                   validation=(vx,y[va]),history=histories['final/fusion'])
    val_scores={'rule_only':vr,'network':val_base[:,0],'log':val_base[:,1],'graph':val_base[:,2],
                'weighted_hybrid':vw,'fusion_oof':xpred(fusion,vx)}
    test_scores={'rule_only':rr,'network':test_base[:,0],'log':test_base[:,1],'graph':test_base[:,2],
                 'weighted_hybrid':tw,'fusion_oof':xpred(fusion,tx)}
    # Extra algorithms use the same train/test network vectors, never fit on test.
    nx=np.array([build_network_features(learning_event(e)) for e in train_rows],np.float32)
    nv=np.array([build_network_features(learning_event(e)) for e in validation],np.float32)
    nt=np.array([build_network_features(learning_event(e)) for e in test],np.float32)
    for name,baseline in [('logistic_regression',make_pipeline(StandardScaler(),LogisticRegression(max_iter=500,class_weight='balanced'))),
                          ('random_forest',RandomForestClassifier(n_estimators=100,max_depth=12,n_jobs=4,random_state=seed))]:
        baseline.fit(nx,train_y);val_scores[name]=baseline.predict_proba(nv)[:,1];test_scores[name]=baseline.predict_proba(nt)[:,1]
        joblib.dump(baseline,out/(name+'.joblib'))
    # Fixed decision threshold parity with existing services. Threshold tuning is future work.
    thresholds={name:(.55 if name in {'fusion_oof','weighted_hybrid'} else .5) for name in test_scores}
    result=[dict(model=name,threshold=thresholds[name],**metrics(y[te],scores,thresholds[name])) for name,scores in test_scores.items()]
    predictions=[dict(event_id=r['event_id'],group_id=r['group_id'],label=r['label'],split='test',
                      scores={n:float(v[j]) for n,v in test_scores.items()}) for j,r in enumerate(test)]
    final['network'].save_model(out/'network-xgboost.json')
    joblib.dump(final['log'],out/'log-ai.joblib');final['graph'].save(str(out/'graphsage-security-event.joblib'))
    fusion.save_model(out/'fusion-hybrid-xgboost.json')
    for filename,model_name in [('network-xgboost.json','network'),('log-ai.joblib','log'),
                                ('graphsage-security-event.joblib','graph'),('fusion-hybrid-xgboost.json','fusion_oof')]:
        m=next(r for r in result if r['model']==model_name)
        Path(out/filename).with_suffix('.metadata.json').write_text(json.dumps({
            'contract':'colab-local-v2','representation':'redacted-v2','graph_context':'single_event_causal_v2',
            'feature_names':feature_names() if model_name=='network' else None,
            'evaluation_split':'heldout_groups','metrics':m,'device_requested':device,
            'runtime_requires_colab_bridge_or_v2_bundle_scorer':True},indent=2),encoding='utf-8')
    write_report(out,result,predictions)
    validation_result=[dict(model=name,threshold=thresholds[name],**metrics(y[va],scores,thresholds[name]))
                       for name,scores in val_scores.items()]
    (out/'validation-metrics.json').write_text(json.dumps(validation_result,indent=2),encoding='utf-8')
    print('Exporting real training history and evaluation figures...',flush=True)
    history_figures(out,histories)
    evaluation_figures(out,y[te],test_scores,thresholds,result,booster=final['network'])
    manifest={'contract':'colab-local-v2','input_sha256':hashlib.sha256(Path(input_path).read_bytes()).hexdigest(),
              'counts':{n:len(ix) for n,ix in splits.items()},'excluded':excluded,'seed':seed,
              'split_groups':{n:sorted({rows[i]['group_id'] for i in ix}) for n,ix in splits.items()},
              'oof_folds':{train_rows[i]['event_id']:int(fold_ids[i]) for i in range(len(tr))},
              'training_wall_seconds':time.perf_counter()-started,'device_requested':device,
              'deployment':'Use v2 scorer/Colab bridge; not a blind overwrite of old window-model artifacts',
              'source':'DVWA_local_not_CIC','files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()}}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    return manifest


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--output',required=True)
    p.add_argument('--device',choices=['cpu','cuda'],default='cuda');p.add_argument('--rounds',type=int,default=120)
    p.add_argument('--max-events',type=int,default=500000)
    a=p.parse_args();print(json.dumps(train(a.input,a.output,a.device,a.rounds,max_events=a.max_events),indent=2))
