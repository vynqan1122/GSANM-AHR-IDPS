"""Native CIC flow benchmark. NEVER deploy these artifacts as network-v1.

Chunked per-class reservoir; no arbitrary zero mapping of missing DVWA telemetry.
"""
import argparse
import hashlib
import json
import time
from collections import Counter
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from .train import fit_xgb,xpred,metrics
from .visuals import dataset_figures,history_figures,evaluation_figures

DROP={'flow id','source ip','src ip','destination ip','dst ip','timestamp','label'}


def benchmark(folder,output,cap_per_class=150000,device='cuda',rounds=400):
    if cap_per_class<100:raise ValueError('cap_per_class must be >=100')
    files=sorted(Path(folder).rglob('*.csv'))
    if not files:raise ValueError('No extracted CSV found. Download/extract dataset before training')
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    if (out/'report.json').exists():raise ValueError('Use a new output directory for each benchmark run')
    rng=np.random.default_rng(42); reservoirs={};features=None;counts=Counter();provenance=[]
    rows_read=0;valid_rows=0;raw_counts=Counter();missing=Counter()
    started=time.perf_counter()
    for file in files:
        print('Reading / preprocessing:',file.name,flush=True)
        h=hashlib.sha256()
        with file.open('rb') as f:
            for chunk in iter(lambda:f.read(2**20),b''):h.update(chunk)
        provenance.append({'file':file.name,'sha256':h.hexdigest(),'bytes':file.stat().st_size})
        for chunk in pd.read_csv(file,chunksize=50000,encoding_errors='replace',low_memory=False):
            rows_read+=len(chunk)
            chunk.columns=[c.strip().lower() for c in chunk.columns]
            if 'label' not in chunk:raise ValueError(f'Label column missing in {file.name}')
            # Duplicate column names made by CIC exporter are explicitly dropped, not interpreted as two sensors.
            chunk=chunk.loc[:,~chunk.columns.duplicated()]
            labels=chunk['label'].astype(str).str.strip()
            raw_counts.update(labels)
            candidates=chunk.drop(columns=[c for c in chunk if c in DROP],errors='ignore')
            numeric=candidates.apply(pd.to_numeric,errors='coerce').replace([np.inf,-np.inf],np.nan)
            if features is None:features=[c for c in numeric if numeric[c].notna().mean()>.9]
            if len(features)<5 or any(c not in numeric for c in features):raise ValueError('Incompatible CIC feature schema across files')
            missing.update({c:int(numeric[c].isna().sum()) for c in features})
            valid=(numeric[features].notna().mean(axis=1)>.9)&(~labels.str.lower().isin(['label','nan','']))
            valid_rows+=int(valid.sum())
            numeric=numeric.loc[valid,features].fillna(0).astype('float32')
            numeric['__label']=labels.loc[valid].values
            numeric['__priority']=rng.random(len(numeric))
            for label,part in numeric.groupby('__label',sort=False):
                counts[label]+=len(part)
                combined=pd.concat([reservoirs[label],part],ignore_index=True) if label in reservoirs else part
                reservoirs[label]=combined.nsmallest(cap_per_class,'__priority')
    if not reservoirs:raise ValueError('No valid rows after preprocessing')
    dataset=pd.concat(reservoirs.values(),ignore_index=True).drop(columns='__priority')
    reservoir_rows=len(dataset)
    # Collapse exact feature duplicates BEFORE random split. Conflicting labels are rejected.
    fp=pd.util.hash_pandas_object(dataset[features],index=False)
    label_count=dataset.assign(__fp=fp).groupby('__fp')['__label'].nunique()
    conflicts=set(label_count[label_count>1].index)
    conflict_rows=int(fp.isin(conflicts).sum())
    dataset=dataset.loc[~fp.isin(conflicts)].drop_duplicates(subset=features)
    y=(~dataset['__label'].str.lower().isin(['benign','normal','0'])).astype('int32').to_numpy()
    x=dataset[features].to_numpy(np.float32)
    if len(set(y))<2:raise ValueError('Need benign and attack rows')
    idx=np.arange(len(y));tr,rest=train_test_split(idx,test_size=.4,stratify=y,random_state=42)
    va,te=train_test_split(rest,test_size=.5,stratify=y[rest],random_state=42)
    # Native CIC names can contain symbols forbidden by XGBoost, use stable positional names.
    names=[f'cic_{i:03}' for i in range(len(features))]
    splits={'train':tr,'validation':va,'test':te}
    stages={'CSV rows read':rows_read,'valid rows before sampling':valid_rows,
            'per-class reservoir rows':reservoir_rows,'conflicting rows excluded':conflict_rows,
            'exact duplicate rows excluded':reservoir_rows-conflict_rows-len(dataset),
            'final selected rows':len(dataset)}
    print('Saving dataset review / training-only EDA...',flush=True)
    dataset_figures(out,x,y,splits,features,stages,raw_labels=dict(raw_counts),
                    selected_labels={str(k):int(v) for k,v in dataset['__label'].value_counts().items()},
                    missing=dict(missing))
    history={}
    print(f'TRAIN NETWORK XGBOOST: train={len(tr):,}, validation={len(va):,}, test={len(te):,}; {rounds} rounds on {device}',flush=True)
    model=fit_xgb(x[tr],y[tr],device,rounds,names,validation=(x[va],y[va]),history=history)
    model.save_model(out/'CIC_BENCHMARK_ONLY_NOT_RUNTIME.json')
    validation_scores=xpred(model,x[va]);test_scores=xpred(model,x[te])
    history_figures(out,{'network_xgboost':history})
    test_result=dict(model='network_xgboost',threshold=.5,**metrics(y[te],test_scores))
    evaluation_figures(out,y[te],{'network_xgboost':test_scores},{'network_xgboost':.5},
                        [test_result],booster=model,feature_labels=dict(zip(names,features)))
    pd.DataFrame({'row_index':te,'label':y[te],'score':test_scores}).to_csv(out/'test-predictions.csv',index=False)
    pd.DataFrame({'row_index':np.concatenate((tr,va,te)),
                  'split':np.repeat(['train','validation','test'],[len(tr),len(va),len(te)])}).to_csv(out/'split-indices.csv',index=False)
    report={'contract':'CIC-native-benchmark-only','deployable':False,'feature_map':dict(zip(names,features)),
            'input_counts':dict(counts),'selected_rows':len(y),'conflicting_fingerprints_excluded':len(conflicts),
            'validation':metrics(y[va],validation_scores), 'test':metrics(y[te],test_scores),
            'preprocessing':stages,'split_counts':{k:len(ix) for k,ix in splits.items()},
            'figures_index':'figures-index.json','training_history':'training-history.json',
            'split':'exact-deduplicated stratified rows; correlated/near-duplicate flows can still make results optimistic',
            'wall_seconds':time.perf_counter()-started,'provenance':provenance,
            'device_actual':json.loads(model.save_config())['learner']['generic_param']['device']}
    (out/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input-dir',required=True);p.add_argument('--output',required=True)
    p.add_argument('--cap-per-class',type=int,default=150000);p.add_argument('--device',choices=['cuda','cpu'],default='cuda')
    p.add_argument('--rounds',type=int,default=400);a=p.parse_args()
    print(json.dumps(benchmark(a.input_dir,a.output,a.cap_per_class,a.device,a.rounds),indent=2))
