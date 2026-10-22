"""Training/export integration checks on small, explicitly synthetic test data."""
import hashlib
import json

import numpy as np
import pandas as pd
from sklearn.metrics import log_loss

from ai.colab.train import fit_xgb,xpred
from ai.colab.public_benchmark import benchmark


def test_validation_history_matches_actual_final_predictions():
    rng=np.random.default_rng(8)
    x=rng.normal(size=(100,6)).astype('float32')
    y=(x[:,0]+x[:,1]>0).astype('int32')
    history={}
    model=fit_xgb(x[:70],y[:70],'cpu',rounds=4,names=[f'f{i}' for i in range(6)],
                  validation=(x[70:],y[70:]),history=history)
    assert set(history)=={'train','validation'}
    assert len(history['validation']['logloss'])==4
    assert abs(history['validation']['logloss'][-1]-log_loss(y[70:],xpred(model,x[70:])))<1e-6


def test_csv_training_preprocessing_figures_and_exports(tmp_path):
    rng=np.random.default_rng(44)
    values=rng.normal(size=(160,6))
    labels=np.where(values[:,0]>0,'Web Attack','BENIGN')
    frame=pd.DataFrame(values,columns=[f'feature{i}' for i in range(6)])
    frame['Label']=labels
    # One exact same-label duplicate, one conflicting feature fingerprint,
    # one unusable row and a row containing one missing cell (>90% rule rejects it).
    conflict=frame.iloc[[1]].copy()
    conflict['Label']='Web Attack' if conflict['Label'].iloc[0]=='BENIGN' else 'BENIGN'
    invalid=pd.DataFrame([{**{f'feature{i}':np.nan for i in range(6)},'Label':'BENIGN'}])
    data=pd.concat([frame,frame.iloc[[0]],conflict,invalid],ignore_index=True)
    source=tmp_path/'source';source.mkdir()
    data.to_csv(source/'fixture.csv',index=False)
    out=tmp_path/'run'
    report=benchmark(source,out,cap_per_class=100,device='cpu',rounds=3)
    assert report['preprocessing']['CSV rows read']==163
    assert report['preprocessing']['valid rows before sampling']==162
    assert report['preprocessing']['conflicting rows excluded']==2
    assert report['preprocessing']['exact duplicate rows excluded']==1
    assert report['selected_rows']==159
    assert report['deployable'] is False
    history=json.loads((out/'training-history.json').read_text())['network_xgboost']
    assert len(history['train']['logloss'])==3
    assert len(history['validation']['logloss'])==3
    predicted=pd.read_csv(out/'test-predictions.csv')
    assert len(predicted)==report['split_counts']['test']
    assert abs(report['test']['fpr']-sum((predicted.label==0)&(predicted.score>=.5))/sum(predicted.label==0))<1e-10
    splits=pd.read_csv(out/'split-indices.csv')
    assert not splits.row_index.duplicated().any()
    assert len(splits)==159
    index=json.loads((out/'figures-index.json').read_text())
    expected={'01_preprocessing','02_class_distribution','03_split_counts','04_feature_correlation',
              '05_feature_distributions','06_missing_values','loss_network_xgboost',
              'learning_network_xgboost','cm_network_xgboost','08_roc_pr','09_calibration'}
    assert expected <= {r['name'] for r in index}
    for item in index:
        for rel,digest in item['files'].items():
            assert hashlib.sha256((out/rel).read_bytes()).hexdigest()==digest
            if rel.endswith('.png'):assert (out/rel).read_bytes().startswith(b'\x89PNG')
