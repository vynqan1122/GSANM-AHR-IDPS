from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
import xgboost as xgb

from feature_engine.versioning import FEATURES_VERSION, assert_no_feature_leakage

from .config import Settings
from .dataset import load_labeled_rows, schema, to_matrix
from .db import connect
from .registry import register_model


def metrics(y_true: np.ndarray, probabilities: np.ndarray) -> dict[str, float]:
    predictions = (probabilities >= 0.5).astype(np.int32)
    result = {
        "accuracy": accuracy_score(y_true, predictions),
        "precision": precision_score(y_true, predictions, zero_division=0),
        "recall": recall_score(y_true, predictions, zero_division=0),
        "f1": f1_score(y_true, predictions, zero_division=0),
    }
    try:
        result["roc_auc"] = roc_auc_score(y_true, probabilities)
    except ValueError:
        result["roc_auc"] = 0.5
    cm = confusion_matrix(y_true, predictions, labels=[0, 1])
    fp = float(cm[0][1])
    tn = float(cm[0][0])
    result["fpr"] = fp / max(1.0, fp + tn)
    return {key: float(value) for key, value in result.items()}


async def train(output: Path) -> dict[str, object]:
    assert_no_feature_leakage()
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        rows = await load_labeled_rows(connection)
        if len(rows) < 4:
            raise RuntimeError("not enough labeled rows for network training")
        x, y = to_matrix(rows)
        if y is None or len(set(y.tolist())) < 2:
            raise RuntimeError("network training requires both benign and attack labels")
        dtrain = xgb.DMatrix(x, label=y)
        model = xgb.train(
            {
                "objective": "binary:logistic",
                "eval_metric": "logloss",
                "max_depth": 3,
                "eta": 0.15,
                "subsample": 0.9,
                "colsample_bytree": 0.9,
                "seed": 42,
            },
            dtrain,
            num_boost_round=50,
        )
        probabilities = model.predict(dtrain)
        measured = metrics(y, probabilities)
        output.parent.mkdir(parents=True, exist_ok=True)
        model.save_model(output)
        metadata_path = output.with_suffix(".metadata.json")
        metadata = {
            "model_id": "network-xgboost",
            "version": FEATURES_VERSION,
            "features_version": FEATURES_VERSION,
            "feature_schema": schema(),
            "metrics": measured,
            "training_rows": len(rows),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        await register_model(
            connection,
            model_id="network-xgboost",
            artifact_path=output,
            metrics=measured,
            training_set="phase5-labeled-events",
        )
        return metadata
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="/opt/ahr-idps/experiments/models/network-xgboost.json")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(train(Path(args.output))), sort_keys=True))


if __name__ == "__main__":
    main()
