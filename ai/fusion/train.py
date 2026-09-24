from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
import xgboost as xgb

from ai.network.config import Settings
from ai.network.db import connect
from ai.network.registry import register_model

from .dataset import FEATURE_NAMES, load_training_rows, matrix


MODEL_ID = "fusion-hybrid-xgboost"
MODEL_VERSION = "fusion-v1"


def metrics(y_true, probabilities) -> dict[str, float]:
    predictions = (probabilities >= 0.5).astype("int32")
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
    return {key: float(value) for key, value in result.items()}


async def train(output: Path) -> dict[str, object]:
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        events = await load_training_rows(connection)
        if len(events) < 4:
            raise RuntimeError("not enough labeled rows for fusion training")
        x, y = await matrix(connection, events)
        if len(set(y.tolist())) < 2:
            raise RuntimeError("fusion training requires benign and attack labels")
        dtrain = xgb.DMatrix(x, label=y, feature_names=list(FEATURE_NAMES))
        model = xgb.train(
            {
                "objective": "binary:logistic",
                "eval_metric": "logloss",
                "max_depth": 3,
                "eta": 0.2,
                "subsample": 0.9,
                "colsample_bytree": 0.9,
                "seed": 42,
            },
            dtrain,
            num_boost_round=40,
        )
        probabilities = model.predict(dtrain)
        measured = metrics(y, probabilities)
        output.parent.mkdir(parents=True, exist_ok=True)
        model.save_model(output)
        metadata = {
            "model_id": MODEL_ID,
            "version": MODEL_VERSION,
            "features": list(FEATURE_NAMES),
            "metrics": measured,
            "training_rows": len(events),
        }
        output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        await register_model(
            connection,
            model_id=MODEL_ID,
            artifact_path=output,
            metrics=measured,
            training_set="phase5-labeled-fusion-features",
            name=MODEL_ID,
            model_type="xgboost-meta-fusion",
            version=MODEL_VERSION,
            feature_schema={"features": list(FEATURE_NAMES)},
        )
        return metadata
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="/opt/ahr-idps/experiments/models/fusion-hybrid-xgboost.json")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(train(Path(args.output))), sort_keys=True))


if __name__ == "__main__":
    main()

