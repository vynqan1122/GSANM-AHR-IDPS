from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.neural_network import MLPClassifier

from ai.network.config import Settings
from ai.network.db import connect
from ai.network.registry import register_model

from .dataset import load_labeled_logs, to_embeddings

MODEL_ID = "log-minilm-iforest-mlp"
MODEL_VERSION = "log-v1"


async def train(output: Path) -> dict[str, object]:
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        rows = await load_labeled_logs(connection)
        if len(rows) < 4:
            raise RuntimeError("not enough labeled log rows")
        x, y, _texts = to_embeddings(rows)
        if len(set(y.tolist())) < 2:
            raise RuntimeError("log training requires benign and attack labels")
        benign = x[y == 0]
        iforest = IsolationForest(n_estimators=80, contamination="auto", random_state=42)
        iforest.fit(benign if len(benign) else x)
        classifier = MLPClassifier(hidden_layer_sizes=(32,), max_iter=500, random_state=42)
        classifier.fit(x, y)
        pred = classifier.predict(x)
        metrics = {
            "accuracy": float(accuracy_score(y, pred)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"iforest": iforest, "classifier": classifier, "version": MODEL_VERSION}, output)
        metadata = {
            "model_id": MODEL_ID,
            "version": MODEL_VERSION,
            "embedding_model": "all-MiniLM-L6-v2-compatible-384",
            "metrics": metrics,
            "training_rows": len(rows),
        }
        output.with_suffix(".metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        await register_model(
            connection,
            model_id=MODEL_ID,
            artifact_path=output,
            metrics=metrics,
            training_set="phase5-labeled-logs",
            name="log-ai",
            model_type="minilm-iforest-mlp",
            version=MODEL_VERSION,
            feature_schema={"embedding_model": "all-MiniLM-L6-v2-compatible-384", "embedding_dim": 384},
        )
        return metadata
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="/opt/ahr-idps/experiments/models/log-ai.joblib")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(train(Path(args.output))), sort_keys=True))


if __name__ == "__main__":
    main()
