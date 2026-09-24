from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import xgboost as xgb

from ai.network.config import Settings
from ai.network.db import connect

from .dataset import FEATURE_NAMES, load_training_rows, matrix
from .train import metrics


async def evaluate(model_path: Path, output: Path) -> dict[str, float]:
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        events = await load_training_rows(connection)
        x, y = await matrix(connection, events)
        model = xgb.Booster()
        model.load_model(model_path)
        measured = metrics(y, model.predict(xgb.DMatrix(x, feature_names=list(FEATURE_NAMES))))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(measured, indent=2, sort_keys=True), encoding="utf-8")
        return measured
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="/opt/ahr-idps/experiments/models/fusion-hybrid-xgboost.json")
    parser.add_argument("--output", default="/opt/ahr-idps/experiments/models/fusion-hybrid-xgboost.metrics.json")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(evaluate(Path(args.model), Path(args.output))), sort_keys=True))


if __name__ == "__main__":
    main()

