from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from ai.network.config import Settings
from ai.network.db import connect

from .dataset import graphs_and_labels, load_labeled_events
from .graphsage import GraphSAGEWindowClassifier


async def evaluate(model_path: Path, output: Path) -> dict[str, float]:
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        events = await load_labeled_events(connection)
        graphs, labels = graphs_and_labels(events)
        model = GraphSAGEWindowClassifier.load(str(model_path))
        metrics = model.evaluate(graphs, labels)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
        return metrics
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="/opt/ahr-idps/experiments/models/graphsage-security-event.joblib")
    parser.add_argument("--output", default="/opt/ahr-idps/experiments/models/graphsage-security-event.metrics.json")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(evaluate(Path(args.model), Path(args.output))), sort_keys=True))


if __name__ == "__main__":
    main()

