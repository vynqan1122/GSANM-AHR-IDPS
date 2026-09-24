from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from ai.network.config import Settings
from ai.network.db import connect
from ai.network.registry import register_model

from .dataset import graphs_and_labels, load_labeled_events
from .graph_builder import DEFAULT_WINDOW_SECONDS, graph_json
from .graphsage import MODEL_ID, MODEL_VERSION, GraphSAGEWindowClassifier


async def train(output: Path, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> dict[str, object]:
    settings = Settings.from_env()
    connection = await connect(settings)
    try:
        events = await load_labeled_events(connection)
        graphs, labels = graphs_and_labels(events, window_seconds)
        if len(graphs) < 2:
            raise RuntimeError("not enough graph windows for GraphSAGE training")
        model = GraphSAGEWindowClassifier()
        model.fit(graphs, labels)
        measured = model.evaluate(graphs, labels)
        output.parent.mkdir(parents=True, exist_ok=True)
        model.save(str(output))
        graph_export = Path("/opt/ahr-idps/datasets/graphs/phase8_training_graphs.jsonl")
        graph_export.parent.mkdir(parents=True, exist_ok=True)
        graph_export.write_text("\n".join(graph_json(graph) for graph in graphs) + "\n", encoding="utf-8")
        metadata = {
            "model_id": MODEL_ID,
            "version": MODEL_VERSION,
            "window_seconds": window_seconds,
            "mode": "graph_window_classification",
            "device": "cpu",
            "metrics": measured,
            "training_graphs": len(graphs),
            "training_events": len(events),
            "graph_artifact": str(graph_export),
        }
        output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        await register_model(
            connection,
            model_id=MODEL_ID,
            artifact_path=output,
            metrics=measured,
            training_set="phase5-labeled-security-graphs",
            name=MODEL_ID,
            model_type="graphsage-window",
            version=MODEL_VERSION,
            feature_schema={
                "features_version": "graph-features-v1",
                "window_seconds": window_seconds,
                "node_embedding": "mean-neighborhood",
            },
        )
        return metadata
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="/opt/ahr-idps/experiments/models/graphsage-security-event.joblib")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS, choices=[10, 30, 60, 120])
    args = parser.parse_args()
    print(json.dumps(asyncio.run(train(Path(args.output), args.window_seconds)), sort_keys=True))


if __name__ == "__main__":
    main()

