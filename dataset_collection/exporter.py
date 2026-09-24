"""Dataset export utilities."""

from __future__ import annotations

import csv
import json
import pickle
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(_jsonable(row), sort_keys=True, separators=(",", ":")) + "\n")


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _jsonable(row.get(field)) for field in fields})


def _temporal_split(index: int, total: int) -> str:
    if total <= 0:
        return "train"
    ratio = index / total
    if ratio < 0.60:
        return "train"
    if ratio < 0.75:
        return "validation"
    if ratio < 0.85:
        return "known_test"
    if ratio < 0.95:
        return "variant_test"
    return "unknown_test"


async def export_dataset(connection: Any, output_root: Path) -> dict[str, str]:
    rows = [
        dict(row)
        for row in await connection.fetch(
            """
            SELECT e.event_id, e.timestamp, e.source, e.event_type, e.category,
                   e.src_ip, e.dst_ip, e.protocol, e.container, e.rule,
                   e.severity, e.raw_event, e.metadata, l.scenario_id,
                   l.label, l.attack_type
            FROM ahr.events e
            JOIN ahr.event_labels l ON l.event_id = e.event_id
            ORDER BY e.timestamp ASC
            """
        )
    ]
    scenarios = [
        dict(row)
        for row in await connection.fetch(
            """
            SELECT scenario_id, name, label, attack_type, mode, start_time,
                   end_time, source, target, notes, request_count
            FROM ahr.scenario_runs
            ORDER BY start_time ASC
            """
        )
    ]

    manifest: dict[str, str] = {}
    raw_path = output_root / "raw" / "events.jsonl"
    normalized_path = output_root / "normalized" / "events.jsonl"
    network_path = output_root / "network" / "flows.jsonl"
    logs_path = output_root / "logs" / "events.jsonl"
    labels_path = output_root / "labels" / "event_labels.csv"
    metadata_path = output_root / "metadata" / "scenario_runs.csv"
    parquet_path = output_root / "processed" / "events.parquet"
    graph_path = output_root / "graphs" / "events_graph.pt"
    splits_path = output_root / "metadata" / "splits.csv"

    # Keep every event from one DVWA scenario in one split. Splitting event by
    # event leaks the same request/session markers into both train and test.
    scenario_order: list[str] = []
    for row in rows:
        scenario_id = str(row["scenario_id"])
        if scenario_id not in scenario_order:
            scenario_order.append(scenario_id)
    scenario_splits = {
        scenario_id: _temporal_split(index, len(scenario_order))
        for index, scenario_id in enumerate(scenario_order)
    }
    for row in rows:
        row["split"] = scenario_splits[str(row["scenario_id"])]
    _write_jsonl(raw_path, rows)
    _write_jsonl(normalized_path, [{k: v for k, v in row.items() if k != "raw_event"} for row in rows])
    _write_jsonl(network_path, [row for row in rows if row.get("src_ip") or row.get("dst_ip")])
    _write_jsonl(logs_path, [row for row in rows if row.get("source") in {"falco", "wazuh", "nginx"}])
    _write_csv(labels_path, rows, ["event_id", "scenario_id", "label", "attack_type", "source", "timestamp", "split"])
    _write_csv(metadata_path, scenarios, ["scenario_id", "name", "label", "attack_type", "mode", "start_time", "end_time", "source", "target", "request_count", "notes"])
    _write_csv(splits_path, rows, ["event_id", "scenario_id", "timestamp", "split"])

    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    parquet_rows = [{k: json.dumps(_jsonable(v), sort_keys=True) if isinstance(v, (dict, list)) else _jsonable(v) for k, v in row.items()} for row in rows]
    pq.write_table(pa.Table.from_pylist(parquet_rows), parquet_path)

    graph_path.parent.mkdir(parents=True, exist_ok=True)
    event_ids = [row["event_id"] for row in rows]
    edges = [
        (rows[index]["event_id"], rows[index + 1]["event_id"])
        for index in range(max(0, len(rows) - 1))
        if rows[index].get("scenario_id") == rows[index + 1].get("scenario_id")
    ]
    with graph_path.open("wb") as handle:
        pickle.dump({"nodes": event_ids, "edges": edges, "format": "pytorch-compatible-pickle"}, handle)

    for key, path in {
        "raw_jsonl": raw_path,
        "normalized_jsonl": normalized_path,
        "network_jsonl": network_path,
        "logs_jsonl": logs_path,
        "labels_csv": labels_path,
        "metadata_csv": metadata_path,
        "splits_csv": splits_path,
        "events_parquet": parquet_path,
        "graph_artifact": graph_path,
    }.items():
        manifest[key] = str(path)
    manifest_path = output_root / "metadata" / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    manifest["manifest"] = str(manifest_path)
    return manifest
