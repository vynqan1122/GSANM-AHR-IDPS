#!/usr/bin/env python3
"""Train and compare lightweight network classifiers for AHR-IDPS.

The input may be an AHR-IDPS JSONL export, a Kaggle CSV, or a ZIP containing
CSV files.  Every model uses the project's network-v1 feature contract so the
XGBoost artifact can be installed into the realtime network-ai service.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import shutil
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    import xgboost as xgb
except ImportError:  # pragma: no cover - optional only for comparison/install
    xgb = None


FEATURE_NAMES = [
    "src_port",
    "dst_port",
    "dst_port_class",
    "protocol_tcp",
    "protocol_udp",
    "protocol_http",
    "has_src_ip",
    "has_dst_ip",
    "has_container",
    "has_rule",
    "severity",
    "event_type_alert",
    "event_type_http",
    "event_type_flow",
    "bytes_total",
    "packets_total",
    "status_error",
    "connections_per_window",
    "unique_dst_per_window",
    "request_rate",
    "error_rate",
]

BENIGN_VALUES = {
    "0",
    "benign",
    "normal",
    "normal traffic",
    "background",
    "non-attack",
    "no attack",
}


def _clean_key(value: Any) -> str:
    return "".join(ch.lower() for ch in str(value or "").strip() if ch.isalnum())


def _number(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        text = str(value).strip().replace(",", "")
        if text.endswith("%"):
            text = text[:-1]
        parsed = float(text)
        return parsed if math.isfinite(parsed) else default
    except (TypeError, ValueError):
        return default


def _first(row: dict[str, Any], *aliases: str) -> Any:
    cache_key = "__ahr_normalized_keys__"
    normalized = row.get(cache_key)
    if not isinstance(normalized, dict):
        normalized = {_clean_key(key): value for key, value in row.items()}
        row[cache_key] = normalized
    for alias in aliases:
        value = normalized.get(_clean_key(alias))
        if value not in (None, ""):
            return value
    return None


def _label(row: dict[str, Any]) -> int | None:
    raw = _first(row, "label", "class", "target", "attack", "outcome", "category")
    if raw in (None, ""):
        raw = _first(row, "attack_type", "attack type")
    if raw in (None, ""):
        return None
    text = str(raw).strip().lower()
    if text in BENIGN_VALUES or text.startswith("benign") or text.startswith("normal"):
        return 0
    if text in {"false", "no", "safe"}:
        return 0
    return 1


def _label_name(row: dict[str, Any]) -> str:
    raw = _first(row, "label", "class", "target", "attack", "outcome", "category")
    if raw in (None, ""):
        raw = _first(row, "attack_type", "attack type")
    return str(raw or "unknown").strip().replace("\ufffd", "-").replace("–", "-").replace("—", "-")


def _protocol_flags(value: Any) -> tuple[float, float, float]:
    text = str(value or "").lower()
    numeric = _number(value, -1)
    tcp = float("tcp" in text or numeric == 6)
    udp = float("udp" in text or numeric == 17)
    http = float("http" in text or numeric in {80, 443})
    return tcp, udp, http


def _port_class(port: float) -> float:
    if port <= 0:
        return 0.0
    if port < 1024:
        return 1.0
    if port < 49152:
        return 2.0
    return 3.0


def _raw_event(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw_event")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _event_row(row: dict[str, Any], source_file: str) -> dict[str, Any] | None:
    label = _label(row)
    if label is None:
        return None
    raw = _raw_event(row)
    http_candidate = row.get("http") if isinstance(row.get("http"), dict) else raw.get("http", {})
    http = http_candidate if isinstance(http_candidate, dict) else {}
    src_ip = _first(row, "src_ip", "source_ip", "source") or raw.get("src_ip")
    dst_ip = _first(row, "dst_ip", "destination_ip", "destination") or raw.get("dest_ip") or raw.get("destination_ip")
    src_port = _number(_first(row, "src_port", "source_port") or raw.get("src_port"))
    dst_port = _number(_first(row, "dst_port", "destination_port") or raw.get("dest_port", raw.get("destination_port")))
    protocol = _first(row, "protocol", "proto") or raw.get("proto")
    event_type = str(_first(row, "event_type", "type") or "flow").lower()
    if event_type not in {"alert", "http", "flow"}:
        event_type = "flow"

    fwd_bytes = _number(_first(row, "bytes_to_server", "total_length_of_fwd_packets", "total_fwd_bytes"))
    bwd_bytes = _number(_first(row, "bytes_to_client", "total_length_of_bwd_packets", "total_bwd_bytes"))
    fwd_packets = _number(_first(row, "packets_to_server", "total_fwd_packets", "fwd_packets"))
    bwd_packets = _number(_first(row, "packets_to_client", "total_backward_packets", "bwd_packets"))
    status = _number(_first(row, "status", "http_response_code", "response_code") or http.get("status"))
    severity = _number(_first(row, "severity"))
    rule = _first(row, "rule", "rule_name", "signature", "attack_type")
    scenario = _first(row, "scenario_id", "scenario", "session_id")
    timestamp = _first(row, "timestamp", "time", "date")
    group = str(scenario or "").strip()
    if not group:
        # CICIDS has no scenario_id. A day/file group avoids mixing every row
        # into one synthetic scenario while retaining a deterministic split.
        group = str(_first(row, "day", "date") or source_file)
    return {
        "label": label,
        "original_label": _label_name(row),
        "source_file": source_file,
        "group": group,
        "src_ip": str(src_ip or ""),
        "dst_ip": str(dst_ip or ""),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "event_type": event_type,
        "bytes_total": fwd_bytes + bwd_bytes,
        "packets_total": fwd_packets + bwd_packets,
        "status_error": float(status >= 400),
        "severity": severity,
        "has_container": float(bool(_first(row, "container", "container_name"))),
        "has_rule": float(bool(rule)),
        "timestamp": timestamp,
    }


def _read_csv(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            yield dict(row), path.name


def _read_zip(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.lower().endswith(".csv") and not name.endswith("/")]
        if not names:
            raise ValueError(f"ZIP does not contain CSV files: {path}")
        for name in names:
            with archive.open(name) as raw_handle:
                text_handle = (line.decode("utf-8-sig", errors="replace") for line in raw_handle)
                for row in csv.DictReader(text_handle):
                    yield dict(row), Path(name).name


def _read_jsonl(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line), path.name


def load_rows(path: Path, max_rows: int | None, seed: int) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".zip":
        source = _read_zip(path)
    elif path.suffix.lower() in {".jsonl", ".ndjson"}:
        source = _read_jsonl(path)
    elif path.suffix.lower() == ".csv":
        source = _read_csv(path)
    else:
        raise ValueError("Input must be .csv, .jsonl/.ndjson, or .zip containing CSV files")
    rows: list[dict[str, Any]] = []
    rng = random.Random(seed)
    per_class_limit = max(1, max_rows // 2) if max_rows else None
    reservoirs: dict[int, list[dict[str, Any]]] = defaultdict(list)
    seen_by_label: Counter[int] = Counter()
    for raw, source_file in source:
        normalized = _event_row(raw, source_file)
        if normalized is None:
            continue
        if per_class_limit is None:
            rows.append(normalized)
            continue
        label = int(normalized["label"])
        seen_by_label[label] += 1
        reservoir = reservoirs[label]
        if len(reservoir) < per_class_limit:
            reservoir.append(normalized)
        else:
            replacement = rng.randrange(seen_by_label[label])
            if replacement < per_class_limit:
                reservoir[replacement] = normalized
    if per_class_limit is not None:
        populated = [len(reservoirs[label]) for label in (0, 1) if reservoirs[label]]
        balanced_limit = min(populated) if len(populated) == 2 else per_class_limit
        for label in sorted(reservoirs):
            rows.extend(reservoirs[label][:balanced_limit])
        rng.shuffle(rows)
    if not rows:
        raise ValueError("No labeled rows found. Check the Kaggle Label column or AHR label field.")
    return rows


def make_matrix(rows: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    counts = Counter(row["src_ip"] for row in rows)
    destinations: dict[str, set[str]] = defaultdict(set)
    errors = Counter()
    for row in rows:
        destinations[row["src_ip"]].add(row["dst_ip"])
        errors[row["src_ip"]] += int(row["status_error"])
    matrix = []
    for row in rows:
        total = max(1, counts[row["src_ip"]])
        tcp, udp, http = _protocol_flags(row["protocol"])
        values = [
            row["src_port"], row["dst_port"], _port_class(row["dst_port"]), tcp, udp, http,
            float(bool(row["src_ip"])), float(bool(row["dst_ip"])), row["has_container"], row["has_rule"],
            row["severity"], float(row["event_type"] == "alert"), float(row["event_type"] == "http"),
            float(row["event_type"] == "flow"), row["bytes_total"], row["packets_total"], row["status_error"],
            float(total), float(len(destinations[row["src_ip"]])), float(total), float(errors[row["src_ip"]] / total),
        ]
        matrix.append(values)
    return np.nan_to_num(np.asarray(matrix, dtype=np.float32), nan=0.0, posinf=0.0, neginf=0.0), np.asarray([row["label"] for row in rows], dtype=np.int32), [row["group"] for row in rows]


def calculate_metrics(y_true: np.ndarray, probabilities: np.ndarray) -> dict[str, float]:
    predictions = (probabilities >= 0.5).astype(np.int32)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    result = {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "fpr": float(fp / max(1, fp + tn)),
        "true_positives": float(tp),
        "false_positives": float(fp),
        "false_negatives": float(fn),
        "true_negatives": float(tn),
    }
    for key, scorer in (("roc_auc", roc_auc_score), ("pr_auc", average_precision_score)):
        try:
            result[key] = float(scorer(y_true, probabilities))
        except ValueError:
            result[key] = 0.5
    return result


def split_indices(y: np.ndarray, groups: list[str], seed: int) -> tuple[np.ndarray, np.ndarray, str]:
    unique_groups = len(set(groups))
    if unique_groups >= 4:
        group_array = np.asarray(groups)
        for offset in range(10):
            splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed + offset)
            train_idx, test_idx = next(splitter.split(np.zeros(len(y)), y, group_array))
            if len(set(y[train_idx])) == 2 and len(set(y[test_idx])) == 2:
                return train_idx, test_idx, "group_shuffle_split"
    train_idx, test_idx = train_test_split(np.arange(len(y)), test_size=0.2, random_state=seed, stratify=y)
    return np.asarray(train_idx), np.asarray(test_idx), "stratified_random_split_fallback"


def train_xgb(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, device: str) -> tuple[Any, np.ndarray]:
    if xgb is None:
        raise RuntimeError("xgboost is not installed; install ai/requirements.txt or use Docker")
    dtrain = xgb.DMatrix(x_train, label=y_train, feature_names=FEATURE_NAMES)
    model = xgb.train(
        {
            "objective": "binary:logistic",
            "eval_metric": "logloss",
            "max_depth": 4,
            "eta": 0.08,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
            "seed": 42,
            "nthread": min(4, os.cpu_count() or 1),
            "tree_method": "hist",
            "device": device,
        },
        dtrain,
        num_boost_round=160,
    )
    return model, model.predict(xgb.DMatrix(x_test, feature_names=FEATURE_NAMES))


def write_comparison(output_dir: Path, records: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "network_model_comparison.json").write_text(json.dumps({"metadata": metadata, "models": records}, indent=2, sort_keys=True), encoding="utf-8")
    fields = ["model", "artifact", "accuracy", "precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"]
    with (output_dir / "network_model_comparison.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field, "") for field in fields})
    lines = [
        "# So sánh mô hình Network AI AHR-IDPS",
        "",
        f"Dataset: `{metadata['input']}` | rows: `{metadata['rows']}` | split: `{metadata['split_strategy']}`",
        "",
        "| Model | F1 | Precision | Recall | FPR | ROC-AUC | PR-AUC | Artifact |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for record in sorted(records, key=lambda item: item.get("f1", 0), reverse=True):
        lines.append(f"| {record['model']} | {record['f1']:.4f} | {record['precision']:.4f} | {record['recall']:.4f} | {record['fpr']:.4f} | {record['roc_auc']:.4f} | {record['pr_auc']:.4f} | `{record['artifact']}` |")
    (output_dir / "network_model_comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="datasets/network/flows.jsonl", help="AHR JSONL, Kaggle CSV, or ZIP of CSV files")
    parser.add_argument("--output-dir", default="experiments/comparison/network", help="Comparison artifacts directory")
    parser.add_argument("--max-rows", type=int, default=30000, help="Cap rows after class-balanced sampling; use 0 for all")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu", help="XGBoost device; comparison baselines remain CPU")
    parser.add_argument("--install-xgboost", action="store_true", help="Copy the trained XGBoost JSON to experiments/models/network-xgboost.json")
    parser.add_argument("--model-dest", default="experiments/models/network-xgboost.json")
    args = parser.parse_args()
    random.seed(args.seed)
    np.random.seed(args.seed)
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = load_rows(input_path, args.max_rows or None, args.seed)
    x, y, groups = make_matrix(rows)
    if len(set(y.tolist())) < 2:
        raise RuntimeError("Dataset must contain both benign/normal and attack labels")
    train_idx, test_idx, split_strategy = split_indices(y, groups, args.seed)
    x_train, x_test, y_train, y_test = x[train_idx], x[test_idx], y[train_idx], y[test_idx]
    records: list[dict[str, Any]] = []

    models: dict[str, Any] = {
        "logistic_regression": Pipeline([("scale", StandardScaler()), ("model", LogisticRegression(max_iter=500, class_weight="balanced", random_state=args.seed))]),
        "random_forest": RandomForestClassifier(n_estimators=160, max_depth=12, min_samples_leaf=2, class_weight="balanced", n_jobs=min(4, os.cpu_count() or 1), random_state=args.seed),
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_iter=160, learning_rate=0.08, max_leaf_nodes=15, random_state=args.seed),
    }
    for name, estimator in models.items():
        estimator.fit(x_train, y_train)
        probability = estimator.predict_proba(x_test)[:, 1]
        metrics = calculate_metrics(y_test, probability)
        artifact = output_dir / f"{name}.joblib"
        joblib.dump({"model": estimator, "feature_names": FEATURE_NAMES, "features_version": "network-v1"}, artifact)
        records.append({"model": name, "artifact": str(artifact), **metrics})

    xgb_artifact = output_dir / "xgboost-network.json"
    if xgb is not None:
        try:
            xgb_model, probability = train_xgb(x_train, y_train, x_test, args.device)
        except Exception as exc:
            if args.device == "cuda":
                raise RuntimeError(
                    "XGBoost CUDA training failed. Verify the NVIDIA driver, a CUDA-enabled XGBoost wheel, "
                    "and Docker/WSL GPU passthrough; retry with --device cpu to diagnose the dataset."
                ) from exc
            raise
        metrics = calculate_metrics(y_test, probability)
        xgb_model.save_model(str(xgb_artifact))
        records.append({"model": "xgboost", "artifact": str(xgb_artifact), **metrics})
        if args.install_xgboost:
            destination = Path(args.model_dest)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                backup = destination.with_suffix(destination.suffix + ".bak")
                shutil.copy2(destination, backup)
            shutil.copy2(xgb_artifact, destination)
            metadata_destination = destination.with_suffix(".metadata.json")
        else:
            metadata_destination = None
    else:
        print("WARNING: xgboost is unavailable; no runtime-compatible artifact was produced.", file=sys.stderr)
        metadata_destination = None

    metadata = {
        "created_at": datetime.now(UTC).isoformat(),
        "input": str(input_path),
        "rows": len(rows),
        "train_rows": len(train_idx),
        "test_rows": len(test_idx),
        "label_counts": dict(Counter(int(value) for value in y.tolist())),
        "original_label_counts": dict(Counter(row["original_label"] for row in rows)),
        "groups": len(set(groups)),
        "split_strategy": split_strategy,
        "features_version": "network-v1",
        "xgboost_device": args.device,
        "feature_names": FEATURE_NAMES,
        "source_note": "External Kaggle data is supplemental; DVWA-local labeled telemetry is the primary evaluation set.",
    }
    write_comparison(output_dir, records, metadata)
    if xgb is not None:
        xgb_record = next(record for record in records if record["model"] == "xgboost")
        runtime_metadata = {
            "model_id": "network-xgboost",
            "version": "network-v1",
            "features_version": "network-v1",
            "feature_schema": {"features": FEATURE_NAMES, "target": "attack_probability"},
            "metrics": {key: value for key, value in xgb_record.items() if key not in {"model", "artifact"}},
            "training_rows": len(train_idx),
            "evaluation_rows": len(test_idx),
            "dataset": str(input_path),
            "split_strategy": split_strategy,
            "device": args.device,
            "installed_at": datetime.now(UTC).isoformat(),
        }
        comparison_metadata = xgb_artifact.with_suffix(".metadata.json")
        comparison_metadata.write_text(json.dumps(runtime_metadata, indent=2, sort_keys=True), encoding="utf-8")
    if metadata_destination is not None:
        shutil.copy2(comparison_metadata, metadata_destination)
        print(f"Installed runtime model: {metadata_destination.parent / metadata_destination.name}")
    print(json.dumps({"comparison_dir": str(output_dir), "models": records, "metadata": metadata}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
