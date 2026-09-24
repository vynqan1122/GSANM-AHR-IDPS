from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from feature_engine.versioning import FEATURES_VERSION


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


async def register_model(
    connection: Any,
    *,
    model_id: str,
    artifact_path: Path,
    metrics: dict[str, float],
    training_set: str,
    name: str = "network-xgboost",
    model_type: str = "xgboost",
    version: str = FEATURES_VERSION,
    feature_schema: dict[str, Any] | None = None,
) -> None:
    await connection.execute(
        """
        INSERT INTO ahr.models(
            model_id, name, model_type, version, status, artifact_uri,
            artifact_sha256, feature_schema, training_metadata, activated_at
        )
        VALUES ($1, $7, $8, $2, 'active', $3, $4,
                $5::jsonb, $6::jsonb, now())
        ON CONFLICT (model_id) DO UPDATE SET
            status = 'active',
            artifact_uri = excluded.artifact_uri,
            artifact_sha256 = excluded.artifact_sha256,
            feature_schema = excluded.feature_schema,
            training_metadata = excluded.training_metadata,
            activated_at = now()
        """,
        model_id,
        version,
        str(artifact_path),
        sha256_file(artifact_path),
        json.dumps(feature_schema or {"features_version": FEATURES_VERSION}),
        json.dumps({"training_set": training_set, "created_at": datetime.now(UTC).isoformat()}),
        name,
        model_type,
    )
    for name, value in metrics.items():
        await connection.execute(
            """
            INSERT INTO ahr.model_metrics(model_id, dataset_split, metric_name, metric_value, metadata)
            VALUES ($1, 'train', $2, $3, '{}'::jsonb)
            """,
            model_id,
            name,
            float(value),
        )
