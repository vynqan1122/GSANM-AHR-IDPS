from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def _row(row: Any) -> dict[str, Any]:
    data = dict(row)
    for key, value in list(data.items()):
        data[key] = _json(value)
    return data


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True, default=str) + "\n" for row in rows), encoding="utf-8")


def _manifest(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for path in sorted(item for item in root.iterdir() if item.is_file() and item.name != "manifest.json"):
        data = path.read_bytes()
        rows.append(
            {
                "filename": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "timestamp": now,
                "size": len(data),
            }
        )
    return rows


async def collect_evidence(connection: Any, incident_id: str, evidence_root: str | Path = "evidence") -> dict[str, Any]:
    root = Path(evidence_root) / incident_id
    root.mkdir(parents=True, exist_ok=True)

    incident_row = await connection.fetchrow("SELECT * FROM ahr.incidents WHERE incident_id = $1", incident_id)
    if not incident_row:
        raise RuntimeError(f"incident not found: {incident_id}")
    incident = _row(incident_row)

    event_rows = await connection.fetch(
        """
        SELECT e.*
        FROM ahr.events e
        JOIN ahr.incident_events ie ON ie.event_id = e.event_id
        WHERE ie.incident_id = $1
        ORDER BY e.timestamp ASC
        """,
        incident_id,
    )
    events = [_row(row) for row in event_rows]
    event_ids = [event["event_id"] for event in events]
    flows = []
    predictions = []
    if event_ids:
        flows = [_row(row) for row in await connection.fetch("SELECT * FROM ahr.network_flows WHERE flow_row_id = ANY($1::text[])", event_ids)]
        predictions = [_row(row) for row in await connection.fetch("SELECT * FROM ahr.ai_predictions WHERE event_id = ANY($1::text[]) ORDER BY created_at ASC", event_ids)]

    _write_json(root / "incident.json", incident)
    _write_json(root / "timeline.json", incident.get("timeline") or [])
    _write_jsonl(root / "events.jsonl", events)
    for source in ("suricata", "falco", "wazuh"):
        _write_jsonl(root / f"{source}.jsonl", [event for event in events if str(event.get("source")) == source])
    nginx_lines = [
        json.dumps({"timestamp": event.get("timestamp"), "src_ip": event.get("src_ip"), "http": event.get("http"), "raw_event": event.get("raw_event")}, sort_keys=True, default=str)
        for event in events
        if str(event.get("source")) == "nginx" or event.get("http")
    ]
    (root / "nginx.log").write_text("\n".join(nginx_lines) + ("\n" if nginx_lines else ""), encoding="utf-8")
    _write_json(root / "network_flows.json", flows)
    _write_json(root / "process_tree.json", [event.get("process") for event in events if event.get("process")])
    _write_json(root / "ai_predictions.json", predictions or [event.get("ai") for event in events if event.get("ai")])
    _write_json(root / "rule_matches.json", [event.get("rule") for event in events if event.get("rule")])
    _write_json(root / "container_metadata.json", [event.get("container") for event in events if event.get("container")])

    manifest = _manifest(root)
    _write_json(root / "manifest.json", manifest)
    bundle_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return {
        "incident_id": incident_id,
        "path": str(root),
        "manifest": manifest,
        "bundle_sha256": bundle_hash,
        "file_count": len(manifest) + 1,
    }

