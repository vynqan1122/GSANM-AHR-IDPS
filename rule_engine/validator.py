from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ai.graph.dataset import row_to_event
from ai.network.config import Settings
from ai.network.db import connect


DEFAULT_THRESHOLDS = {
    "min_precision": 0.90,
    "min_recall": 0.75,
    "max_fpr": 0.02,
    "min_positive_matches": 5,
}


@dataclass(frozen=True, slots=True)
class SyntaxResult:
    valid: bool
    engine_used: str
    error: str | None = None


def validate_suricata(content: str) -> SyntaxResult:
    binary = shutil.which("suricata")
    if binary:
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "candidate.rules"
            config = Path(tmp) / "suricata.yaml"
            rules.write_text(content + "\n", encoding="utf-8")
            config.write_text(f"vars: {{}}\ndefault-rule-path: {tmp}\nrule-files:\n  - candidate.rules\noutputs: []\n", encoding="utf-8")
            result = subprocess.run([binary, "-T", "-c", str(config)], capture_output=True, text=True, timeout=30)
            return SyntaxResult(result.returncode == 0, "suricata-binary", result.stderr[-500:] if result.returncode else None)
    valid = content.strip().startswith("alert ") and " sid:" in content and content.count("(") == content.count(")")
    return SyntaxResult(valid, "suricata-structural", None if valid else "invalid Suricata rule structure")


def validate_falco(content: str) -> SyntaxResult:
    binary = shutil.which("falco")
    if binary:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
            handle.write(content)
            path = handle.name
        try:
            result = subprocess.run([binary, "--dry-run", "-r", path], capture_output=True, text=True, timeout=30)
            return SyntaxResult(result.returncode == 0, "falco-binary", result.stderr[-500:] if result.returncode else None)
        finally:
            Path(path).unlink(missing_ok=True)
    valid = "- rule:" in content and "condition:" in content and "output:" in content
    return SyntaxResult(valid, "falco-structural", None if valid else "missing Falco rule/condition/output")


def validate_wazuh(content: str) -> SyntaxResult:
    try:
        ET.fromstring(f"<root>{content}</root>")
    except ET.ParseError as exc:
        return SyntaxResult(False, "wazuh-xml", str(exc))
    valid = "<rule" in content and "<description>" in content
    return SyntaxResult(valid, "wazuh-xml", None if valid else "missing Wazuh rule/description")


def syntax_check(engine: str, content: str) -> SyntaxResult:
    if engine == "suricata":
        return validate_suricata(content)
    if engine == "falco":
        return validate_falco(content)
    if engine == "wazuh":
        return validate_wazuh(content)
    return SyntaxResult(False, "unknown", f"unsupported engine: {engine}")


def rule_matches(engine: str, content: str, event: dict[str, Any]) -> bool:
    if engine == "suricata":
        http = event.get("http") if isinstance(event.get("http"), dict) else {}
        uri = str(http.get("uri") or http.get("url") or "")
        method = str(http.get("method") or "")
        return bool(uri and any(token in uri for token in ("/vulnerabilities", "/login", "/healthz"))) and (not method or method in content)
    if engine == "falco":
        process = event.get("process") if isinstance(event.get("process"), dict) else {}
        return bool(process and str(process.get("name") or process.get("command_line") or "")[:32] in content)
    if engine == "wazuh":
        return str(event.get("event_type") or "") in content or event.get("source") == "wazuh"
    return False


def metrics_for(engine: str, content: str, events: list[dict[str, Any]]) -> dict[str, float]:
    tp = fp = tn = fn = 0
    started = time.perf_counter()
    for event in events:
        attack = bool(event.get("attack_label"))
        matched = rule_matches(engine, content, event)
        if matched and attack:
            tp += 1
        elif matched and not attack:
            fp += 1
        elif not matched and attack:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "support": sum(1 for event in events if event.get("attack_label")),
        "match_count": tp + fp,
        "processing_cost": time.perf_counter() - started,
    }


def passes(metrics: dict[str, float], thresholds: dict[str, float] | None = None) -> bool:
    limits = thresholds or DEFAULT_THRESHOLDS
    return (
        metrics["precision"] >= limits["min_precision"]
        and metrics["recall"] >= limits["min_recall"]
        and metrics["fpr"] <= limits["max_fpr"]
        and metrics["tp"] >= limits["min_positive_matches"]
    )


async def load_rule(connection: Any, rule_id: str) -> dict[str, Any]:
    row = await connection.fetchrow(
        """
        SELECT r.*, rv.content
        FROM ahr.rules r
        JOIN ahr.rule_versions rv ON rv.rule_id = r.rule_id AND rv.version = r.current_version
        WHERE r.rule_id = $1
        """,
        rule_id,
    )
    if not row:
        raise RuntimeError(f"rule not found: {rule_id}")
    return dict(row)


async def load_validation_events(connection: Any) -> list[dict[str, Any]]:
    rows = await connection.fetch(
        """
        SELECT e.*, lbl.attack_label
        FROM ahr.events e
        JOIN (
            SELECT event_id, bool_or(label <> 'benign') AS attack_label
            FROM ahr.event_labels
            GROUP BY event_id
        ) lbl ON lbl.event_id = e.event_id
        ORDER BY e.timestamp ASC
        """
    )
    events = []
    for row in rows:
        event = row_to_event(row)
        event["attack_label"] = bool(row["attack_label"])
        events.append(event)
    return events


async def validate_rule(rule_id: str, thresholds: dict[str, float] | None = None) -> dict[str, Any]:
    settings = Settings.from_env()
    connection = await connect(settings)
    validation_id = "val-" + hashlib.sha256(f"{rule_id}:{time.time()}".encode()).hexdigest()[:24]
    try:
        rule = await load_rule(connection, rule_id)
        content = rule["content"]
        engine = rule["engine"]
        await connection.execute("UPDATE ahr.rules SET status = 'validating', updated_at = now() WHERE rule_id = $1", rule_id)
        syntax = syntax_check(engine, content)
        events = await load_validation_events(connection)
        replay = metrics_for(engine, content, events) if syntax.valid else {
            "tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "fpr": 1.0,
            "support": 0, "match_count": 0, "processing_cost": 0.0,
        }
        accepted = syntax.valid and passes(replay, thresholds)
        next_status = "shadow" if accepted else "rejected"
        await connection.execute(
            """
            INSERT INTO ahr.rule_validation_runs(
                validation_id, rule_id, rule_version, status, syntax_valid,
                conflicts, replay_metrics, performance_metrics, error_message, completed_at
            )
            VALUES ($1,$2,$3,$4,$5,'[]'::jsonb,$6::jsonb,$7::jsonb,$8,now())
            """,
            validation_id,
            rule_id,
            int(rule["current_version"]),
            "passed" if accepted else "failed",
            syntax.valid,
            json.dumps(replay),
            json.dumps({"syntax_engine": syntax.engine_used, "shadow_alerts_only": accepted}),
            syntax.error,
        )
        await connection.execute(
            """
            UPDATE ahr.rules
            SET status = $2::varchar,
                shadow_metrics = CASE WHEN $2::text = 'shadow' THEN $3::jsonb ELSE shadow_metrics END,
                updated_at = now()
            WHERE rule_id = $1
            """,
            rule_id,
            next_status,
            json.dumps({"alerts_only": True, "replay_metrics": replay}),
        )
        return {"rule_id": rule_id, "validation_id": validation_id, "status": next_status, "syntax": asdict(syntax), "metrics": replay}
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("rule_id")
    parser.add_argument("--min-precision", type=float, default=DEFAULT_THRESHOLDS["min_precision"])
    parser.add_argument("--min-recall", type=float, default=DEFAULT_THRESHOLDS["min_recall"])
    parser.add_argument("--max-fpr", type=float, default=DEFAULT_THRESHOLDS["max_fpr"])
    parser.add_argument("--min-positive-matches", type=float, default=DEFAULT_THRESHOLDS["min_positive_matches"])
    args = parser.parse_args()
    thresholds = {
        "min_precision": args.min_precision,
        "min_recall": args.min_recall,
        "max_fpr": args.max_fpr,
        "min_positive_matches": args.min_positive_matches,
    }
    print(json.dumps(asyncio.run(validate_rule(args.rule_id, thresholds)), sort_keys=True))


if __name__ == "__main__":
    main()
