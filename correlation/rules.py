from __future__ import annotations

from typing import Any
from feature_engine.event_contract import routine_navigation


VALID_STATUSES = {"open", "investigating", "contained", "resolved", "false_positive"}


def actionable_event(event: dict[str, Any]) -> bool:
    # Log all events, but normal navigation is not automatically an incident.
    # Rule evidence or suspicious parameters still take the normal triage path.
    if routine_navigation(event):
        return False
    return bool(event.get('rule')) or risk_score(event) >= 0.5


def risk_score(event: dict[str, Any]) -> float:
    ai = event.get("ai") if isinstance(event.get("ai"), dict) else {}
    severity = float(event.get("severity") or 0) / 10.0
    fusion = ai.get("fusion_score")
    graph = ai.get("graph_score")
    log = ai.get("log_score")
    network = ai.get("network_score")
    scores = [value for value in (fusion, graph, log, network) if isinstance(value, (int, float))]
    ai_score = max(scores) if scores else 0.0
    return max(0.0, min(1.0, 0.65 * ai_score + 0.35 * severity))


def attack_type(event: dict[str, Any]) -> str:
    labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
    if labels.get("attack_type"):
        return str(labels["attack_type"])
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    text = " ".join(str(rule.get(k) or "") for k in ("name", "category", "rule_id")).lower()
    if "sql" in text or "sqli" in text:
        return "sql_injection"
    if "scan" in text or "recon" in text:
        return "reconnaissance"
    if "command" in text or "shell" in text:
        return "command_execution"
    return str(event.get("category") or event.get("event_type") or "unknown")


def title_for(event: dict[str, Any], event_count: int) -> str:
    src = event.get("src_ip") or "unknown source"
    dst = event.get("dst_ip") or "unknown target"
    return f"{attack_type(event)} incident: {src} -> {dst} ({event_count} events)"


def rule_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    for event in events:
        rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
        key = str(rule.get("rule_id") or rule.get("name") or "")
        if not key:
            continue
        item = rules.setdefault(key, {"rule_id": key, "name": rule.get("name"), "count": 0})
        item["count"] += 1
    return {"matched_rules": list(rules.values()), "rule_match_count": sum(item["count"] for item in rules.values())}


def ai_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    maxima = {"network_score": None, "log_score": None, "graph_score": None, "fusion_score": None}
    risks: dict[str, int] = {}
    for event in events:
        ai = event.get("ai") if isinstance(event.get("ai"), dict) else {}
        for key in maxima:
            value = ai.get(key)
            if isinstance(value, (int, float)):
                maxima[key] = value if maxima[key] is None else max(float(maxima[key]), float(value))
        risk = ai.get("risk_level")
        if risk:
            risks[str(risk)] = risks.get(str(risk), 0) + 1
    return {"max_scores": maxima, "risk_levels": risks}

