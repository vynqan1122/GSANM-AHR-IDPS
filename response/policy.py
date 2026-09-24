from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


LEVELS = {
    0: "log",
    1: "alert",
    2: "rate_limit",
    3: "lab_block",
    4: "isolate_container",
}


@dataclass(frozen=True, slots=True)
class ResponseConfig:
    mode: str = "alert_only"
    automatic_block: bool = False
    automatic_container_isolation: bool = False
    critical_risk_threshold: float = 0.75
    high_ai_threshold: float = 0.70

    @classmethod
    def from_env(cls) -> "ResponseConfig":
        return cls(
            mode=os.getenv("AHR_RESPONSE_MODE", "alert_only"),
            automatic_block=os.getenv("AHR_RESPONSE_AUTOMATIC_BLOCK", "false").lower() == "true",
            automatic_container_isolation=os.getenv("AHR_RESPONSE_AUTOMATIC_CONTAINER_ISOLATION", "false").lower() == "true",
            critical_risk_threshold=float(os.getenv("AHR_RESPONSE_CRITICAL_RISK", "0.75")),
            high_ai_threshold=float(os.getenv("AHR_RESPONSE_HIGH_AI", "0.70")),
        )


@dataclass(frozen=True, slots=True)
class ResponseDecision:
    level: int
    action: str
    reason: str
    eligible_for_block: bool
    eligible_for_isolation: bool
    risk: float


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def high_confidence_rule_match(incident: dict[str, Any]) -> bool:
    rule_summary = incident.get("rule_summary") if isinstance(incident.get("rule_summary"), dict) else {}
    matched = rule_summary.get("matched_rules")
    count = rule_summary.get("rule_match_count")
    return bool(matched) or (isinstance(count, int) and count > 0)


def independent_ai_sources(incident: dict[str, Any], *, threshold: float) -> int:
    ai_summary = incident.get("ai_summary") if isinstance(incident.get("ai_summary"), dict) else {}
    scores = ai_summary.get("max_scores") if isinstance(ai_summary.get("max_scores"), dict) else {}
    return sum(
        1
        for key in ("network_score", "log_score", "graph_score")
        if (_number(scores.get(key)) or 0.0) >= threshold
    )


def graph_runtime_correlation(incident: dict[str, Any]) -> bool:
    graph = incident.get("attack_graph") if isinstance(incident.get("attack_graph"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    event_count = int(incident.get("event_count") or 0)
    has_runtime_entity = any(str(edge.get("relationship")) in {"spawned", "outbound", "touched"} for edge in edges if isinstance(edge, dict))
    return event_count >= 2 and (len(edges) >= 2 or has_runtime_entity)


def critical_response_eligible(incident: dict[str, Any], config: ResponseConfig | None = None) -> tuple[bool, str]:
    cfg = config or ResponseConfig()
    risk = float(incident.get("risk_score") or 0.0)
    if risk < cfg.critical_risk_threshold:
        return False, f"risk {risk:.3f} below critical threshold {cfg.critical_risk_threshold:.3f}"
    if high_confidence_rule_match(incident):
        return True, "fusion risk plus high-confidence rule match"
    ai_count = independent_ai_sources(incident, threshold=cfg.high_ai_threshold)
    if ai_count >= 2:
        return True, f"fusion risk plus {ai_count} independent AI sources"
    if graph_runtime_correlation(incident):
        return True, "fusion risk plus graph/runtime correlation"
    return False, "AI risk alone is insufficient for critical response"


def decide_response(incident: dict[str, Any], config: ResponseConfig | None = None) -> ResponseDecision:
    cfg = config or ResponseConfig()
    risk = float(incident.get("risk_score") or 0.0)
    severity = int(incident.get("severity") or incident.get("highest_severity") or 0)
    eligible, reason = critical_response_eligible(incident, cfg)

    if risk < 0.35 and severity < 4:
        level = 0
        reason = "low risk: log only"
    elif eligible and cfg.automatic_container_isolation and severity >= 10:
        level = 4
    elif eligible and cfg.automatic_block:
        level = 3
    elif risk >= 0.50 or severity >= 5:
        level = 1
        if eligible:
            reason = f"{reason}; automatic containment disabled"
    else:
        level = 0
        reason = "below alert threshold"

    if cfg.mode == "alert_only" and level > 1:
        level = 1
        reason = f"{reason}; response mode is alert_only"

    return ResponseDecision(
        level=level,
        action=LEVELS[level],
        reason=reason,
        eligible_for_block=eligible and cfg.automatic_block,
        eligible_for_isolation=eligible and cfg.automatic_container_isolation and severity >= 10,
        risk=risk,
    )

