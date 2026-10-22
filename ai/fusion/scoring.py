from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


DEFAULT_WEIGHTS = {
    "rule_score": 0.25,
    "network_score": 0.25,
    "log_score": 0.20,
    "graph_score": 0.25,
    "context_score": 0.05,
}

DEFAULT_THRESHOLDS = {
    "medium": 0.30,
    "high": 0.55,
    "critical": 0.80,
}


@dataclass(frozen=True, slots=True)
class FusionResult:
    fusion_score: float
    risk_level: str
    components: dict[str, float | None]
    normalized_weights: dict[str, float]
    missing_scores: list[str]
    method: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fusion_score": self.fusion_score,
            "risk_level": self.risk_level,
            "components": self.components,
            "normalized_weights": self.normalized_weights,
            "missing_scores": self.missing_scores,
            "method": self.method,
        }


def clamp01(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return None


def risk_level(score: float, thresholds: dict[str, float] | None = None) -> str:
    limits = thresholds or DEFAULT_THRESHOLDS
    if score >= limits["critical"]:
        return "critical"
    if score >= limits["high"]:
        return "high"
    if score >= limits["medium"]:
        return "medium"
    return "low"


def rule_score(event: dict[str, Any]) -> float | None:
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    severity = clamp01((event.get("severity") or 0) / 10.0) or 0.0
    confidence = clamp01(rule.get("confidence")) if rule else None
    engine_weight = {
        "suricata": 1.0,
        "falco": 0.9,
        "wazuh": 0.85,
        "nginx": 0.35,
    }.get(str(event.get("source") or "").lower(), 0.5)
    matched = 1.0 if rule or severity >= 0.5 else 0.0
    if not matched:
        return None
    conf = confidence if confidence is not None else 0.65
    # Severity dominates, but rule confidence/source engine prevent
    # "rule matched == 1" from becoming the scoring policy.
    return clamp01(0.55 * severity + 0.25 * conf + 0.20 * engine_weight)


def context_score(event: dict[str, Any], event_density: float = 0.0) -> float:
    ai = event.get("ai") if isinstance(event.get("ai"), dict) else {}
    labels = event.get("labels") if isinstance(event.get("labels"), dict) else {}
    density_score = min(max(event_density, 0.0), 25.0) / 25.0
    prior_ai = max(
        clamp01(ai.get("network_score")) or 0.0,
        clamp01(ai.get("log_score")) or 0.0,
        clamp01(ai.get("graph_score")) or 0.0,
    )
    # Ground-truth/scenario metadata must never raise operational risk.
    return float(clamp01(0.45 * density_score + 0.35 * prior_ai) or 0.0)


def score_components(event: dict[str, Any], event_density: float = 0.0) -> dict[str, float | None]:
    ai = event.get("ai") if isinstance(event.get("ai"), dict) else {}
    return {
        "rule_score": rule_score(event),
        "network_score": clamp01(ai.get("network_score")),
        "log_score": clamp01(ai.get("log_score")),
        "graph_score": clamp01(ai.get("graph_score")),
        "context_score": context_score(event, event_density),
    }


def weighted_baseline(
    components: dict[str, float | None],
    weights: dict[str, float] | None = None,
    thresholds: dict[str, float] | None = None,
) -> FusionResult:
    configured = weights or DEFAULT_WEIGHTS
    available = {name: value for name, value in components.items() if value is not None and name in configured}
    if not available:
        available = {"context_score": 0.0}
    total_weight = sum(configured[name] for name in available)
    normalized = {name: configured[name] / total_weight for name in available}
    score = sum(float(available[name]) * normalized[name] for name in available)
    return FusionResult(
        fusion_score=float(clamp01(score) or 0.0),
        risk_level=risk_level(float(clamp01(score) or 0.0), thresholds),
        components=components,
        normalized_weights=normalized,
        missing_scores=[name for name in configured if components.get(name) is None],
        method="weighted-baseline-renormalized",
    )


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)

