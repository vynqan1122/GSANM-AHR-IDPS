"""Deterministic GenTI-inspired context and CoVe checks for AHR-IDPS.

The paper's full workflow uses an LLM and a CTI-enriched rule corpus. AHR-IDPS
keeps the deployable path deterministic: this module provides the structured
context, conservative CTI hints, difficulty score, and the three verification
gates. An optional LLM may enrich the context later, but it cannot bypass the
syntax, logic, false-positive, candidate, shadow, and approval controls.
"""

from __future__ import annotations

from typing import Any
import json


GENTI_VERSION = "genti-lite-v1"

ATTACK_CONTEXT = {
    "sql_injection": {"cwe": ["CWE-89"], "attack": ["T1190"], "tactic": ["TA0001"]},
    "xss": {"cwe": ["CWE-79"], "attack": ["T1189"], "tactic": ["TA0001"]},
    "command_injection": {"cwe": ["CWE-78"], "attack": ["T1059"], "tactic": ["TA0002"]},
    "file_inclusion": {"cwe": ["CWE-98"], "attack": ["T1190"], "tactic": ["TA0001"]},
    "brute_force": {"cwe": ["CWE-307"], "attack": ["T1110"], "tactic": ["TA0006"]},
    "scanner_pattern": {"cwe": [], "attack": ["T1595"], "tactic": ["TA0043"]},
}


def _normalize_pattern(pattern: Any) -> dict[str, Any]:
    if isinstance(pattern, dict):
        return pattern
    if isinstance(pattern, str):
        try:
            parsed = json.loads(pattern)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return {}


def _attack_key(pattern: Any) -> str:
    pattern = _normalize_pattern(pattern)
    values = " ".join(
        str(pattern.get(key) or "").lower()
        for key in ("attack_type", "attack", "category", "uri_pattern", "process_family")
    )
    aliases = {
        "sql_injection": ("sql_injection", "sqli", "sql injection"),
        "xss": ("xss", "cross site", "cross-site"),
        "command_injection": ("command_injection", "command injection", "exec"),
        "file_inclusion": ("file_inclusion", "file inclusion", "vulnerabilities/fi"),
        "brute_force": ("brute_force", "brute force", "vulnerabilities/brute"),
        "scanner_pattern": ("scanner_pattern", "scanner", "probe", ".env"),
    }
    for key, candidates in aliases.items():
        if any(candidate in values for candidate in candidates):
            return key
    return "unknown_web_behavior" if pattern.get("type") == "network" else "unknown_runtime_behavior"


def map_threat_context(pattern: Any) -> dict[str, Any]:
    pattern = _normalize_pattern(pattern)
    key = _attack_key(pattern)
    mapped = ATTACK_CONTEXT.get(key, {"cwe": [], "attack": [], "tactic": []})
    return {
        "attack_type": key,
        "cwe": list(mapped["cwe"]),
        "mitre_attack": list(mapped["attack"]),
        "mitre_tactics": list(mapped["tactic"]),
        "mapping_confidence": 0.85 if key != "unknown_web_behavior" and key != "unknown_runtime_behavior" else 0.35,
        "mapping_source": "deterministic-dvwa-taxonomy",
    }


def difficulty_score(pattern: Any) -> float:
    """Return a reproducible [0, 1] curriculum score for a candidate."""
    pattern = _normalize_pattern(pattern)
    context = map_threat_context(pattern)
    constraints = sum(
        bool(pattern.get(key))
        for key in ("http_method", "uri_pattern", "protocol", "dst_port_class", "container_role", "process_family")
    )
    payload = min(len(str(pattern.get("uri_pattern") or "")) / 80.0, 1.0)
    support = min(float(pattern.get("support") or 0) / 25.0, 1.0)
    cti = min((len(context["cwe"]) + len(context["mitre_attack"]) + len(context["mitre_tactics"])) / 6.0, 1.0)
    return round(min(1.0, 0.15 + 0.08 * constraints + 0.30 * payload + 0.20 * support + 0.27 * cti), 4)


def build_context(pattern: Any, *, examples: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build a GTI-like structured context without leaking sample identifiers."""
    pattern = _normalize_pattern(pattern)
    context = map_threat_context(pattern)
    return {
        "genti_version": GENTI_VERSION,
        "header": {
            "engine": "suricata" if pattern.get("type") == "network" else "falco" if pattern.get("type") == "runtime" else "wazuh",
            "protocol": pattern.get("protocol"),
            "direction": "to_server" if pattern.get("type") == "network" else "host_event",
            "action": "alert",
        },
        "flow": {
            "event_type": pattern.get("event_type"),
            "http_method": pattern.get("http_method"),
            "dst_port_class": pattern.get("dst_port_class"),
        },
        "payload": {
            "uri_pattern": pattern.get("uri_pattern"),
            "process_family": pattern.get("process_family"),
            "container_role": pattern.get("container_role"),
        },
        "threat_context": context,
        "difficulty": difficulty_score(pattern),
        "provenance": {
            "source": "ahr-idps-event-cluster",
            "example_count": len(examples or []),
            "sample_identifiers_embedded": False,
        },
        "verification": {
            "stages": ["syntax", "logic", "false_positive"],
            "deployment": "candidate_then_shadow_then_manual_approval",
            "response_action": "alert_only",
        },
    }


def logic_check(engine: str, content: str, pattern: Any) -> dict[str, Any]:
    pattern = _normalize_pattern(pattern)
    expected_engine = str(build_context(pattern)["header"]["engine"])
    checks = {
        "engine_matches_pattern": engine == expected_engine,
        "action_is_alert": "drop" not in content.lower() and "reject" not in content.lower(),
        "has_behavior_anchor": bool(pattern.get("uri_pattern") or pattern.get("process_family") or pattern.get("event_type")),
    }
    uri = str(pattern.get("uri_pattern") or "")
    if engine == "suricata" and uri:
        checks["uri_in_rule"] = uri in content
    if engine == "falco" and pattern.get("process_family"):
        checks["process_in_rule"] = str(pattern["process_family"])[:32] in content
    if engine == "wazuh" and pattern.get("event_type"):
        checks["event_type_in_rule"] = str(pattern["event_type"]) in content
    return {"passed": all(checks.values()), "checks": checks}


def quality_score(*, syntax_valid: bool, logic_valid: bool, replay: dict[str, Any]) -> dict[str, float]:
    detection_rate = float(replay.get("recall", 0.0))
    false_positive_rate = float(replay.get("fpr", 1.0))
    security_effectiveness = 0.5 * detection_rate + 0.5 * (1.0 - false_positive_rate)
    score = (
        0.20 * float(syntax_valid)
        + 0.30 * float(logic_valid)
        + 0.20 * float(replay.get("precision", 0.0))
        + 0.30 * security_effectiveness
    )
    return {
        "syntax_accuracy": float(syntax_valid),
        "logic_consistency": float(logic_valid),
        "security_effectiveness": security_effectiveness,
        "composite_score": max(0.0, min(1.0, score)),
    }


def cove_verify(engine: str, content: str, pattern: Any, events: list[dict[str, Any]], thresholds: dict[str, float]) -> dict[str, Any]:
    """Run syntax, logic, and false-positive checks modeled on GenTI CoVe."""
    # Imported lazily to avoid a module cycle: validator uses this helper too.
    from .validator import metrics_for, syntax_check

    pattern = _normalize_pattern(pattern)

    syntax = syntax_check(engine, content)
    logic = logic_check(engine, content, pattern)
    replay = metrics_for(engine, content, events) if syntax.valid else {
        "tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "fpr": 1.0,
        "support": 0, "match_count": 0, "processing_cost": 0.0,
    }
    fp_ok = float(replay.get("fpr", 1.0)) <= float(thresholds.get("max_fpr", 0.02))
    replay_ok = (
        float(replay.get("precision", 0.0)) >= float(thresholds.get("min_precision", 0.90))
        and float(replay.get("recall", 0.0)) >= float(thresholds.get("min_recall", 0.75))
        and int(replay.get("tp", 0)) >= int(thresholds.get("min_positive_matches", 5))
    )
    quality = quality_score(syntax_valid=syntax.valid, logic_valid=logic["passed"], replay=replay)
    return {
        "genti_version": GENTI_VERSION,
        "syntax": {"passed": syntax.valid, "engine_used": syntax.engine_used, "error": syntax.error},
        "logic": logic,
        "false_positive": {"passed": fp_ok, "threshold": thresholds.get("max_fpr", 0.02), "observed": replay.get("fpr", 1.0)},
        "replay": replay,
        "replay_thresholds": thresholds,
        "quality": quality,
        "passed": bool(syntax.valid and logic["passed"] and fp_ok and replay_ok),
    }
