from __future__ import annotations

from rule_engine.genti import build_context, cove_verify, difficulty_score, logic_check, map_threat_context


def pattern():
    return {
        "type": "network",
        "source": "nginx",
        "event_type": "http",
        "http_method": "GET",
        "uri_pattern": "/vulnerabilities/sqli/",
        "protocol": "tcp",
        "dst_port_class": "web",
        "support": 6,
        "confidence": 0.92,
    }


def event(idx: int, attack: bool):
    return {
        "event_id": f"e{idx}",
        "event_type": "http",
        "source": "nginx",
        "attack_label": attack,
        "http": {"method": "GET", "uri": "/vulnerabilities/sqli/" if attack else "/"},
    }


def test_context_is_structured_and_sample_free():
    context = build_context(pattern(), examples=[event(1, True)])
    assert context["genti_version"] == "genti-lite-v1"
    assert context["threat_context"]["cwe"] == ["CWE-89"]
    assert context["provenance"]["sample_identifiers_embedded"] is False
    assert 0.0 <= context["difficulty"] <= 1.0


def test_logic_gate_rejects_wrong_engine():
    result = logic_check("falco", 'alert http any any -> any any (msg:"x"; sid:1; rev:1;)', pattern())
    assert result["passed"] is False
    assert result["checks"]["engine_matches_pattern"] is False


def test_cove_passes_for_low_noise_sqli_candidate():
    content = 'alert http any any -> any any (msg:"x"; flow:to_server,established; http.method; content:"GET"; http.uri; content:"/vulnerabilities/sqli/"; startswith; classtype:web-application-attack; sid:9100001; rev:1;)'
    report = cove_verify(
        "suricata",
        content,
        pattern(),
        [event(1, True), event(2, True), event(3, True), event(4, True), event(5, True), event(6, True), event(7, False)],
        {"min_precision": 0.90, "min_recall": 0.75, "max_fpr": 0.02, "min_positive_matches": 5},
    )
    assert report["syntax"]["passed"] is True
    assert report["logic"]["passed"] is True
    assert report["passed"] is True
