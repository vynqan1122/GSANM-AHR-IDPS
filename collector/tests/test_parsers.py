from __future__ import annotations

from collector.collectors.falco import parse_falco
from collector.collectors.nginx import parse_nginx
from collector.collectors.suricata import parse_suricata
from collector.collectors.wazuh import parse_wazuh


def test_source_parsers_produce_stable_ids_and_contract() -> None:
    fixtures = (
        (
            parse_suricata,
            {"timestamp": "2026-01-01T01:02:03.000000+00:00", "event_type": "alert", "flow_id": 9},
            "suricata",
        ),
        (
            parse_falco,
            {"time": "2026-01-01T01:02:03.000000Z", "rule": "AHR test", "output_fields": {"evt.num": 7}},
            "falco",
        ),
        (
            parse_wazuh,
            {"timestamp": "2026-01-01T01:02:03.000+0000", "id": "99123", "rule": {"id": "100101"}},
            "wazuh",
        ),
        (
            parse_nginx,
            {"time_iso8601": "2026-01-01T01:02:03+00:00", "request_id": "request-1", "status": 200},
            "nginx",
        ),
    )
    for parser, payload, source in fixtures:
        first = parser(payload, {"source_path": "/test"})
        second = parser(payload, {"source_path": "/different-file-copy"})
        fields = first.stream_fields()
        assert first.event_id == second.event_id
        assert first.source == source
        assert first.observed_at.endswith("Z")
        assert fields["schema_version"] == "1"
        assert set(fields) == {
            "schema_version",
            "event_id",
            "source",
            "source_event_id",
            "observed_at",
            "ingested_at",
            "payload",
            "metadata",
        }


def test_distinct_source_events_have_distinct_ids() -> None:
    base = {"time_iso8601": "2026-01-01T01:02:03+00:00", "request_id": "one"}
    other = {**base, "request_id": "two"}
    assert parse_nginx(base, {}).event_id != parse_nginx(other, {}).event_id
