from __future__ import annotations

from normalizer.mappings import normalize


def test_suricata_alert_maps_only_observed_values(envelope_factory):
    event = normalize(
        envelope_factory(
            "suricata",
            {
                "timestamp": "2026-08-13T01:02:01.123456+00:00",
                "flow_id": 12345,
                "event_type": "alert",
                "src_ip": "172.28.0.10",
                "src_port": 51000,
                "dest_ip": "172.28.0.20",
                "dest_port": 80,
                "proto": "TCP",
                "alert": {
                    "signature_id": 9000001,
                    "signature": "AHR controlled marker",
                    "category": "Test Traffic",
                    "severity": 1,
                },
                "http": {
                    "hostname": "localhost",
                    "url": "/?marker=phase3",
                    "http_method": "GET",
                    "status": 200,
                },
            },
        )
    )
    assert event.rule.rule_id == "9000001"
    assert event.severity == 9
    assert event.http.uri == "/?marker=phase3"
    assert event.network.flow_id == "12345"
    assert event.ingestion_timestamp.isoformat() == "2026-08-13T01:02:04+00:00"
    assert event.ai.network_score is None
    assert event.ai.model_versions == {}


def test_falco_real_flat_dotted_output_fields_map(envelope_factory):
    event = normalize(
        envelope_factory(
            "falco",
            {
                "time": "2026-08-13T01:02:03.000000000Z",
                "rule": "Shell spawned in a container",
                "priority": "Warning",
                "tags": ["container", "process"],
                "output": "A shell was spawned",
                "output_fields": {
                    "container.id": "d84f4babc123",
                    "container.name": "dvwa",
                    "container.image.repository": "vulnerables/web-dvwa",
                    "proc.pid": 4242,
                    "proc.ppid": 4200,
                    "proc.name": "sh",
                    "proc.pname": "docker-exec",
                    "proc.exepath": "/bin/sh",
                    "proc.cmdline": "sh -c true",
                    "user.name": "www-data",
                    "evt.type": "execve",
                },
            },
        )
    )
    assert event.container.id == "d84f4babc123"
    assert event.container.name == "dvwa"
    assert event.process.pid == 4242
    assert event.process.exe == "/bin/sh"
    assert event.user.name == "www-data"
    assert event.rule.engine == "falco"
    assert event.severity == 6


def test_wazuh_alert_maps_nested_docker_event(envelope_factory):
    event = normalize(
        envelope_factory(
            "wazuh",
            {
                "timestamp": "2026-08-13T01:02:03+00:00",
                "rule": {
                    "level": 7,
                    "description": "Docker container started",
                    "id": "87901",
                    "groups": ["docker"],
                },
                "decoder": {"name": "json"},
                "data": {
                    "docker": {
                        "Type": "container",
                        "Action": "start",
                        "Actor": {
                            "ID": "abc123",
                            "Attributes": {"name": "phase3-marker", "image": "alpine"},
                        },
                    }
                },
            },
        )
    )
    assert event.rule.rule_id == "87901"
    assert event.container.name == "phase3-marker"
    assert event.container.runtime == "docker"
    assert event.raw["data"]["docker"]["Actor"]["Attributes"]["name"] == "phase3-marker"


def test_nginx_access_event_maps_http_without_security_severity(envelope_factory):
    event = normalize(
        envelope_factory(
            "nginx",
            {
                "time_iso8601": "2026-08-13T08:02:03+07:00",
                "remote_addr": "172.28.0.1",
                "remote_port": "51234",
                "server_addr": "172.28.0.10",
                "server_port": "8080",
                "request_method": "GET",
                "host": "127.0.0.1",
                "request_uri": "/?marker=phase3",
                "status": "200",
                "request_length": "132",
                "body_bytes_sent": "42",
                "http_user_agent": "phase3-acceptance",
            },
        )
    )
    assert event.http.method == "GET"
    assert event.http.status == 200
    assert event.http.request_length == 132
    assert event.severity is None
    assert event.timestamp.isoformat() == "2026-08-13T01:02:03+00:00"


def test_docker_event_maps_engine_observation_not_alert(envelope_factory):
    event = normalize(
        envelope_factory(
            "docker_events",
            {
                "Type": "container",
                "Action": "start",
                "Actor": {
                    "ID": "deadbeef",
                    "Attributes": {"name": "dvwa", "image": "dvwa:test"},
                },
                "timeNano": 1786582923000000000,
            },
        )
    )
    assert event.event_type == "container.start"
    assert event.container.name == "dvwa"
    assert event.rule is None
    assert event.severity is None


def test_system_event_does_not_manufacture_network_or_ai_scores(envelope_factory):
    event = normalize(
        envelope_factory(
            "system",
            {"event_type": "resource.sample", "load1": 0.4, "memory_used": 1000},
        )
    )
    assert event.network is None
    assert event.http is None
    assert event.ai.fusion_score is None


def test_out_of_range_numeric_timestamp_falls_back_without_poisoning_worker(envelope_factory):
    envelope = envelope_factory(
        "docker_events",
        {"Type": "container", "Action": "start", "timeNano": 10**400},
    )
    event = normalize(envelope)
    assert event.timestamp == envelope.observed_at
